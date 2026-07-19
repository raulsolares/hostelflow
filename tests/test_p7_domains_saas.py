"""
P7 — Dominio personalizado por hotel + overview SaaS de solo lectura.

Cubre:
  - PUT /api/admin/hotel: custom_domain se normaliza (protocolo/path/puerto
    fuera, minúsculas), formato inválido -> 422, duplicado entre hoteles ->
    409, editor -> 403, y NUNCA aparece en GET /api/guest/{slug}.
  - GET /: si el Host coincide con el custom_domain de un hotel activo sirve
    el guest con window.HF_SLUG inyectado; Host desconocido sirve el admin.
  - GET /api/admin/hotel/domain-status: sin dominio -> dns_ok null; con
    dominio no resoluble -> dns_ok false.
  - GET /api/admin/saas/overview: solo super_admin (403 para hotel_admin);
    200 con todas las claves y counts coherentes; mrr con source "estimate"
    cuando billing no está habilitado.

Run with: pytest tests/ -v  (from project root)
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("HOSTELFLOW_SECRET", "test-secret-key-not-for-prod")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")

import main
from main import app
from models import Base, Hotel, User, UserRole, UserHotel, ContentModule


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    main.limiter.enabled = False

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    db_url = f"sqlite:///{db_path}"

    old_engine = main.engine
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    main.engine = create_engine(db_url, connect_args={"check_same_thread": False})
    main.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=main.engine)

    Base.metadata.create_all(bind=main.engine)
    db = main.SessionLocal()
    try:
        hotel_a = Hotel(
            nombre="Hotel A", slug="hotel-a-p7", is_active=True, plan="active",
            created_at=datetime.utcnow() - timedelta(days=40),
        )
        hotel_b = Hotel(
            nombre="Hotel B", slug="hotel-b-p7", is_active=True, plan="trial",
            trial_ends_at=datetime.utcnow() + timedelta(days=3),
            created_at=datetime.utcnow() - timedelta(days=10),
        )
        hotel_c = Hotel(
            nombre="Hotel C", slug="hotel-c-p7", is_active=True, plan="suspended",
            created_at=datetime.utcnow() - timedelta(days=5),
        )
        hotel_sub = Hotel(
            nombre="Hotel Con Suscripcion", slug="hotel-sub-p7", is_active=True, plan="active",
            stripe_subscription_id="sub_fake_p7",
            created_at=datetime.utcnow() - timedelta(days=2),
        )
        db.add_all([hotel_a, hotel_b, hotel_c, hotel_sub])
        db.flush()

        db.add(ContentModule(
            hotel_id=hotel_a.id, module_type="wifi", title="WiFi",
            content_html="<p>red</p>", icon="wifi", sort_order=1,
            is_active=True, audience_stage="all",
        ))

        super_admin = User(
            email="super_p7@test.com", password_hash=main.hash_password("testpass"),
            name="Super Admin", role=UserRole.super_admin, is_active=True,
        )
        admin_a = User(
            email="admin_a_p7@test.com", password_hash=main.hash_password("testpass"),
            name="Admin A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        editor_a = User(
            email="editor_a_p7@test.com", password_hash=main.hash_password("testpass"),
            name="Editor A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        admin_b = User(
            email="admin_b_p7@test.com", password_hash=main.hash_password("testpass"),
            name="Admin B", role=UserRole.hotel_admin, hotel_id=hotel_b.id, is_active=True,
        )
        db.add_all([super_admin, admin_a, editor_a, admin_b])
        db.flush()
        db.add(UserHotel(user_id=editor_a.id, hotel_id=hotel_a.id, role="editor"))
        db.commit()

        ids = {
            "hotel_a": hotel_a.id, "hotel_b": hotel_b.id,
            "hotel_c": hotel_c.id, "hotel_sub": hotel_sub.id,
        }
        slugs = {
            "hotel_a": hotel_a.slug, "hotel_b": hotel_b.slug,
            "hotel_c": hotel_c.slug, "hotel_sub": hotel_sub.slug,
        }
    finally:
        db.close()

    c = TestClient(app)
    c.ids = ids
    c.slugs = slugs
    yield c

    from sqlalchemy.orm import sessionmaker as sm
    main.engine = old_engine
    main.SessionLocal = sm(autocommit=False, autoflush=False, bind=old_engine)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def _login(client, email, password="testpass"):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def super_token(client):
    return _login(client, "super_p7@test.com")


@pytest.fixture
def admin_a_token(client):
    return _login(client, "admin_a_p7@test.com")


@pytest.fixture
def editor_a_token(client):
    return _login(client, "editor_a_p7@test.com")


def _auth(token, hotel_id=None):
    h = {"Authorization": f"Bearer {token}"}
    if hotel_id:
        h["X-Hotel-Id"] = str(hotel_id)
    return h


def _clear_domain_cache():
    main._CUSTOM_DOMAIN_CACHE.clear()


def _reset_domain(hotel_id: int):
    db = main.SessionLocal()
    try:
        h = db.query(Hotel).filter(Hotel.id == hotel_id).first()
        h.custom_domain = None
        db.commit()
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
#  PUT /api/admin/hotel — custom_domain
# ═══════════════════════════════════════════════════════════════════════════


class TestCustomDomainUpdate:
    def test_valid_domain_persists_normalized(self, client, admin_a_token):
        _reset_domain(client.ids["hotel_a"])
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": "HTTPS://App.MiHotel.MX/"},
            headers=_auth(admin_a_token, client.ids["hotel_a"]),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["custom_domain"] == "app.mihotel.mx"

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.custom_domain == "app.mihotel.mx"
        finally:
            db.close()

    def test_invalid_format_422(self, client, admin_a_token):
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": "not a domain"},
            headers=_auth(admin_a_token, client.ids["hotel_a"]),
        )
        assert resp.status_code == 422

    def test_invalid_format_no_dot_422(self, client, admin_a_token):
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": "localhost"},
            headers=_auth(admin_a_token, client.ids["hotel_a"]),
        )
        assert resp.status_code == 422

    def test_duplicate_domain_409(self, client, admin_a_token):
        # hotel_a ya tiene app.mihotel.mx del primer test (test_valid_domain_persists_normalized)
        admin_b_token = _login(client, "admin_b_p7@test.com")
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": "app.mihotel.mx"},
            headers=_auth(admin_b_token, client.ids["hotel_b"]),
        )
        assert resp.status_code == 409

    def test_editor_forbidden(self, client, editor_a_token):
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": "otro.dominio.com"},
            headers=_auth(editor_a_token, client.ids["hotel_a"]),
        )
        assert resp.status_code == 403

    def test_null_clears_domain(self, client, admin_a_token):
        resp = client.put(
            "/api/admin/hotel", json={"custom_domain": None},
            headers=_auth(admin_a_token, client.ids["hotel_a"]),
        )
        assert resp.status_code == 200
        assert resp.json()["custom_domain"] is None

    def test_not_exposed_in_guest_api(self, client, admin_a_token):
        client.put(
            "/api/admin/hotel", json={"custom_domain": "guarda.secreto.com"},
            headers=_auth(admin_a_token, client.ids["hotel_a"]),
        )
        resp = client.get(f"/api/guest/{client.slugs['hotel_a']}")
        assert resp.status_code == 200
        assert "custom_domain" not in resp.json()["hotel"]
        _reset_domain(client.ids["hotel_a"])


# ═══════════════════════════════════════════════════════════════════════════
#  GET / — resolución por Host
# ═══════════════════════════════════════════════════════════════════════════


class TestHostResolution:
    def test_unknown_host_serves_admin(self, client):
        _clear_domain_cache()
        resp = client.get("/", headers={"host": "no-configurado.example.com"})
        assert resp.status_code == 200
        assert "HF_SLUG" not in resp.text

    def test_known_custom_domain_serves_guest_with_slug(self, client, admin_a_token):
        db = main.SessionLocal()
        try:
            h = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            h.custom_domain = "miguia.ejemplo.com"
            db.commit()
        finally:
            db.close()
        _clear_domain_cache()

        resp = client.get("/", headers={"host": "miguia.ejemplo.com"})
        assert resp.status_code == 200
        assert f'window.HF_SLUG="{client.slugs["hotel_a"]}"' in resp.text
        _reset_domain(client.ids["hotel_a"])
        _clear_domain_cache()


# ═══════════════════════════════════════════════════════════════════════════
#  GET /api/admin/hotel/domain-status
# ═══════════════════════════════════════════════════════════════════════════


class TestDomainStatus:
    def test_no_domain_dns_ok_null(self, client, admin_a_token):
        _reset_domain(client.ids["hotel_a"])
        resp = client.get("/api/admin/hotel/domain-status", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["domain"] is None
        assert body["dns_ok"] is None
        assert "expected_target" in body

    def test_non_resolvable_domain_dns_ok_false(self, client, admin_a_token):
        db = main.SessionLocal()
        try:
            h = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            h.custom_domain = "no-existe-xyz.invalid"
            db.commit()
        finally:
            db.close()

        resp = client.get("/api/admin/hotel/domain-status", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["domain"] == "no-existe-xyz.invalid"
        assert body["dns_ok"] is False
        _reset_domain(client.ids["hotel_a"])


# ═══════════════════════════════════════════════════════════════════════════
#  GET /api/admin/saas/overview
# ═══════════════════════════════════════════════════════════════════════════


class TestSaasOverview:
    def test_hotel_admin_forbidden(self, client, admin_a_token):
        resp = client.get("/api/admin/saas/overview", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_super_admin_200_with_all_keys(self, client, super_token):
        assert main.BILLING_ENABLED is False
        resp = client.get("/api/admin/saas/overview", headers=_auth(super_token))
        assert resp.status_code == 200, resp.text
        body = resp.json()

        for key in ("totals", "mrr", "signups_by_month", "trials_expiring", "hotels"):
            assert key in body

        totals = body["totals"]
        for key in ("hotels", "active", "trial", "suspended", "with_subscription"):
            assert key in totals
        assert totals["hotels"] >= 4
        assert totals["with_subscription"] >= 1
        assert totals["suspended"] >= 1
        assert totals["trial"] >= 1

        assert body["mrr"]["source"] == "estimate"
        assert "amount" in body["mrr"]
        assert "currency" in body["mrr"]

        assert len(body["signups_by_month"]) == 12
        for entry in body["signups_by_month"]:
            assert "month" in entry and "count" in entry

        trial_ids = {t["id"] for t in body["trials_expiring"]}
        assert client.ids["hotel_b"] in trial_ids

        hotel_ids_out = {h["id"] for h in body["hotels"]}
        assert client.ids["hotel_a"] in hotel_ids_out
        sub_entry = next(h for h in body["hotels"] if h["id"] == client.ids["hotel_sub"])
        assert sub_entry["has_subscription"] is True
        assert "leads_count" in sub_entry
