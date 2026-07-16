"""
P2-1 — matriz de tests ampliada: CRUD completo por recurso, aislamiento de
tenant (hotel_admin no puede ver/tocar datos de otro hotel), upload de
imágenes, onboarding y endpoints premium (hoteles/usuarios).
Run with: pytest tests/ -v  (from project root)
"""

import io
import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("HOSTELFLOW_SECRET", "test-secret-key-not-for-prod")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")

import main
from main import app
from models import Base, Hotel, User, UserRole


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
        hotel_a = Hotel(nombre="Hotel A", slug="hotel-a", is_active=True)
        hotel_b = Hotel(nombre="Hotel B", slug="hotel-b", is_active=True)
        db.add_all([hotel_a, hotel_b])
        db.flush()
        super_admin = User(
            email="super@test.com", password_hash=main.hash_password("testpass"),
            name="Super", role=UserRole.super_admin, is_active=True,
        )
        admin_a = User(
            email="admin_a@test.com", password_hash=main.hash_password("testpass"),
            name="Admin A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        admin_b = User(
            email="admin_b@test.com", password_hash=main.hash_password("testpass"),
            name="Admin B", role=UserRole.hotel_admin, hotel_id=hotel_b.id, is_active=True,
        )
        db.add_all([super_admin, admin_a, admin_b])
        db.commit()
        ids = {"hotel_a": hotel_a.id, "hotel_b": hotel_b.id}
    finally:
        db.close()

    c = TestClient(app)
    c.ids = ids
    yield c

    from sqlalchemy.orm import sessionmaker as sm
    main.engine = old_engine
    main.SessionLocal = sm(autocommit=False, autoflush=False, bind=old_engine)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def _login(client, email):
    resp = client.post("/api/auth/login", json={"email": email, "password": "testpass"})
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def super_token(client):
    return _login(client, "super@test.com")


@pytest.fixture
def admin_a_token(client):
    return _login(client, "admin_a@test.com")


@pytest.fixture
def admin_b_token(client):
    return _login(client, "admin_b@test.com")


def _auth(token, hotel_id=None):
    h = {"Authorization": f"Bearer {token}"}
    if hotel_id:
        h["X-Hotel-Id"] = str(hotel_id)
    return h


# ═══════════════════════════════════════════════════════════════════════════
#  CRUD completo por recurso (modules/faqs/promos/posts/popups)
# ═══════════════════════════════════════════════════════════════════════════


RESOURCE_PAYLOADS = {
    "modules": {"title": "Modulo test"},
    "faqs": {"question": "¿Wifi?", "answer": "Sí, gratis"},
    "promos": {"title": "Promo test"},
    "posts": {"section": "restaurant", "title": "Post test"},
    "popups": {"title": "Popup test"},
}


@pytest.mark.parametrize("resource,payload", RESOURCE_PAYLOADS.items())
class TestCRUDComplete:
    def test_full_crud_cycle(self, client, admin_a_token, resource, payload):
        base = f"/api/admin/{resource}"
        headers = _auth(admin_a_token, client.ids["hotel_a"])

        # CREATE
        created = client.post(base, json=payload, headers=headers)
        assert created.status_code == 200
        item = created.json()
        assert item["id"]

        # READ (list)
        listed = client.get(base, headers=headers)
        assert listed.status_code == 200
        assert any(i["id"] == item["id"] for i in listed.json())

        # UPDATE
        update_field, update_value = list(payload.items())[0]
        updated = client.put(f"{base}/{item['id']}", json={update_field: f"{update_value} editado"},
                             headers=headers)
        assert updated.status_code == 200
        assert updated.json()[update_field] == f"{update_value} editado"

        # DELETE
        deleted = client.delete(f"{base}/{item['id']}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json() == {"ok": True}

        # Ya no aparece en el listado
        listed_after = client.get(base, headers=headers)
        assert not any(i["id"] == item["id"] for i in listed_after.json())

    def test_update_nonexistent_returns_404(self, client, admin_a_token, resource, payload):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put(f"/api/admin/{resource}/999999", json=payload, headers=headers)
        assert resp.status_code == 404

    def test_delete_nonexistent_returns_404(self, client, admin_a_token, resource, payload):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.delete(f"/api/admin/{resource}/999999", headers=headers)
        assert resp.status_code == 404

    def test_anonymous_forbidden(self, client, resource, payload):
        resp = client.post(f"/api/admin/{resource}", json=payload)
        assert resp.status_code in (401, 403)


# ═══════════════════════════════════════════════════════════════════════════
#  Aislamiento de tenant — admin_a no puede tocar datos de hotel_b
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("resource,payload", RESOURCE_PAYLOADS.items())
class TestTenantIsolation:
    def test_admin_a_cannot_see_hotel_b_items(self, client, admin_a_token, admin_b_token, resource, payload):
        # admin_b crea un item en su propio hotel
        created = client.post(f"/api/admin/{resource}", json=payload,
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        assert created.status_code == 200
        item_id = created.json()["id"]

        # admin_a no lo ve en su listado
        listed = client.get(f"/api/admin/{resource}", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert not any(i["id"] == item_id for i in listed.json())

    def test_admin_a_cannot_update_hotel_b_item(self, client, admin_a_token, admin_b_token, resource, payload):
        created = client.post(f"/api/admin/{resource}", json=payload,
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        item_id = created.json()["id"]

        update_field, update_value = list(payload.items())[0]
        resp = client.put(f"/api/admin/{resource}/{item_id}", json={update_field: "hackeado"},
                          headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 404

    def test_admin_a_cannot_delete_hotel_b_item(self, client, admin_a_token, admin_b_token, resource, payload):
        created = client.post(f"/api/admin/{resource}", json=payload,
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        item_id = created.json()["id"]

        resp = client.delete(f"/api/admin/{resource}/{item_id}",
                             headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 404

        # sigue existiendo para admin_b
        listed = client.get(f"/api/admin/{resource}", headers=_auth(admin_b_token, client.ids["hotel_b"]))
        assert any(i["id"] == item_id for i in listed.json())

    def test_hotel_admin_cannot_spoof_hotel_id_header(self, client, admin_a_token, admin_b_token, resource, payload):
        """hotel_admin sin acceso a hotel_b: X-Hotel-Id: hotel_b -> 403 (P5 §4),
        no un fallback silencioso a su propio hotel."""
        created = client.post(f"/api/admin/{resource}", json=payload,
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        item_id = created.json()["id"]

        # admin_a intenta forzar X-Hotel-Id: hotel_b — no tiene acceso a ese hotel
        spoofed_headers = _auth(admin_a_token, client.ids["hotel_b"])
        resp = client.get(f"/api/admin/{resource}", headers=spoofed_headers)
        assert resp.status_code == 403


class TestLeadsTenantIsolation:
    def test_leads_isolated_per_hotel(self, client, admin_a_token, admin_b_token):
        client.post("/api/guest/hotel-a/onboarding", json={"name": "Lead A"})
        client.post("/api/guest/hotel-b/onboarding", json={"name": "Lead B"})

        leads_a = client.get("/api/admin/leads", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert leads_a.status_code == 200
        assert all(l["name"] != "Lead B" for l in leads_a.json()["leads"])
        assert any(l["name"] == "Lead A" for l in leads_a.json()["leads"])

    def test_leads_pagination(self, client, admin_a_token):
        for i in range(5):
            client.post("/api/guest/hotel-a/onboarding", json={"name": f"Paginado {i}"})
        resp = client.get("/api/admin/leads?limit=2&offset=0",
                          headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert len(resp.json()["leads"]) == 2
        assert resp.json()["total"] >= 5


# ═══════════════════════════════════════════════════════════════════════════
#  Upload — rechaza no-imágenes y archivos grandes
# ═══════════════════════════════════════════════════════════════════════════


class TestUpload:
    def test_upload_anonymous_401(self, client):
        resp = client.post("/api/admin/upload",
                           files={"file": ("x.png", io.BytesIO(b"data"), "image/png")})
        assert resp.status_code in (401, 403)

    def test_upload_non_image_rejected(self, client, admin_a_token):
        resp = client.post("/api/admin/upload",
                           files={"file": ("x.html", io.BytesIO(b"<script>x</script>"), "text/html")},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 415

    def test_upload_svg_rejected(self, client, admin_a_token):
        resp = client.post("/api/admin/upload",
                           files={"file": ("x.svg", io.BytesIO(b"<svg></svg>"), "image/svg+xml")},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 415

    def test_upload_oversized_rejected(self, client, admin_a_token):
        big = b"\xff" * (5 * 1024 * 1024 + 1)
        resp = client.post("/api/admin/upload",
                           files={"file": ("big.png", io.BytesIO(big), "image/png")},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 413

    def test_upload_valid_image_ok(self, client, admin_a_token):
        resp = client.post("/api/admin/upload",
                           files={"file": ("ok.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json()["url"].startswith("/static/uploads/")


# ═══════════════════════════════════════════════════════════════════════════
#  Onboarding crea lead
# ═══════════════════════════════════════════════════════════════════════════


class TestOnboardingCreatesLead:
    def test_onboarding_creates_visible_lead(self, client, admin_a_token):
        resp = client.post("/api/guest/hotel-a/onboarding", json={
            "name": "Nuevo Huesped", "email": "huesped@example.com",
        })
        assert resp.status_code == 200
        lead_id = resp.json()["id"]

        leads = client.get("/api/admin/leads", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert any(l["id"] == lead_id for l in leads.json()["leads"])

    def test_onboarding_unknown_slug_404(self, client):
        resp = client.post("/api/guest/no-existe/onboarding", json={"name": "X"})
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
#  Endpoints premium: hoteles y usuarios (solo super_admin)
# ═══════════════════════════════════════════════════════════════════════════


class TestHotelsAdminOnly:
    def test_hotel_admin_forbidden_from_list_hotels(self, client, admin_a_token):
        resp = client.get("/api/admin/hotels", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_super_admin_lists_all_hotels(self, client, super_token):
        resp = client.get("/api/admin/hotels", headers=_auth(super_token))
        assert resp.status_code == 200
        slugs = {h["slug"] for h in resp.json()}
        assert {"hotel-a", "hotel-b"} <= slugs

    def test_super_admin_creates_hotel_with_unique_slug(self, client, super_token):
        r1 = client.post("/api/admin/hotels", json={"nombre": "Hotel Nuevo"}, headers=_auth(super_token))
        assert r1.status_code == 200
        r2 = client.post("/api/admin/hotels", json={"nombre": "Hotel Nuevo"}, headers=_auth(super_token))
        assert r2.status_code == 200
        assert r1.json()["slug"] != r2.json()["slug"]

    def test_hotel_admin_cannot_create_hotel(self, client, admin_a_token):
        resp = client.post("/api/admin/hotels", json={"nombre": "Intento"},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_get_update_delete_hotel_by_id(self, client, super_token):
        created = client.post("/api/admin/hotels", json={"nombre": "Hotel Ciclo"}, headers=_auth(super_token))
        hid = created.json()["id"]

        got = client.get(f"/api/admin/hotels/{hid}", headers=_auth(super_token))
        assert got.status_code == 200

        updated = client.put(f"/api/admin/hotels/{hid}", json={"description": "actualizado"},
                             headers=_auth(super_token))
        assert updated.status_code == 200
        assert updated.json()["description"] == "actualizado"

        deleted = client.delete(f"/api/admin/hotels/{hid}", headers=_auth(super_token))
        assert deleted.status_code == 200
        assert deleted.json()["is_active"] is False

    def test_get_hotel_by_id_not_found(self, client, super_token):
        resp = client.get("/api/admin/hotels/999999", headers=_auth(super_token))
        assert resp.status_code == 404


class TestUsersAdminOnly:
    """P5: la gestión de usuarios ya no es exclusiva de super_admin — un
    hotel_admin con rol "admin" en su hotel (caso legacy, sin filas en
    user_hotels) también puede gestionar usuarios de SU hotel. Solo se
    bloquea a los editores (cubierto en test_p5_permissions_saas.py)."""

    def test_hotel_admin_can_create_user_for_own_hotel(self, client, admin_a_token):
        resp = client.post("/api/admin/users", json={
            "email": "x@test.com", "name": "X", "password": "pass1234",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["hotels"] == [{"hotel_id": client.ids["hotel_a"], "role": "admin"}]

    def test_super_admin_creates_hotel_admin_user(self, client, super_token):
        resp = client.post("/api/admin/users", json={
            "email": "nuevo_admin@test.com", "name": "Nuevo", "password": "pass1234",
            "role": "hotel_admin", "hotels": [{"hotel_id": client.ids["hotel_a"], "role": "admin"}],
        }, headers=_auth(super_token))
        assert resp.status_code == 200
        body = resp.json()
        assert "password_hash" not in body
        assert body["role"] == "hotel_admin"

    def test_create_user_duplicate_email_409(self, client, super_token):
        payload = {"email": "dup@test.com", "name": "Dup", "password": "pass1234",
                   "role": "hotel_admin", "hotels": [{"hotel_id": client.ids["hotel_a"], "role": "admin"}]}
        r1 = client.post("/api/admin/users", json=payload, headers=_auth(super_token))
        assert r1.status_code == 200
        r2 = client.post("/api/admin/users", json=payload, headers=_auth(super_token))
        assert r2.status_code == 409

    def test_create_hotel_admin_without_hotels_400(self, client, super_token):
        resp = client.post("/api/admin/users", json={
            "email": "sinhotel@test.com", "name": "Sin Hotel", "password": "pass1234",
            "role": "hotel_admin",
        }, headers=_auth(super_token))
        assert resp.status_code == 400

    def test_create_user_invalid_hotel_404(self, client, super_token):
        resp = client.post("/api/admin/users", json={
            "email": "hotelinexistente@test.com", "name": "X", "password": "pass1234",
            "role": "hotel_admin", "hotels": [{"hotel_id": 999999, "role": "admin"}],
        }, headers=_auth(super_token))
        assert resp.status_code == 404

    def test_create_user_short_password_400(self, client, super_token):
        resp = client.post("/api/admin/users", json={
            "email": "corta@test.com", "name": "X", "password": "short",
            "role": "hotel_admin", "hotels": [{"hotel_id": client.ids["hotel_a"], "role": "admin"}],
        }, headers=_auth(super_token))
        assert resp.status_code == 400

    def test_hotel_admin_cannot_create_super_admin(self, client, admin_a_token):
        resp = client.post("/api/admin/users", json={
            "email": "wannabe_super@test.com", "name": "X", "password": "pass1234",
            "role": "super_admin",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_hotel_admin_cannot_assign_other_hotel(self, client, admin_a_token):
        resp = client.post("/api/admin/users", json={
            "email": "otrohotel@test.com", "name": "X", "password": "pass1234",
            "hotels": [{"hotel_id": client.ids["hotel_b"], "role": "admin"}],
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403


class TestChangePassword:
    def test_wrong_current_password_401(self, client, admin_a_token):
        resp = client.post("/api/admin/change-password", json={
            "current_password": "incorrecta", "new_password": "nuevapass123",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 401

    def test_too_short_new_password_400(self, client, admin_a_token):
        resp = client.post("/api/admin/change-password", json={
            "current_password": "testpass", "new_password": "corta",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 400
