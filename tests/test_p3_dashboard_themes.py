"""
P3 — dashboard analytics ampliado (visits_by_date, leads_by_date, push_subscribers,
top_modules) + themes por hotel (default "boutique", override vía PUT /api/admin/hotel).
Run with: pytest tests/ -v  (from project root)
"""

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
#  Dashboard — formas de los campos nuevos
# ═══════════════════════════════════════════════════════════════════════════


class TestDashboardShapes:
    def test_dashboard_returns_new_fields_with_correct_shapes(self, client, admin_a_token):
        # Genera algo de actividad: un lead, un page_view y un module_open en hotel-a
        client.post("/api/guest/hotel-a/onboarding", json={"name": "Shape Test"})
        client.post("/api/guest/hotel-a/events", json={"event_type": "page_view", "page_view": "home"})
        client.post("/api/guest/hotel-a/events", json={"event_type": "module_open", "page_view": "WiFi Premium"})

        resp = client.get("/api/admin/dashboard", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        body = resp.json()

        # Campos existentes siguen presentes (aditivo, no rompe contrato)
        for key in ("total_leads", "leads_this_week", "total_modules", "total_faqs",
                    "total_promos", "total_popups", "recent_leads"):
            assert key in body

        assert isinstance(body["visits_by_date"], list)
        assert isinstance(body["leads_by_date"], list)
        assert isinstance(body["push_subscribers"], int)
        assert isinstance(body["top_modules"], list)

        for item in body["visits_by_date"]:
            assert set(item.keys()) == {"date", "count"}
        for item in body["leads_by_date"]:
            assert set(item.keys()) == {"date", "count"}
        for item in body["top_modules"]:
            assert set(item.keys()) == {"module", "views"}

        # Al menos un day bucket para el lead y el page_view generados arriba
        assert any(i["count"] >= 1 for i in body["leads_by_date"])
        assert any(i["count"] >= 1 for i in body["visits_by_date"])
        # top_modules solo cuenta eventos module_open (page_view lleva el título del módulo)
        assert any(i["module"] == "WiFi Premium" for i in body["top_modules"])
        assert not any(i["module"] == "home" for i in body["top_modules"])


# ═══════════════════════════════════════════════════════════════════════════
#  Dashboard — aislamiento por tenant
# ═══════════════════════════════════════════════════════════════════════════


class TestDashboardTenantIsolation:
    def test_hotel_b_leads_not_counted_for_hotel_a(self, client, admin_a_token, admin_b_token):
        before = client.get("/api/admin/dashboard", headers=_auth(admin_a_token, client.ids["hotel_a"])).json()

        client.post("/api/guest/hotel-b/onboarding", json={"name": "Isolation Lead"})

        after = client.get("/api/admin/dashboard", headers=_auth(admin_a_token, client.ids["hotel_a"])).json()
        assert after["total_leads"] == before["total_leads"]

        # el lead sí cuenta para hotel_b
        b_dashboard = client.get("/api/admin/dashboard", headers=_auth(admin_b_token, client.ids["hotel_b"])).json()
        assert b_dashboard["total_leads"] >= 1


# ═══════════════════════════════════════════════════════════════════════════
#  Theme por hotel — persistencia y propagación al guest endpoint
# ═══════════════════════════════════════════════════════════════════════════


class TestHotelTheme:
    def test_put_hotel_theme_persists_and_reflects_in_guest_endpoint(self, client, admin_a_token):
        resp = client.put("/api/admin/hotel", json={"theme": "urban"},
                          headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json()["theme"] == "urban"

        guest = client.get("/api/guest/hotel-a")
        assert guest.status_code == 200
        assert guest.json()["hotel"]["theme"] == "urban"

    def test_new_hotel_defaults_to_boutique_theme(self, client, super_token):
        resp = client.post("/api/admin/hotels", json={"nombre": "Hotel Theme Default"},
                           headers=_auth(super_token))
        assert resp.status_code == 200
        assert resp.json()["theme"] == "boutique"


# ═══════════════════════════════════════════════════════════════════════════
#  Analytics — sin regresión de contrato
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyticsNoRegression:
    def test_analytics_shapes_unchanged(self, client, admin_a_token):
        resp = client.get("/api/admin/analytics", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body["events_breakdown"], dict)
        assert isinstance(body["leads_by_date"], list)
        assert isinstance(body["top_modules"], list)
        for item in body["top_modules"]:
            assert set(item.keys()) == {"module", "views"}
