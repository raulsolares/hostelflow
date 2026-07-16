"""
P4 — Sections, Gallery e i18n de contenido.
Cubre: CRUD de sections/gallery + aislamiento de tenant, DELETE de sección con
posts (409), slugs autogenerados únicos, i18n en módulos (sanitizado y con
allowlist de idiomas), header configurable del hotel, y las nuevas claves en
GET /api/guest/{slug}.
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
#  Sections — CRUD completo + aislamiento de tenant
# ═══════════════════════════════════════════════════════════════════════════


class TestSectionsCRUD:
    def test_full_crud_cycle(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        created = client.post("/api/admin/sections", json={"name": "Spa & Bienestar"}, headers=headers)
        assert created.status_code == 200
        item = created.json()
        assert item["id"]
        assert item["slug"] == "spa-bienestar"

        listed = client.get("/api/admin/sections", headers=headers)
        assert listed.status_code == 200
        assert any(s["id"] == item["id"] for s in listed.json())

        updated = client.put(f"/api/admin/sections/{item['id']}", json={"name": "Spa Editado"}, headers=headers)
        assert updated.status_code == 200
        assert updated.json()["name"] == "Spa Editado"

        deleted = client.delete(f"/api/admin/sections/{item['id']}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json() == {"ok": True}

        listed_after = client.get("/api/admin/sections", headers=headers)
        assert not any(s["id"] == item["id"] for s in listed_after.json())

    def test_anonymous_forbidden(self, client):
        resp = client.post("/api/admin/sections", json={"name": "X"})
        assert resp.status_code in (401, 403)

    def test_update_nonexistent_404(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/sections/999999", json={"name": "X"}, headers=headers)
        assert resp.status_code == 404

    def test_delete_nonexistent_404(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.delete("/api/admin/sections/999999", headers=headers)
        assert resp.status_code == 404

    def test_duplicate_name_gets_unique_slug(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        r1 = client.post("/api/admin/sections", json={"name": "Café Bar"}, headers=headers)
        r2 = client.post("/api/admin/sections", json={"name": "Café Bar"}, headers=headers)
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["slug"] != r2.json()["slug"]
        assert r1.json()["slug"] == "cafe-bar"
        assert r2.json()["slug"] == "cafe-bar-2"

    def test_delete_section_with_posts_returns_409(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        section = client.post("/api/admin/sections", json={"name": "Restaurante Test"}, headers=headers).json()
        client.post("/api/admin/posts", json={"section": section["slug"], "title": "Post en la seccion"}, headers=headers)

        resp = client.delete(f"/api/admin/sections/{section['id']}", headers=headers)
        assert resp.status_code == 409
        assert "publicaciones" in resp.json()["detail"]

    def test_delete_section_without_posts_ok(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        section = client.post("/api/admin/sections", json={"name": "Sin Posts Test"}, headers=headers).json()
        resp = client.delete(f"/api/admin/sections/{section['id']}", headers=headers)
        assert resp.status_code == 200


class TestSectionsTenantIsolation:
    def test_admin_a_cannot_see_or_touch_hotel_b_section(self, client, admin_a_token, admin_b_token):
        created = client.post("/api/admin/sections", json={"name": "Seccion B"},
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        item_id = created.json()["id"]

        listed = client.get("/api/admin/sections", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert not any(s["id"] == item_id for s in listed.json())

        upd = client.put(f"/api/admin/sections/{item_id}", json={"name": "hackeado"},
                         headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert upd.status_code == 404

        deleted = client.delete(f"/api/admin/sections/{item_id}",
                                headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert deleted.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
#  Gallery — CRUD completo + aislamiento de tenant
# ═══════════════════════════════════════════════════════════════════════════


class TestGalleryCRUD:
    def test_full_crud_cycle(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        payload = {"image_url": "https://images.unsplash.com/photo-test?w=600", "caption": "Playa"}
        created = client.post("/api/admin/gallery", json=payload, headers=headers)
        assert created.status_code == 200
        item = created.json()

        listed = client.get("/api/admin/gallery", headers=headers)
        assert any(g["id"] == item["id"] for g in listed.json())

        updated = client.put(f"/api/admin/gallery/{item['id']}", json={"caption": "Playa editada"}, headers=headers)
        assert updated.status_code == 200
        assert updated.json()["caption"] == "Playa editada"

        deleted = client.delete(f"/api/admin/gallery/{item['id']}", headers=headers)
        assert deleted.status_code == 200

        listed_after = client.get("/api/admin/gallery", headers=headers)
        assert not any(g["id"] == item["id"] for g in listed_after.json())

    def test_anonymous_forbidden(self, client):
        resp = client.post("/api/admin/gallery", json={"image_url": "https://x.com/a.png"})
        assert resp.status_code in (401, 403)

    def test_update_nonexistent_404(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/gallery/999999", json={"caption": "x"}, headers=headers)
        assert resp.status_code == 404

    def test_delete_nonexistent_404(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.delete("/api/admin/gallery/999999", headers=headers)
        assert resp.status_code == 404


class TestGalleryTenantIsolation:
    def test_admin_a_cannot_see_or_touch_hotel_b_image(self, client, admin_a_token, admin_b_token):
        created = client.post("/api/admin/gallery",
                              json={"image_url": "https://images.unsplash.com/photo-b?w=600"},
                              headers=_auth(admin_b_token, client.ids["hotel_b"]))
        item_id = created.json()["id"]

        listed = client.get("/api/admin/gallery", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert not any(g["id"] == item_id for g in listed.json())

        upd = client.put(f"/api/admin/gallery/{item_id}", json={"caption": "hackeado"},
                         headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert upd.status_code == 404

        deleted = client.delete(f"/api/admin/gallery/{item_id}",
                                headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert deleted.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
#  i18n de contenido — módulos (sanitización + allowlist de idiomas)
# ═══════════════════════════════════════════════════════════════════════════


class TestModuleI18n:
    def test_i18n_persists_and_sanitizes_html(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        created = client.post("/api/admin/modules", json={"title": "WiFi"}, headers=headers)
        module_id = created.json()["id"]

        resp = client.put(f"/api/admin/modules/{module_id}", json={
            "i18n": {"en": {"title": "WiFi", "content_html": "<p>Hi<script>alert(1)</script></p>"}}
        }, headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["i18n"]["en"]["title"] == "WiFi"
        assert "<script>" not in body["i18n"]["en"]["content_html"]
        assert "Hi" in body["i18n"]["en"]["content_html"]

        # Se sirve saneado en GET /api/guest/{slug}
        guest = client.get("/api/guest/hotel-a")
        assert guest.status_code == 200
        served = next(m for m in guest.json()["modules"] if m["id"] == module_id)
        assert "<script>" not in served["i18n"]["en"]["content_html"]

    def test_invalid_language_returns_422(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        created = client.post("/api/admin/modules", json={"title": "Modulo idioma invalido"}, headers=headers)
        module_id = created.json()["id"]

        resp = client.put(f"/api/admin/modules/{module_id}", json={
            "i18n": {"xx": {"title": "no valido"}}
        }, headers=headers)
        assert resp.status_code == 422

    def test_create_with_i18n(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.post("/api/admin/modules", json={
            "title": "Horarios", "i18n": {"en": {"title": "Hours"}},
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["i18n"]["en"]["title"] == "Hours"


# ═══════════════════════════════════════════════════════════════════════════
#  Hotel — header_style, header_config, supported_languages
# ═══════════════════════════════════════════════════════════════════════════


class TestHotelHeaderConfig:
    def test_invalid_header_style_422(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/hotel", json={"header_style": "not-a-style"}, headers=headers)
        assert resp.status_code == 422

    def test_header_config_unknown_key_422(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/hotel", json={
            "header_config": {"show_name": True, "evil_key": "x"}
        }, headers=headers)
        assert resp.status_code == 422

    def test_invalid_supported_languages_422(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/hotel", json={"supported_languages": "es,xx"}, headers=headers)
        assert resp.status_code == 422

    def test_valid_combo_persists_and_shows_in_guest(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        resp = client.put("/api/admin/hotel", json={
            "header_style": "centered",
            "header_config": {"show_name": True, "overlay": 0.4},
            "supported_languages": "es,en",
        }, headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["header_style"] == "centered"
        assert body["header_config"] == {"show_name": True, "overlay": 0.4}
        assert body["supported_languages"] == ["es", "en"]

        guest = client.get("/api/guest/hotel-a")
        assert guest.status_code == 200
        h = guest.json()["hotel"]
        assert h["header_style"] == "centered"
        assert h["header_config"] == {"show_name": True, "overlay": 0.4}
        assert h["supported_languages"] == ["es", "en"]


# ═══════════════════════════════════════════════════════════════════════════
#  GET /api/guest/{slug} — sections y gallery
# ═══════════════════════════════════════════════════════════════════════════


class TestGuestSectionsAndGallery:
    def test_guest_payload_includes_sections_and_gallery(self, client, admin_a_token):
        headers = _auth(admin_a_token, client.ids["hotel_a"])
        client.post("/api/admin/sections", json={"name": "Galeria Seccion Test"}, headers=headers)
        client.post("/api/admin/gallery", json={
            "image_url": "https://images.unsplash.com/photo-guest-test?w=600",
            "caption": "Foto de prueba",
        }, headers=headers)

        resp = client.get("/api/guest/hotel-a")
        assert resp.status_code == 200
        body = resp.json()
        assert "sections" in body and isinstance(body["sections"], list)
        assert "gallery" in body and isinstance(body["gallery"], list)
        assert any(s["name"] == "Galeria Seccion Test" for s in body["sections"])
        assert any(g["caption"] == "Foto de prueba" for g in body["gallery"])
        for s in body["sections"]:
            assert set(["id", "slug", "name", "icon", "sort_order", "is_active", "i18n"]) <= set(s.keys())
        for g in body["gallery"]:
            assert set(["id", "image_url", "caption", "sort_order", "is_active", "i18n"]) <= set(g.keys())


class TestGalleryOpenEvent:
    def test_gallery_open_event_accepted(self, client):
        resp = client.post("/api/guest/hotel-a/events", json={"event_type": "gallery_open"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
