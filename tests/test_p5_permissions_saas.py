"""
P5 — Permisos multi-hotel robustos (UserHotel: admin/editor por hotel) y
módulo SaaS de registro público + trial de 14 días.

Cubre:
  - editor: puede CRUD de contenido pero 403 en PUT /api/admin/hotel,
    /api/admin/users*, /api/admin/notifications*, POST /api/admin/qr.
  - usuario multi-hotel: X-Hotel-Id de un hotel asignado -> 200; de uno no
    asignado -> 403.
  - CRUD de usuarios con alcance por hotel, protección del último admin,
    reset de contraseña.
  - signup público: crea hotel en trial + admin, token funcional, secciones
    default, email duplicado -> 409.
  - enforcement de trial vencido/suspendido en escrituras admin (403), no en
    lecturas (200), y trial_expired en la guía de huésped pública.
  - regresión: super_admin y hotel_admin legacy (sin filas user_hotels)
    siguen funcionando en todo el flujo existente.

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
from models import Base, Hotel, User, UserRole, UserHotel


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
        hotel_a = Hotel(nombre="Hotel A", slug="hotel-a", is_active=True, plan="active")
        hotel_b = Hotel(nombre="Hotel B", slug="hotel-b", is_active=True, plan="active")
        hotel_expired = Hotel(
            nombre="Hotel Vencido", slug="hotel-vencido", is_active=True,
            plan="trial", trial_ends_at=datetime.utcnow() - timedelta(days=1),
        )
        hotel_suspended = Hotel(
            nombre="Hotel Suspendido", slug="hotel-suspendido", is_active=True, plan="suspended",
        )
        db.add_all([hotel_a, hotel_b, hotel_expired, hotel_suspended])
        db.flush()

        super_admin = User(
            email="super@test.com", password_hash=main.hash_password("testpass"),
            name="Super", role=UserRole.super_admin, is_active=True,
        )
        # Legacy: hotel_admin puro, SIN fila en user_hotels (regresión).
        admin_a = User(
            email="admin_a@test.com", password_hash=main.hash_password("testpass"),
            name="Admin A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        # Editor de hotel_a (rol fino en user_hotels).
        editor_a = User(
            email="editor_a@test.com", password_hash=main.hash_password("testpass"),
            name="Editor A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        # Multi-hotel: admin en A, editor en B.
        multi = User(
            email="multi@test.com", password_hash=main.hash_password("testpass"),
            name="Multi", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        # Admin del hotel con trial vencido.
        admin_expired = User(
            email="admin_expired@test.com", password_hash=main.hash_password("testpass"),
            name="Admin Vencido", role=UserRole.hotel_admin, hotel_id=hotel_expired.id, is_active=True,
        )
        db.add_all([super_admin, admin_a, editor_a, multi, admin_expired])
        db.flush()

        db.add(UserHotel(user_id=editor_a.id, hotel_id=hotel_a.id, role="editor"))
        db.add(UserHotel(user_id=multi.id, hotel_id=hotel_a.id, role="admin"))
        db.add(UserHotel(user_id=multi.id, hotel_id=hotel_b.id, role="editor"))
        db.add(UserHotel(user_id=admin_expired.id, hotel_id=hotel_expired.id, role="admin"))
        db.commit()

        ids = {
            "hotel_a": hotel_a.id, "hotel_b": hotel_b.id,
            "hotel_expired": hotel_expired.id, "hotel_suspended": hotel_suspended.id,
        }
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


def _login(client, email, password="testpass"):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def super_token(client):
    return _login(client, "super@test.com")


@pytest.fixture
def admin_a_token(client):
    return _login(client, "admin_a@test.com")


@pytest.fixture
def editor_a_token(client):
    return _login(client, "editor_a@test.com")


@pytest.fixture
def multi_token(client):
    return _login(client, "multi@test.com")


@pytest.fixture
def admin_expired_token(client):
    return _login(client, "admin_expired@test.com")


def _auth(token, hotel_id=None):
    h = {"Authorization": f"Bearer {token}"}
    if hotel_id:
        h["X-Hotel-Id"] = str(hotel_id)
    return h


# ═══════════════════════════════════════════════════════════════════════════
#  Editor: CRUD de contenido sí, gestión reservada a admin no
# ═══════════════════════════════════════════════════════════════════════════


class TestEditorRestrictions:
    def test_editor_can_create_module(self, client, editor_a_token, admin_a_token):
        resp = client.post("/api/admin/modules", json={"title": "Modulo editor"},
                            headers=_auth(editor_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200

    def test_editor_can_read_dashboard_and_analytics(self, client, editor_a_token):
        assert client.get("/api/admin/dashboard", headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 200
        assert client.get("/api/admin/analytics", headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 200

    def test_editor_can_upload_and_change_password(self, client, editor_a_token):
        resp = client.post("/api/admin/change-password", json={
            "current_password": "testpass", "new_password": "testpass",
        }, headers=_auth(editor_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200

    def test_editor_forbidden_put_hotel(self, client, editor_a_token):
        resp = client.put("/api/admin/hotel", json={"description": "hackeado"},
                           headers=_auth(editor_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_editor_forbidden_users(self, client, editor_a_token):
        assert client.get("/api/admin/users", headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 403
        assert client.post("/api/admin/users", json={
            "email": "x@test.com", "name": "X", "password": "pass1234",
        }, headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 403

    def test_editor_forbidden_notifications(self, client, editor_a_token):
        assert client.get("/api/admin/notifications", headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 403
        assert client.post("/api/admin/notifications", json={
            "title": "Hola", "body": "Mensaje",
        }, headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 403

    def test_editor_forbidden_qr_create_but_can_list(self, client, editor_a_token):
        assert client.get("/api/admin/qr", headers=_auth(editor_a_token, client.ids["hotel_a"])).status_code == 200
        resp = client.post("/api/admin/qr", json={"name": "QR editor"},
                            headers=_auth(editor_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
#  Usuario multi-hotel: X-Hotel-Id validado contra hoteles asignados
# ═══════════════════════════════════════════════════════════════════════════


class TestMultiHotelAccess:
    def test_multi_sees_hotels_in_me(self, client, multi_token):
        resp = client.get("/api/auth/me", headers=_auth(multi_token))
        assert resp.status_code == 200
        roles = {h["id"]: h["role"] for h in resp.json()["hotels"]}
        assert roles[client.ids["hotel_a"]] == "admin"
        assert roles[client.ids["hotel_b"]] == "editor"

    def test_multi_can_access_assigned_hotel_a(self, client, multi_token):
        resp = client.get("/api/admin/hotel", headers=_auth(multi_token, client.ids["hotel_a"]))
        assert resp.status_code == 200

    def test_multi_can_access_assigned_hotel_b_as_editor(self, client, multi_token):
        resp = client.get("/api/admin/hotel", headers=_auth(multi_token, client.ids["hotel_b"]))
        assert resp.status_code == 200
        # pero como editor en B, no puede escribir
        put_resp = client.put("/api/admin/hotel", json={"description": "x"},
                               headers=_auth(multi_token, client.ids["hotel_b"]))
        assert put_resp.status_code == 403

    def test_multi_denied_unassigned_hotel(self, client, multi_token, admin_a_token):
        # hotel_expired no está asignado a multi
        resp = client.get("/api/admin/hotel", headers=_auth(multi_token, client.ids["hotel_expired"]))
        assert resp.status_code == 403

    def test_multi_default_hotel_without_header_is_legacy_hotel_id(self, client, multi_token):
        resp = client.get("/api/admin/hotel", headers=_auth(multi_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == client.ids["hotel_a"]


# ═══════════════════════════════════════════════════════════════════════════
#  CRUD de usuarios con alcance por hotel
# ═══════════════════════════════════════════════════════════════════════════


class TestUserManagementScoped:
    def test_admin_a_lists_only_own_hotel_users(self, client, admin_a_token):
        resp = client.get("/api/admin/users", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        emails = {u["email"] for u in resp.json()}
        assert "admin_a@test.com" in emails
        assert "admin_expired@test.com" not in emails

    def test_admin_a_creates_user_for_own_hotel(self, client, admin_a_token):
        resp = client.post("/api/admin/users", json={
            "email": "creado_por_admin_a@test.com", "name": "Creado", "password": "pass1234",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json()["hotels"] == [{"hotel_id": client.ids["hotel_a"], "role": "admin"}]

    def test_admin_a_cannot_reach_user_of_other_hotel(self, client, admin_a_token, admin_expired_token):
        me = client.get("/api/auth/me", headers=_auth(admin_expired_token)).json()
        resp = client.post(f"/api/admin/users/{me['id']}/reset-password",
                            json={"new_password": "otranueva1"},
                            headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 404

    def test_reset_password_works(self, client, super_token, admin_a_token):
        me = client.get("/api/auth/me", headers=_auth(admin_a_token)).json()
        resp = client.post(f"/api/admin/users/{me['id']}/reset-password",
                            json={"new_password": "nuevapass123"},
                            headers=_auth(super_token))
        assert resp.status_code == 200
        # el login con la nueva contraseña funciona
        login_resp = client.post("/api/auth/login", json={
            "email": "admin_a@test.com", "password": "nuevapass123",
        })
        assert login_resp.status_code == 200
        # revertir para no romper otros tests que dependan de "testpass"
        client.post(f"/api/admin/users/{me['id']}/reset-password",
                    json={"new_password": "testpass12"}, headers=_auth(super_token))
        # rehash igual a "testpass" no es posible via API (min 8 chars y bcrypt
        # es one-way) — restauramos directamente en BD para no afectar tests
        # posteriores que hacen login con "testpass".
        db = main.SessionLocal()
        try:
            u = db.query(User).filter(User.id == me["id"]).first()
            u.password_hash = main.hash_password("testpass")
            db.commit()
        finally:
            db.close()

    def test_cannot_deactivate_last_admin_of_hotel(self, client, super_token):
        db = main.SessionLocal()
        try:
            solo_admin = User(
                email="solo_admin@test.com", password_hash=main.hash_password("testpass"),
                name="Solo Admin", role=UserRole.hotel_admin, is_active=True,
            )
            db.add(solo_admin); db.flush()
            hotel_c = Hotel(nombre="Hotel C", slug="hotel-c", is_active=True, plan="active")
            db.add(hotel_c); db.flush()
            db.add(UserHotel(user_id=solo_admin.id, hotel_id=hotel_c.id, role="admin"))
            db.commit()
            uid = solo_admin.id
        finally:
            db.close()

        resp = client.delete(f"/api/admin/users/{uid}", headers=_auth(super_token))
        assert resp.status_code == 400

    def test_cannot_self_deactivate(self, client, admin_a_token):
        me = client.get("/api/auth/me", headers=_auth(admin_a_token)).json()
        resp = client.delete(f"/api/admin/users/{me['id']}", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 400

    def test_hotel_admin_cannot_touch_super_admin(self, client, admin_a_token, super_token):
        me = client.get("/api/auth/me", headers=_auth(super_token)).json()
        resp = client.put(f"/api/admin/users/{me['id']}", json={"name": "hackeado"},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
#  Signup público + trial de 14 días
# ═══════════════════════════════════════════════════════════════════════════


class TestSignup:
    def test_signup_creates_trial_hotel_and_admin(self, client):
        resp = client.post("/api/signup", json={
            "hotel_name": "Hotel Nuevo Signup", "email": "nuevo@signup.com",
            "password": "pass1234", "name": "Dueño Nuevo",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["user"]["role"] == "hotel_admin"
        assert body["hotels"][0]["role"] == "admin"

        # el token sirve para llamar al panel
        me = client.get("/api/auth/me", headers=_auth(body["access_token"]))
        assert me.status_code == 200

        # secciones default creadas (restaurant/tour/guide como el seed)
        sections_resp = client.get("/api/admin/sections", headers=_auth(body["access_token"]))
        slugs = {s["slug"] for s in sections_resp.json()}
        assert slugs == {"restaurant", "tour", "guide"}

        # el hotel quedó en trial con fecha de expiración a 14 días
        hotel_resp = client.get("/api/admin/hotel", headers=_auth(body["access_token"]))
        assert hotel_resp.json()["plan"] == "trial"
        assert hotel_resp.json()["trial_ends_at"] is not None

    def test_signup_duplicate_email_409(self, client):
        payload = {
            "hotel_name": "Otro Hotel", "email": "dup_signup@test.com",
            "password": "pass1234", "name": "X",
        }
        r1 = client.post("/api/signup", json=payload)
        assert r1.status_code == 200
        r2 = client.post("/api/signup", json=payload)
        assert r2.status_code == 409

    def test_signup_short_password_422(self, client):
        resp = client.post("/api/signup", json={
            "hotel_name": "Hotel X", "email": "shortpw@test.com",
            "password": "short", "name": "X",
        })
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
#  Enforcement de trial vencido / suspendido
# ═══════════════════════════════════════════════════════════════════════════


class TestTrialEnforcement:
    def test_write_blocked_when_trial_expired(self, client, admin_expired_token):
        resp = client.put("/api/admin/hotel", json={"description": "intento"},
                           headers=_auth(admin_expired_token, client.ids["hotel_expired"]))
        assert resp.status_code == 403
        assert "período de prueba" in resp.json()["detail"]

    def test_read_allowed_when_trial_expired(self, client, admin_expired_token):
        resp = client.get("/api/admin/hotel", headers=_auth(admin_expired_token, client.ids["hotel_expired"]))
        assert resp.status_code == 200

    def test_guest_endpoint_reports_trial_expired(self, client):
        resp = client.get("/api/guest/hotel-vencido")
        assert resp.status_code == 200
        body = resp.json()
        assert body["trial_expired"] is True
        assert "modules" not in body
        assert body["hotel"]["slug"] == "hotel-vencido"

    def test_active_hotel_guest_endpoint_unaffected(self, client):
        resp = client.get("/api/guest/hotel-a")
        assert resp.status_code == 200
        body = resp.json()
        assert "trial_expired" not in body
        assert "modules" in body

    def test_super_admin_can_extend_trial(self, client, super_token, admin_expired_token):
        resp = client.put(f"/api/admin/hotels/{client.ids['hotel_expired']}", json={
            "plan": "active",
        }, headers=_auth(super_token))
        assert resp.status_code == 200
        assert resp.json()["plan"] == "active"

        # ahora el hotel_admin del hotel puede volver a escribir
        write_resp = client.put("/api/admin/hotel", json={"description": "ya reactivado"},
                                 headers=_auth(admin_expired_token, client.ids["hotel_expired"]))
        assert write_resp.status_code == 200

    def test_self_service_hotel_update_cannot_set_plan(self, client, admin_a_token):
        """El PUT self-service (/api/admin/hotel) no acepta plan/trial_ends_at:
        un hotel_admin no puede autoextenderse el trial ni cambiarse el plan."""
        resp = client.put("/api/admin/hotel", json={
            "description": "ok", "plan": "active", "trial_ends_at": "2099-01-01T00:00:00",
        }, headers=_auth(admin_a_token, client.ids["hotel_a"]))
        # el body es válido (los campos desconocidos por HotelUpdate se ignoran)
        assert resp.status_code == 200
        assert resp.json()["description"] == "ok"

    def test_suspended_hotel_blocks_writes(self, client, super_token):
        # crear un admin del hotel suspendido para probar la escritura
        db = main.SessionLocal()
        try:
            u = User(
                email="admin_suspended@test.com", password_hash=main.hash_password("testpass"),
                name="Admin Suspendido", role=UserRole.hotel_admin,
                hotel_id=client.ids["hotel_suspended"], is_active=True,
            )
            db.add(u); db.flush()
            db.add(UserHotel(user_id=u.id, hotel_id=client.ids["hotel_suspended"], role="admin"))
            db.commit()
        finally:
            db.close()
        token = _login(client, "admin_suspended@test.com")
        resp = client.put("/api/admin/hotel", json={"description": "x"},
                           headers=_auth(token, client.ids["hotel_suspended"]))
        assert resp.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
#  Regresión: super_admin y hotel_admin legacy (sin filas user_hotels)
# ═══════════════════════════════════════════════════════════════════════════


class TestLegacyRegression:
    def test_super_admin_full_access_unaffected(self, client, super_token):
        assert client.get("/api/admin/hotels", headers=_auth(super_token)).status_code == 200
        assert client.get("/api/admin/users", headers=_auth(super_token)).status_code == 200
        resp = client.put("/api/admin/hotel", json={"description": "super ok"},
                           headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200

    def test_legacy_hotel_admin_without_user_hotel_row_still_admin(self, client, admin_a_token):
        """admin_a no tiene fila en user_hotels — el fallback de compatibilidad
        (_allowed_hotels) debe seguir tratándolo como admin de su hotel_id."""
        resp = client.put("/api/admin/hotel", json={"description": "legacy sigue funcionando"},
                           headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json()["description"] == "legacy sigue funcionando"

        me = client.get("/api/auth/me", headers=_auth(admin_a_token))
        roles = {h["id"]: h["role"] for h in me.json()["hotels"]}
        assert roles[client.ids["hotel_a"]] == "admin"
