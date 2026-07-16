"""
Regression tests for P1 items — high-severity security hardening.
Run with: pytest tests/ -v  (from project root)
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("HOSTELFLOW_SECRET", "test-secret-key-not-for-prod")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")

import main
from main import app
from models import Base, Hotel, User, GuestLead, AccessLog, UserRole


# ── Fixtures (BD temporal aislada, mismo patrón que test_p0_security) ───────


@pytest.fixture(scope="module")
def client():
    main.limiter.enabled = False  # los tests de 429 lo activan puntualmente

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
            nombre="Hotel Azul", slug="hotel-azul", is_active=True,
            custom_js="alert('spy')", custom_css="body { color: red; }",
        )
        hotel_b = Hotel(nombre="Hotel Rojo", slug="hotel-rojo", is_active=True)
        db.add_all([hotel_a, hotel_b])
        db.flush()
        super_admin = User(
            email="super@test.com", password_hash=main.hash_password("testpass"),
            name="Super", role=UserRole.super_admin, is_active=True,
        )
        db.add(super_admin)
        lead_a = GuestLead(hotel_id=hotel_a.id, name="Lead A")
        lead_b = GuestLead(hotel_id=hotel_b.id, name="Lead B")
        db.add_all([lead_a, lead_b])
        db.commit()
        ids = {"hotel_a": hotel_a.id, "hotel_b": hotel_b.id,
               "lead_a": lead_a.id, "lead_b": lead_b.id}
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


@pytest.fixture
def super_token(client):
    resp = client.post("/api/auth/login", json={
        "email": "super@test.com", "password": "testpass"
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _auth(token, hotel_id=None):
    h = {"Authorization": f"Bearer {token}"}
    if hotel_id:
        h["X-Hotel-Id"] = str(hotel_id)
    return h


# ═══════════════════════════════════════════════════════════════════════════
#  P1-1: content_html sanitizado (SEC A1)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_1_SanitizeContentHtml:
    XSS = '<p>Hola <strong>mundo</strong></p><script>alert(1)</script><img src="x" onerror="alert(2)">'

    def test_module_create_strips_script(self, client, super_token):
        resp = client.post("/api/admin/modules", json={
            "title": "XSS mod", "content_html": self.XSS,
        }, headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        html = resp.json()["content_html"]
        assert "<script" not in html
        assert "onerror" not in html
        assert "<strong>mundo</strong>" in html  # formato legítimo conservado

    def test_module_update_strips_script(self, client, super_token):
        created = client.post("/api/admin/modules", json={"title": "m2", "content_html": "<p>ok</p>"},
                              headers=_auth(super_token, client.ids["hotel_a"])).json()
        resp = client.put(f"/api/admin/modules/{created['id']}", json={
            "content_html": '<b>bold</b><script>evil()</script>',
        }, headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert "<script" not in resp.json()["content_html"]
        assert "<b>bold</b>" in resp.json()["content_html"]

    def test_post_create_strips_script(self, client, super_token):
        resp = client.post("/api/admin/posts", json={
            "section": "restaurant", "title": "XSS post", "content_html": self.XSS,
        }, headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert "<script" not in resp.json()["content_html"]

    def test_output_sanitized_for_legacy_data(self, client):
        """Defensa en profundidad: datos ya guardados con XSS salen limpios."""
        db = main.SessionLocal()
        try:
            from models import ContentModule
            db.add(ContentModule(hotel_id=client.ids["hotel_a"], module_type="custom",
                                 title="Legacy", content_html='<script>old()</script><p>legit</p>',
                                 is_active=True))
            db.commit()
        finally:
            db.close()
        resp = client.get("/api/guest/hotel-azul")
        assert resp.status_code == 200
        for m in resp.json()["modules"]:
            assert "<script" not in (m["content_html"] or "")


# ═══════════════════════════════════════════════════════════════════════════
#  P1-2: custom_js no se sirve; custom_css saneado (SEC A2)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_2_CustomJsCss:
    def test_custom_js_absent_from_public_api(self, client):
        resp = client.get("/api/guest/hotel-azul")
        assert resp.status_code == 200
        assert "custom_js" not in resp.json()["hotel"]

    def test_custom_js_absent_from_admin_hotel(self, client, super_token):
        resp = client.get("/api/admin/hotel", headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert "custom_js" not in resp.json()

    def test_custom_js_in_update_is_ignored(self, client, super_token):
        resp = client.put("/api/admin/hotel", json={"custom_js": "alert(1)", "description": "x"},
                          headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert "custom_js" not in resp.json()

    def test_custom_css_sanitized_on_save(self, client, super_token):
        evil = "body{background:url(javascript:alert(1))} @import url(http://evil.com/x.css); .a{width:expression(alert(1))} </style><script>x()</script>"
        resp = client.put("/api/admin/hotel", json={"custom_css": evil},
                          headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        css = resp.json()["custom_css"] or ""
        assert "javascript:" not in css.lower()
        assert "@import" not in css.lower()
        assert "expression(" not in css.lower()
        assert "</style" not in css.lower()
        assert "<script" not in css.lower()

    def test_custom_css_legit_kept(self, client, super_token):
        ok = "body { color: #333; background: url(https://cdn.example.com/bg.png); }"
        resp = client.put("/api/admin/hotel", json={"custom_css": ok},
                          headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert "https://cdn.example.com/bg.png" in resp.json()["custom_css"]


# ═══════════════════════════════════════════════════════════════════════════
#  P1-3: JWT 8h + expires_in (SEC A3)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_3_ShortLivedJWT:
    def test_login_returns_expires_in(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "super@test.com", "password": "testpass"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["expires_in"] == main.ACCESS_TOKEN_EXPIRE_HOURS * 3600

    def test_token_expires_in_8_hours(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "super@test.com", "password": "testpass"})
        token = resp.json()["access_token"]
        payload = pyjwt.decode(token, os.environ["HOSTELFLOW_SECRET"], algorithms=["HS256"])
        exp = datetime.utcfromtimestamp(payload["exp"])
        delta = exp - datetime.utcnow()
        assert timedelta(hours=7, minutes=55) < delta <= timedelta(hours=8, minutes=5)

    def test_expired_token_rejected(self, client):
        expired = pyjwt.encode(
            {"sub": "1", "exp": datetime.utcnow() - timedelta(minutes=1)},
            os.environ["HOSTELFLOW_SECRET"], algorithm="HS256")
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
#  P1-4: eventos con tenant derivado del slug (SEC A4)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_4_GuestEvents:
    def test_event_by_slug_ok(self, client):
        resp = client.post("/api/guest/hotel-azul/events", json={
            "event_type": "page_view", "page_view": "home"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_event_unknown_slug_404(self, client):
        resp = client.post("/api/guest/no-existe/events", json={"event_type": "page_view"})
        assert resp.status_code == 404

    def test_event_invalid_type_422(self, client):
        resp = client.post("/api/guest/hotel-azul/events", json={"event_type": "hackeo"})
        assert resp.status_code == 422

    def test_lead_from_other_hotel_stored_as_null(self, client):
        resp = client.post("/api/guest/hotel-azul/events", json={
            "event_type": "module_open", "guest_lead_id": client.ids["lead_b"]})
        assert resp.status_code == 200
        db = main.SessionLocal()
        try:
            log = db.query(AccessLog).filter(
                AccessLog.hotel_id == client.ids["hotel_a"],
                AccessLog.event_type == "module_open",
            ).order_by(AccessLog.id.desc()).first()
            assert log is not None
            assert log.guest_lead_id is None
        finally:
            db.close()

    def test_own_lead_is_kept(self, client):
        resp = client.post("/api/guest/hotel-azul/events", json={
            "event_type": "faq_open", "guest_lead_id": client.ids["lead_a"]})
        assert resp.status_code == 200
        db = main.SessionLocal()
        try:
            log = db.query(AccessLog).filter(
                AccessLog.hotel_id == client.ids["hotel_a"],
                AccessLog.event_type == "faq_open",
            ).order_by(AccessLog.id.desc()).first()
            assert log.guest_lead_id == client.ids["lead_a"]
        finally:
            db.close()

    def test_user_agent_truncated_to_300(self, client):
        resp = client.post("/api/guest/hotel-azul/events",
                           json={"event_type": "page_view"},
                           headers={"User-Agent": "X" * 1000})
        assert resp.status_code == 200
        db = main.SessionLocal()
        try:
            log = db.query(AccessLog).order_by(AccessLog.id.desc()).first()
            assert len(log.user_agent) <= 300
        finally:
            db.close()

    def test_legacy_endpoint_still_works_with_validation(self, client):
        ok = client.post("/api/guest/events", json={
            "hotel_id": client.ids["hotel_a"], "event_type": "promo_click"})
        assert ok.status_code == 200
        bad_hotel = client.post("/api/guest/events", json={
            "hotel_id": 99999, "event_type": "promo_click"})
        assert bad_hotel.status_code == 404
        bad_type = client.post("/api/guest/events", json={
            "hotel_id": client.ids["hotel_a"], "event_type": "invented"})
        assert bad_type.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
#  P1-6: rate limiting (SEC A6)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_6_RateLimit:
    def test_login_rate_limited_429(self, client):
        main.limiter.enabled = True
        try:
            statuses = []
            for _ in range(7):
                r = client.post("/api/auth/login", json={
                    "email": "super@test.com", "password": "wrong"})
                statuses.append(r.status_code)
            assert 429 in statuses
            # El handler responde en español
            last_429 = [s for s in statuses if s == 429]
            assert last_429
        finally:
            main.limiter.enabled = False

    def test_429_message_in_spanish(self, client):
        main.limiter.enabled = True
        try:
            resp = None
            for _ in range(7):
                resp = client.post("/api/auth/login", json={
                    "email": "super@test.com", "password": "wrong"})
                if resp.status_code == 429:
                    break
            assert resp.status_code == 429
            assert "Demasiadas solicitudes" in resp.json()["detail"]
        finally:
            main.limiter.enabled = False


# ═══════════════════════════════════════════════════════════════════════════
#  P1-7: cabeceras de seguridad + CSP (SEC M1)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_7_SecurityHeaders:
    def test_common_headers_present(self, client):
        resp = client.get("/admin")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert resp.headers.get("x-frame-options") == "DENY"
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "https://fonts.gstatic.com" in csp
        assert "https://fonts.googleapis.com" in csp

    def test_guest_page_embeddable_same_origin_only(self, client):
        resp = client.get("/g/hotel-azul")
        csp = resp.headers.get("content-security-policy", "")
        assert "frame-ancestors 'self'" in csp
        assert "x-frame-options" not in resp.headers

    def test_hsts_only_over_https(self, client):
        plain = client.get("/admin")
        assert "strict-transport-security" not in plain.headers
        tls = client.get("/admin", headers={"x-forwarded-proto": "https"})
        assert tls.headers.get("strict-transport-security") == "max-age=31536000"


# ═══════════════════════════════════════════════════════════════════════════
#  P1-8: validación estricta (SEC M4)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_8_StrictValidation:
    def test_login_invalid_email_422(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "no-es-un-email", "password": "x"})
        assert resp.status_code == 422

    def test_onboarding_invalid_email_422(self, client):
        resp = client.post("/api/guest/hotel-azul/onboarding", json={
            "name": "Juan", "email": "basura"})
        assert resp.status_code == 422

    def test_onboarding_invalid_date_422(self, client):
        resp = client.post("/api/guest/hotel-azul/onboarding", json={
            "name": "Juan", "check_in_date": "no-es-fecha"})
        assert resp.status_code == 422

    def test_onboarding_invalid_whatsapp_422(self, client):
        resp = client.post("/api/guest/hotel-azul/onboarding", json={
            "name": "Juan", "whatsapp": "abc<script>"})
        assert resp.status_code == 422

    def test_onboarding_valid_data_ok(self, client):
        resp = client.post("/api/guest/hotel-azul/onboarding", json={
            "name": "Maria", "email": "maria@example.com",
            "whatsapp": "+52 999 123-4567",
            "check_in_date": "2026-08-01", "check_out_date": "2026-08-05",
        })
        assert resp.status_code == 200
        assert resp.json()["name"] == "Maria"

    def test_promo_invalid_date_422(self, client, super_token):
        resp = client.post("/api/admin/promos", json={
            "title": "Promo mala", "start_date": "fecha-basura"},
            headers=_auth(super_token, client.ids["hotel_a"]))
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
#  P1-9: dependencias (PyJWT en uso, sin python-jose/passlib)
# ═══════════════════════════════════════════════════════════════════════════


class TestP1_9_Dependencies:
    def test_no_jose_or_passlib_in_requirements(self):
        req = os.path.join(os.path.dirname(__file__), "..", "requirements.txt")
        with open(req, encoding="utf-8") as f:
            content = f.read().lower()
        assert "python-jose" not in content
        assert "passlib" not in content
        assert "pyjwt" in content

    def test_main_uses_pyjwt(self):
        import jwt as jwt_mod
        assert main.jwt is jwt_mod
        assert hasattr(main.jwt, "PyJWTError")
