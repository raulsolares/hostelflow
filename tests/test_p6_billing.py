"""
P6 — Pagos automatizados con Stripe (plan único, cupones nativos de Checkout,
facturas manuales desde el dashboard de Stripe).

Cubre:
  - POST /api/admin/billing/checkout: auth/permisos, 503 sin configurar,
    creación (y reutilización) de Customer, sesión de Checkout -> {url}.
  - GET /api/admin/billing/portal: 404 sin customer, 200 -> {url} con customer.
  - POST /api/webhooks/stripe: firma inválida -> 400; checkout.session.completed
    activa el hotel; customer.subscription.updated/deleted actualizan plan;
    idempotencia; evento de hotel desconocido no rompe.
  - Exención de _enforce_trial_write para /api/admin/billing/*: un hotel con
    trial vencido puede iniciar checkout pero sigue bloqueado en el resto de
    endpoints de escritura.
  - has_subscription en GET /api/admin/hotel y ausencia de IDs de Stripe en
    GET /api/guest/{slug}.

Nada de red real: todas las llamadas al SDK de stripe se mockean con
monkeypatch.

Run with: pytest tests/ -v  (from project root)
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
import stripe
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
        hotel_expired = Hotel(
            nombre="Hotel Vencido", slug="hotel-vencido-billing", is_active=True,
            plan="trial", trial_ends_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add_all([hotel_a, hotel_expired])
        db.flush()

        admin_a = User(
            email="admin_a@test.com", password_hash=main.hash_password("testpass"),
            name="Admin A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        editor_a = User(
            email="editor_a@test.com", password_hash=main.hash_password("testpass"),
            name="Editor A", role=UserRole.hotel_admin, hotel_id=hotel_a.id, is_active=True,
        )
        admin_expired = User(
            email="admin_expired_billing@test.com", password_hash=main.hash_password("testpass"),
            name="Admin Vencido", role=UserRole.hotel_admin, hotel_id=hotel_expired.id, is_active=True,
        )
        db.add_all([admin_a, editor_a, admin_expired])
        db.flush()
        db.add(UserHotel(user_id=editor_a.id, hotel_id=hotel_a.id, role="editor"))
        db.add(UserHotel(user_id=admin_expired.id, hotel_id=hotel_expired.id, role="admin"))
        db.commit()

        ids = {"hotel_a": hotel_a.id, "hotel_expired": hotel_expired.id}
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
def admin_a_token(client):
    return _login(client, "admin_a@test.com")


@pytest.fixture
def editor_a_token(client):
    return _login(client, "editor_a@test.com")


@pytest.fixture
def admin_expired_token(client):
    return _login(client, "admin_expired_billing@test.com")


def _auth(token, hotel_id=None):
    h = {"Authorization": f"Bearer {token}"}
    if hotel_id:
        h["X-Hotel-Id"] = str(hotel_id)
    return h


@pytest.fixture
def billing_enabled(monkeypatch):
    """Activa BILLING_ENABLED con config falsa (sin red real)."""
    monkeypatch.setattr(main, "STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setattr(main, "STRIPE_WEBHOOK_SECRET", "whsec_fake")
    monkeypatch.setattr(main, "STRIPE_PRICE_ID", "price_fake123")
    monkeypatch.setattr(main, "BILLING_ENABLED", True)


def _reset_hotel_stripe_fields(hotel_id: int):
    db = main.SessionLocal()
    try:
        h = db.query(Hotel).filter(Hotel.id == hotel_id).first()
        h.stripe_customer_id = None
        h.stripe_subscription_id = None
        h.plan = "active"
        h.trial_ends_at = None
        db.commit()
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
#  POST /api/admin/billing/checkout
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckout:
    def test_anonymous_401(self, client):
        resp = client.post("/api/admin/billing/checkout")
        assert resp.status_code == 401

    def test_editor_forbidden(self, client, editor_a_token):
        resp = client.post("/api/admin/billing/checkout", headers=_auth(editor_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 403

    def test_503_when_not_configured(self, client, admin_a_token):
        assert main.BILLING_ENABLED is False
        resp = client.post("/api/admin/billing/checkout", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 503

    def test_creates_customer_and_returns_checkout_url(self, client, admin_a_token, billing_enabled, monkeypatch):
        _reset_hotel_stripe_fields(client.ids["hotel_a"])
        created_customers = []
        created_sessions = []

        def fake_customer_create(**kwargs):
            created_customers.append(kwargs)
            return SimpleNamespace(id="cus_fake123", **kwargs)

        def fake_session_create(**kwargs):
            created_sessions.append(kwargs)
            return SimpleNamespace(url="https://checkout.stripe.com/fake-session", **kwargs)

        monkeypatch.setattr(stripe.Customer, "create", staticmethod(fake_customer_create))
        monkeypatch.setattr(stripe.checkout.Session, "create", staticmethod(fake_session_create))

        resp = client.post("/api/admin/billing/checkout", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"url": "https://checkout.stripe.com/fake-session"}

        assert len(created_customers) == 1
        assert created_customers[0]["metadata"]["hotel_id"] == str(client.ids["hotel_a"])
        assert created_sessions[0]["customer"] == "cus_fake123"
        assert created_sessions[0]["mode"] == "subscription"
        assert created_sessions[0]["allow_promotion_codes"] is True
        assert created_sessions[0]["line_items"] == [{"price": "price_fake123", "quantity": 1}]

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.stripe_customer_id == "cus_fake123"
        finally:
            db.close()

    def test_reuses_existing_customer(self, client, admin_a_token, billing_enabled, monkeypatch):
        # el hotel ya tiene stripe_customer_id del test anterior
        create_calls = []

        def fake_customer_create(**kwargs):
            create_calls.append(kwargs)
            return SimpleNamespace(id="cus_should_not_be_used")

        def fake_session_create(**kwargs):
            return SimpleNamespace(url="https://checkout.stripe.com/fake-session-2", **kwargs)

        monkeypatch.setattr(stripe.Customer, "create", staticmethod(fake_customer_create))
        monkeypatch.setattr(stripe.checkout.Session, "create", staticmethod(fake_session_create))

        resp = client.post("/api/admin/billing/checkout", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert create_calls == []  # no se creó un customer nuevo


# ═══════════════════════════════════════════════════════════════════════════
#  GET /api/admin/billing/portal
# ═══════════════════════════════════════════════════════════════════════════


class TestPortal:
    def test_404_without_customer(self, client, admin_a_token, billing_enabled):
        _reset_hotel_stripe_fields(client.ids["hotel_a"])
        resp = client.get("/api/admin/billing/portal", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 404

    def test_200_with_customer(self, client, admin_a_token, billing_enabled, monkeypatch):
        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            hotel.stripe_customer_id = "cus_portal_test"
            db.commit()
        finally:
            db.close()

        def fake_portal_create(**kwargs):
            return SimpleNamespace(url="https://billing.stripe.com/fake-portal", **kwargs)

        monkeypatch.setattr(stripe.billing_portal.Session, "create", staticmethod(fake_portal_create))

        resp = client.get("/api/admin/billing/portal", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json() == {"url": "https://billing.stripe.com/fake-portal"}


# ═══════════════════════════════════════════════════════════════════════════
#  POST /api/webhooks/stripe
# ═══════════════════════════════════════════════════════════════════════════


class TestWebhook:
    def test_invalid_signature_400(self, client, billing_enabled, monkeypatch):
        def fake_construct_event(payload, sig_header, secret):
            raise stripe.SignatureVerificationError("Invalid signature", sig_header="bad")

        monkeypatch.setattr(stripe.Webhook, "construct_event", staticmethod(fake_construct_event))
        resp = client.post("/api/webhooks/stripe", json={"type": "checkout.session.completed"},
                            headers={"stripe-signature": "bad-sig"})
        assert resp.status_code == 400

    def test_503_when_not_configured(self, client):
        assert main.BILLING_ENABLED is False
        resp = client.post("/api/webhooks/stripe", json={}, headers={"stripe-signature": "x"})
        assert resp.status_code == 503

    def _send_event(self, client, monkeypatch, event_type, data_object):
        fake_event = {"type": event_type, "data": {"object": data_object}}

        def fake_construct_event(payload, sig_header, secret):
            return fake_event

        monkeypatch.setattr(stripe.Webhook, "construct_event", staticmethod(fake_construct_event))
        return client.post("/api/webhooks/stripe", json={"raw": "ignored-by-mock"},
                            headers={"stripe-signature": "valid-sig"})

    def test_checkout_session_completed_activates_hotel(self, client, billing_enabled, monkeypatch):
        _reset_hotel_stripe_fields(client.ids["hotel_a"])
        db = main.SessionLocal()
        try:
            h = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            h.plan = "trial"
            h.trial_ends_at = datetime.utcnow() + timedelta(days=5)
            db.commit()
        finally:
            db.close()

        data_object = {
            "customer": "cus_webhook_1", "subscription": "sub_webhook_1",
            "client_reference_id": str(client.ids["hotel_a"]),
            "metadata": {"hotel_id": str(client.ids["hotel_a"])},
        }
        resp = self._send_event(client, monkeypatch, "checkout.session.completed", data_object)
        assert resp.status_code == 200

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.plan == "active"
            assert hotel.trial_ends_at is None
            assert hotel.stripe_customer_id == "cus_webhook_1"
            assert hotel.stripe_subscription_id == "sub_webhook_1"
        finally:
            db.close()

    def test_subscription_updated_canceled_suspends(self, client, billing_enabled, monkeypatch):
        data_object = {"id": "sub_webhook_1", "customer": "cus_webhook_1", "status": "canceled"}
        resp = self._send_event(client, monkeypatch, "customer.subscription.updated", data_object)
        assert resp.status_code == 200

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.plan == "suspended"
        finally:
            db.close()

    def test_subscription_updated_active_reactivates(self, client, billing_enabled, monkeypatch):
        data_object = {"id": "sub_webhook_1", "customer": "cus_webhook_1", "status": "active"}
        resp = self._send_event(client, monkeypatch, "customer.subscription.updated", data_object)
        assert resp.status_code == 200

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.plan == "active"
        finally:
            db.close()

    def test_subscription_deleted_suspends_and_clears_id(self, client, billing_enabled, monkeypatch):
        data_object = {"id": "sub_webhook_1", "customer": "cus_webhook_1"}
        resp = self._send_event(client, monkeypatch, "customer.subscription.deleted", data_object)
        assert resp.status_code == 200

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.plan == "suspended"
            assert hotel.stripe_subscription_id is None
            assert hotel.stripe_customer_id == "cus_webhook_1"  # customer se conserva
        finally:
            db.close()

    def test_repeated_event_is_idempotent(self, client, billing_enabled, monkeypatch):
        data_object = {"id": "sub_webhook_1", "customer": "cus_webhook_1"}
        resp1 = self._send_event(client, monkeypatch, "customer.subscription.deleted", data_object)
        resp2 = self._send_event(client, monkeypatch, "customer.subscription.deleted", data_object)
        assert resp1.status_code == 200
        assert resp2.status_code == 200

        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            assert hotel.plan == "suspended"
            assert hotel.stripe_subscription_id is None
        finally:
            db.close()

    def test_unknown_hotel_event_does_not_crash(self, client, billing_enabled, monkeypatch):
        data_object = {"id": "sub_does_not_exist", "customer": "cus_does_not_exist", "status": "active"}
        resp = self._send_event(client, monkeypatch, "customer.subscription.updated", data_object)
        assert resp.status_code == 200

    def test_ignored_event_type_returns_200(self, client, billing_enabled, monkeypatch):
        resp = self._send_event(client, monkeypatch, "invoice.paid", {"id": "in_123"})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
#  Exención del enforcement de trial para /api/admin/billing/*
# ═══════════════════════════════════════════════════════════════════════════


class TestTrialExemption:
    def test_expired_trial_hotel_can_checkout(self, client, admin_expired_token, billing_enabled, monkeypatch):
        def fake_customer_create(**kwargs):
            return SimpleNamespace(id="cus_expired_hotel")

        def fake_session_create(**kwargs):
            return SimpleNamespace(url="https://checkout.stripe.com/expired-hotel", **kwargs)

        monkeypatch.setattr(stripe.Customer, "create", staticmethod(fake_customer_create))
        monkeypatch.setattr(stripe.checkout.Session, "create", staticmethod(fake_session_create))

        resp = client.post("/api/admin/billing/checkout",
                            headers=_auth(admin_expired_token, client.ids["hotel_expired"]))
        # No debe ser el 403 de trial vencido: debe completarse (200).
        assert resp.status_code == 200, resp.text

    def test_expired_trial_hotel_still_blocked_on_modules(self, client, admin_expired_token):
        resp = client.post("/api/admin/modules", json={"title": "Bloqueado"},
                            headers=_auth(admin_expired_token, client.ids["hotel_expired"]))
        assert resp.status_code == 403
        assert "período de prueba" in resp.json()["detail"]


# ═══════════════════════════════════════════════════════════════════════════
#  Serialización: has_subscription en admin, IDs de Stripe ausentes en guest
# ═══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    def test_has_subscription_in_admin_hotel(self, client, admin_a_token):
        db = main.SessionLocal()
        try:
            hotel = db.query(Hotel).filter(Hotel.id == client.ids["hotel_a"]).first()
            hotel.stripe_subscription_id = "sub_serialization_test"
            db.commit()
        finally:
            db.close()

        resp = client.get("/api/admin/hotel", headers=_auth(admin_a_token, client.ids["hotel_a"]))
        assert resp.status_code == 200
        assert resp.json()["has_subscription"] is True

    def test_stripe_ids_not_in_guest_endpoint(self, client):
        resp = client.get(f"/api/guest/hotel-a")
        assert resp.status_code == 200
        body = resp.json()
        assert "stripe_customer_id" not in body["hotel"]
        assert "stripe_subscription_id" not in body["hotel"]
        # has_subscription (booleano) sí puede aparecer, pero nunca los IDs.
