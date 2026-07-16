"""
Regression tests for P0 items — bugs and critical security fixes.
Run with: pytest tests/ -v  (from project root)
"""

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set env vars BEFORE importing main — avoid RuntimeError from SECRET_KEY check
os.environ.setdefault("HOSTELFLOW_SECRET", "test-secret-key-not-for-prod")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")

import main
from main import app, STATIC_DIR, UPLOAD_DIR, QR_DIR
from models import Base, Hotel, User, QRSource, UserRole


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def client():
    """TestClient with a temp-file SQLite database shared by all connections."""
    # Create a temp database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    db_url = f"sqlite:///{db_path}"

    # Desactivar rate limiting durante la suite (los tests de 429 lo
    # re-activan puntualmente) — de lo contrario los logins repetidos
    # de las fixtures disparan el límite 5/minute.
    main.limiter.enabled = False

    # Override engine to use temp-file DB
    old_engine = main.engine
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    main.DATABASE_URL = db_url
    main.engine = create_engine(db_url, connect_args={"check_same_thread": False})
    main.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=main.engine)

    # Create tables + seed data
    Base.metadata.create_all(bind=main.engine)
    db = main.SessionLocal()
    try:
        hotel = Hotel(nombre="Test Hotel", slug="test-hotel", is_active=True)
        db.add(hotel)
        db.flush()
        super_admin = User(
            email="super@test.com",
            password_hash=main.hash_password("testpass"),
            name="Super",
            role=UserRole.super_admin,
            is_active=True,
        )
        hotel_admin = User(
            email="admin@test.com",
            password_hash=main.hash_password("testpass"),
            name="Admin",
            role=UserRole.hotel_admin,
            hotel_id=hotel.id,
            is_active=True,
        )
        db.add_all([super_admin, hotel_admin])
        db.commit()
    finally:
        db.close()

    yield TestClient(app)

    # Cleanup
    main.engine = old_engine
    main.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=old_engine)
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


@pytest.fixture
def admin_token(client):
    resp = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "testpass"
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


VALID_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100


# ═══════════════════════════════════════════════════════════════════════════
#  P0-2: /sw.js returns 200
# ═══════════════════════════════════════════════════════════════════════════


class TestP0_2_SwJs:
    def test_sw_js_returns_200_and_javascript(self, client):
        resp = client.get("/sw.js")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/javascript"
        assert "CACHE_NAME" in resp.text

    def test_sw_js_has_nosniff_header(self, client):
        resp = client.get("/sw.js")
        assert resp.headers.get("x-content-type-options") == "nosniff"


# ═══════════════════════════════════════════════════════════════════════════
#  P0-1: POST /api/admin/qr — crear QR
# ═══════════════════════════════════════════════════════════════════════════


class TestP0_1_CreateQR:
    def test_create_qr_auth_required(self, client):
        """Anonymous → 401"""
        resp = client.post("/api/admin/qr", json={"name": "Test", "source_type": "lobby"})
        assert resp.status_code == 401

    def test_create_qr_success(self, client, super_token):
        resp = client.post(
            "/api/admin/qr",
            json={"name": "Test QR", "source_type": "lobby"},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Test QR"
        assert data["code"].startswith("LOBBY-")
        assert "url_generated" in data

    def test_create_qr_generates_png_file(self, client, super_token):
        resp = client.post(
            "/api/admin/qr",
            json={"name": "PNG Test", "source_type": "room"},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 200
        code = resp.json()["code"]
        png_path = QR_DIR / f"{code}.png"
        assert png_path.exists(), f"QR PNG not created at {png_path}"
        assert png_path.stat().st_size > 100


# ═══════════════════════════════════════════════════════════════════════════
#  P0-6: CORS restringido
# ═══════════════════════════════════════════════════════════════════════════


class TestP0_6_CORS:
    def test_allowed_origin_succeeds(self, client):
        resp = client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://testserver",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "http://testserver"

    def test_disallowed_origin_rejected(self, client):
        resp = client.options(
            "/api/auth/login",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert "access-control-allow-origin" not in resp.headers


# ═══════════════════════════════════════════════════════════════════════════
#  P0-3: Upload auth + validation
# ═══════════════════════════════════════════════════════════════════════════


class TestP0_3_Upload:
    def test_upload_requires_auth(self, client):
        resp = client.post("/api/admin/upload", files={"file": ("test.png", VALID_PNG, "image/png")})
        assert resp.status_code == 401

    def test_upload_rejects_html(self, client, super_token):
        resp = client.post(
            "/api/admin/upload",
            files={"file": ("test.html", b"<script>alert(1)</script>", "text/html")},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 415

    def test_upload_rejects_svg(self, client, super_token):
        resp = client.post(
            "/api/admin/upload",
            files={"file": ("test.svg", b'<svg onload="alert(1)">', "image/svg+xml")},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 415

    def test_upload_rejects_oversized(self, client, super_token):
        oversized = b"f" * (6 * 1024 * 1024)
        resp = client.post(
            "/api/admin/upload",
            files={"file": ("big.png", oversized, "image/png")},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 413

    def test_upload_valid_png_succeeds(self, client, super_token):
        resp = client.post(
            "/api/admin/upload",
            files={"file": ("test.png", VALID_PNG, "image/png")},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["url"].startswith("/static/uploads/")
        assert data["url"].endswith(".png")
        assert data["filename"]

    def test_upload_admin_role(self, client, admin_token):
        """hotel_admin can also upload"""
        resp = client.post(
            "/api/admin/upload",
            files={"file": ("test.png", VALID_PNG, "image/png")},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
#  P0-4: SECRET_KEY validation
# ═══════════════════════════════════════════════════════════════════════════


def test_secret_key_check_exists():
    """Verify the production guard exists in code."""
    main_path = os.path.join(os.path.dirname(__file__), "..", "main.py")
    with open(main_path, encoding="utf-8") as f:
        content = f.read()
    assert "raise RuntimeError" in content
    assert "HOSTELFLOW_SECRET debe definirse" in content


# ═══════════════════════════════════════════════════════════════════════════
#  P0-5: Seed credentials — no admin123 in source
# ═══════════════════════════════════════════════════════════════════════════


def test_no_admin123_in_code():
    """Verify 'admin123' does not appear in main.py"""
    main_path = os.path.join(os.path.dirname(__file__), "..", "main.py")
    with open(main_path, encoding="utf-8") as f:
        content = f.read()
    assert "admin123" not in content, (
        "'admin123' still present in main.py — remove it!"
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Security headers baseline
# ═══════════════════════════════════════════════════════════════════════════


def test_nosniff_header_on_all_responses(client):
    resp = client.get("/api/auth/login")
    assert resp.headers.get("x-content-type-options") == "nosniff"
