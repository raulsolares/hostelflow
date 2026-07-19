"""
HostelFlow — FastAPI main application.
SaaS digital guest guide platform for hotels.
"""

import asyncio
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List

import re
import unicodedata

import bleach
from bleach.css_sanitizer import CSSSanitizer
import jwt  # PyJWT (reemplaza a python-jose — P1-9 / SEC B1)
import qrcode
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid02 as Vapid
from py_vapid.utils import b64urlencode
from pywebpush import webpush, WebPushException
from qrcode.image.svg import SvgPathImage
import stripe
from fastapi import FastAPI, Depends, HTTPException, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session
from starlette.middleware.base import BaseHTTPMiddleware

from models import (
    Base, User, Hotel, GuestLead, ContentModule, FAQItem, Promo,
    AccessLog, QRSource, Post, Popup, UserRole, Theme,
    PushSubscription, ScheduledNotification, Section, GalleryImage,
    UserHotel,
)

# ── Config ─────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("HOSTELFLOW_SECRET")
if not SECRET_KEY or SECRET_KEY == "hostelflow-dev-secret-2026":
    if os.getenv("ENV") == "production":
        raise RuntimeError("HOSTELFLOW_SECRET debe definirse con un valor fuerte en producción")
    SECRET_KEY = "hostelflow-dev-secret-2026"  # solo dev
    print("[WARN] Usando SECRET_KEY por defecto. Define HOSTELFLOW_SECRET en producción.")
ALGORITHM = "HS256"
# Access token de vida corta (P1-3 / SEC A3). Sin refresh token: el admin SPA
# hace re-login limpio al recibir 401. Configurable por env.
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS", "8"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hostelflow.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Facturación (Stripe, P6). Plan único, cupones nativos de Stripe (checkout
# allow_promotion_codes), facturas manuales desde el dashboard. Si falta
# cualquiera de las 3 vars, BILLING_ENABLED queda False y los endpoints
# /api/admin/billing/* devuelven 503 en vez de fallar con credenciales vacías.
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
BILLING_ENABLED = bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET and STRIPE_PRICE_ID)
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
QR_DIR = STATIC_DIR / "qr"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
QR_DIR.mkdir(parents=True, exist_ok=True)

# ── Password hashing ───────────────────────────────────────────────────────

import bcrypt as _bcrypt

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


# ── VAPID (Web Push autoalojado, sin proveedor externo) ────────────────────

VAPID_KEYS_FILE = BASE_DIR / "vapid_keys.json"


def _b64url_public_key(vapid_obj: "Vapid") -> str:
    return b64urlencode(
        vapid_obj.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    )


def _load_vapid_keys():
    """Resuelve el par de claves VAPID usado para firmar los envíos Web Push.

    Prioridad: env vars `VAPID_PRIVATE_KEY`/`VAPID_PUBLIC_KEY` (producción) →
    `vapid_keys.json` en la raíz del repo (dev, reutilizado entre arranques) →
    autogenerar un par EC P-256 nuevo y persistirlo en ese archivo.
    Devuelve (objeto Vapid02 listo para firmar, public_key en base64url sin
    padding — el formato que consume `applicationServerKey` en el navegador).
    """
    env_private = os.getenv("VAPID_PRIVATE_KEY")
    env_public = os.getenv("VAPID_PUBLIC_KEY")
    if env_private and env_public:
        try:
            if "-----BEGIN" in env_private:
                vapid_obj = Vapid.from_pem(env_private.encode("utf-8"))
            else:
                vapid_obj = Vapid.from_string(env_private)
            return vapid_obj, env_public
        except Exception as exc:
            print(f"[WARN] VAPID_PRIVATE_KEY/VAPID_PUBLIC_KEY inválidas ({exc}); autogenerando claves de dev.")

    if VAPID_KEYS_FILE.exists():
        try:
            data = json.loads(VAPID_KEYS_FILE.read_text(encoding="utf-8"))
            vapid_obj = Vapid.from_pem(data["private_key_pem"].encode("utf-8"))
            return vapid_obj, data["public_key"]
        except Exception as exc:
            print(f"[WARN] No se pudo leer vapid_keys.json ({exc}); regenerando claves.")

    vapid_obj = Vapid()
    vapid_obj.generate_keys()
    public_key = _b64url_public_key(vapid_obj)
    private_pem = vapid_obj.private_pem().decode("utf-8")
    try:
        VAPID_KEYS_FILE.write_text(
            json.dumps({"private_key_pem": private_pem, "public_key": public_key}, indent=2),
            encoding="utf-8",
        )
        print(f"[INFO] Claves VAPID autogeneradas y guardadas en {VAPID_KEYS_FILE}")
    except Exception as exc:
        print(f"[WARN] No se pudo persistir vapid_keys.json ({exc}); las claves se regenerarán al reiniciar.")
    return vapid_obj, public_key


VAPID_OBJ, VAPID_PUBLIC_KEY = _load_vapid_keys()
VAPID_CLAIMS_SUB = os.getenv("VAPID_CLAIMS_SUB", "mailto:admin@hostelflow.local")


# ── Lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine, checkfirst=True)
    seed_data()
    scheduler_task = asyncio.create_task(notification_scheduler())
    yield
    scheduler_task.cancel()


# ── JWT helpers ────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── FastAPI app ────────────────────────────────────────────────────────────

app = FastAPI(title="HostelFlow", version="1.0.0", lifespan=lifespan)


# CSP (P1-7 / SEC M1). Orígenes externos legítimos verificados en templates/*.html:
# fonts.googleapis.com (stylesheets, también inyectadas por JS), fonts.gstatic.com
# (archivos de fuente) y placehold.co/images.unsplash.com (imágenes, cubiertas por
# img-src https:). wa.me/maps.google.com son solo href de navegación (no CSP).
_CSP_BASE = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "connect-src 'self'; "
    "font-src 'self' https://fonts.gstatic.com; "
    "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Cabeceras de seguridad en toda respuesta (P1-7 / SEC M1)."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.path.startswith("/g/"):
            # La guía de huésped debe poder embeberse SOLO desde el mismo
            # origen (preview del panel admin) — frame-ancestors 'self'.
            response.headers["Content-Security-Policy"] = _CSP_BASE + "; frame-ancestors 'self'"
        else:
            response.headers["Content-Security-Policy"] = _CSP_BASE + "; frame-ancestors 'none'"
            response.headers["X-Frame-Options"] = "DENY"
        # HSTS solo cuando la petición llegó por HTTPS (tras el proxy TLS)
        if request.headers.get("x-forwarded-proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response


# ── Rate limiting (P1-6 / SEC A6) ─────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Demasiadas solicitudes. Intenta de nuevo en unos minutos."},
    )


app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)


origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)


# ── DB dependency ──────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Auth dependencies ──────────────────────────────────────────────────────

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requerido")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


def require_role(*roles):
    def _dep(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Sin permisos")
        return user
    return _dep


# ── Sanitización de HTML/CSS (P1-1, P1-2 / SEC A1, A2) ────────────────────

# Allowlist de tags/atributos para content_html (módulos y posts).
_ALLOWED_TAGS = [
    "p", "br", "b", "strong", "i", "em", "u", "ul", "ol", "li",
    "h1", "h2", "h3", "h4", "a", "img", "span", "div", "blockquote",
    "hr", "table", "thead", "tbody", "tr", "td", "th",
]
_ALLOWED_ATTRS = {
    "a": ["href", "target", "rel"],
    "img": ["src", "alt", "width", "height"],
    "*": ["class", "style"],
}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto", "tel"]
_CSS_SANITIZER = CSSSanitizer()  # allowlist por defecto de propiedades CSS seguras


def sanitize_html(html: Optional[str]) -> Optional[str]:
    """Sanitiza content_html con allowlist. Se aplica al guardar (create/update)
    y también al servir (defensa en profundidad para datos ya persistidos)."""
    if not html:
        return html
    return bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        css_sanitizer=_CSS_SANITIZER,
        strip=True,
    )


# Patrones peligrosos en CSS custom (case-insensitive).
_CSS_BLOCK_RE = re.compile(
    r"expression\s*\(|javascript\s*:|@import|</style|<script",
    re.IGNORECASE,
)
# url(...) solo con esquema http/https o rutas relativas.
_CSS_URL_RE = re.compile(r"url\s*\(\s*(['\"]?)([^)'\"]*)\1\s*\)", re.IGNORECASE)


def sanitize_custom_css(css: Optional[str]) -> Optional[str]:
    """Sanea custom_css (P1-2 / SEC A2): elimina construcciones ejecutables
    (expression(), javascript:, @import, cierres de <style>, <script>) y
    neutraliza url() con esquemas que no sean http/https o relativos."""
    if not css:
        return css
    css = _CSS_BLOCK_RE.sub("", css)

    def _clean_url(m: "re.Match") -> str:
        target = m.group(2).strip()
        low = target.lower()
        if low.startswith(("http://", "https://", "/", "./", "../")) or ":" not in low:
            return m.group(0)
        return "url()"  # esquema no permitido (data:, javascript:, vbscript:, …)

    return _CSS_URL_RE.sub(_clean_url, css)


# ── i18n de contenido (P4) ──────────────────────────────────────────────────

_ALLOWED_I18N_LANGS = {"es", "en", "fr", "de", "pt"}


def _validate_and_sanitize_i18n(i18n_data: Optional[dict], html_fields: frozenset = frozenset()) -> Optional[str]:
    """Valida claves de idioma contra la allowlist, sanea los campos HTML
    indicados dentro de cada idioma, y devuelve el JSON string a persistir
    (o None si no viene i18n). 422 español si el formato es inválido."""
    if i18n_data is None:
        return None
    if not isinstance(i18n_data, dict):
        raise HTTPException(status_code=422, detail="i18n debe ser un objeto {idioma: campos}")
    cleaned: dict = {}
    for lang, fields in i18n_data.items():
        if lang not in _ALLOWED_I18N_LANGS:
            raise HTTPException(status_code=422, detail=f"Idioma no soportado en i18n: {lang}")
        if not isinstance(fields, dict):
            raise HTTPException(status_code=422, detail="Cada idioma de i18n debe mapear a un objeto de campos")
        fields = dict(fields)
        for f in html_fields:
            if fields.get(f):
                fields[f] = sanitize_html(fields[f])
        cleaned[lang] = fields
    return json.dumps(cleaned)


def _parse_json_field(raw: Optional[str]) -> Optional[dict]:
    """Parsea un campo Text que guarda JSON (i18n, header_config). Fallback a
    None si el registro está corrupto (defensa en profundidad al servir)."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _slugify(text: str) -> str:
    """Convierte un texto a slug: minúsculas, sin acentos, separado por guiones."""
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "seccion"


# ── Header y supported_languages de Hotel (P4) ──────────────────────────────

_ALLOWED_HEADER_STYLES = {"classic", "centered", "split", "custom"}
_ALLOWED_HEADER_CONFIG_KEYS = {"show_name", "overlay", "bg_color", "text_color", "align", "logo_pos"}


def _validate_header_style(v: Optional[str]) -> Optional[str]:
    if v is not None and v not in _ALLOWED_HEADER_STYLES:
        raise HTTPException(status_code=422, detail="header_style inválido (classic|centered|split|custom)")
    return v


def _validate_header_config(v) -> Optional[str]:
    if v is None:
        return None
    if not isinstance(v, dict):
        raise HTTPException(status_code=422, detail="header_config debe ser un objeto JSON")
    unknown = set(v.keys()) - _ALLOWED_HEADER_CONFIG_KEYS
    if unknown:
        raise HTTPException(status_code=422, detail=f"header_config contiene claves no permitidas: {', '.join(sorted(unknown))}")
    return json.dumps(v)


def _validate_supported_languages(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    langs = [x.strip() for x in v.split(",") if x.strip()]
    if not langs or any(l not in _ALLOWED_I18N_LANGS for l in langs):
        raise HTTPException(status_code=422, detail="supported_languages inválido (subconjunto de es,en,fr,de,pt)")
    return ",".join(langs)


# ── Pydantic schemas ──────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    hotel_name: str
    email: EmailStr
    password: str
    name: str

    @field_validator("password")
    @classmethod
    def _validate_signup_password(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError("password debe tener al menos 8 caracteres")
        return v

    @field_validator("hotel_name", "name")
    @classmethod
    def _validate_non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("Campo obligatorio")
        return v


class HotelUpdate(BaseModel):
    nombre: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    whatsapp: Optional[str] = None
    email: Optional[str] = None
    logo_url: Optional[str] = None
    cover_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    accent_color: Optional[str] = None
    privacy_policy: Optional[str] = None
    default_language: Optional[str] = None
    theme: Optional[str] = None
    custom_css: Optional[str] = None
    # custom_js eliminado del schema (P1-2 / SEC A2): decisión de producto —
    # ya no se acepta ni se sirve JS por hotel. La columna sigue en el modelo
    # (no hay migraciones); si un cliente viejo envía el campo, se ignora.
    # Branding extendido
    font_family: Optional[str] = None
    text_color: Optional[str] = None
    bg_color: Optional[str] = None
    # Textos de la experiencia
    welcome_headline: Optional[str] = None
    welcome_subtitle: Optional[str] = None
    onboarding_enabled: Optional[bool] = None
    onboarding_title: Optional[str] = None
    onboarding_subtitle: Optional[str] = None
    # Instalación PWA
    pwa_enabled: Optional[bool] = None
    pwa_short_name: Optional[str] = None
    pwa_icon_url: Optional[str] = None
    install_headline: Optional[str] = None
    install_subtitle: Optional[str] = None
    theme_id: Optional[int] = None
    # Header configurable + idiomas soportados (P4)
    header_style: Optional[str] = None
    header_config: Optional[dict] = None
    supported_languages: Optional[str] = None


class HotelSuperUpdate(HotelUpdate):
    """Extiende HotelUpdate con campos que SOLO un super_admin puede tocar
    (P5): plan/trial_ends_at. Nunca se expone en el PUT self-service
    (/api/admin/hotel) para evitar que un hotel_admin se autoextienda el
    trial — solo en PUT /api/admin/hotels/{id}."""
    plan: Optional[str] = None
    trial_ends_at: Optional[datetime] = None


# ── Theme schemas ──────────────────────────────────────────────────────────
class ThemeCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    css_content: str = ""
    is_active: bool = True


class ThemeUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    css_content: Optional[str] = None
    is_active: Optional[bool] = None


class UserHotelAssignment(BaseModel):
    hotel_id: int
    role: str = "admin"  # admin | editor

    @field_validator("role")
    @classmethod
    def _validate_assignment_role(cls, v: str) -> str:
        if v not in ("admin", "editor"):
            raise ValueError("role debe ser admin o editor")
        return v


class UserCreate(BaseModel):
    email: str
    name: str
    password: str
    role: str = "hotel_admin"  # hotel_admin | super_admin
    hotels: List[UserHotelAssignment] = []


class UserUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    hotels: Optional[List[UserHotelAssignment]] = None


class ResetPasswordRequest(BaseModel):
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class InstallEventRequest(BaseModel):
    guest_lead_id: Optional[int] = None
    event: str


class ModuleCreate(BaseModel):
    module_type: str = "custom"
    title: str
    subtitle: Optional[str] = ""
    content_html: Optional[str] = ""
    image_url: Optional[str] = None
    icon: Optional[str] = "info"
    sort_order: int = 0
    is_active: bool = True
    audience_stage: str = "all"
    i18n: Optional[dict] = None


class ModuleUpdate(BaseModel):
    module_type: Optional[str] = None
    title: Optional[str] = None
    subtitle: Optional[str] = None
    content_html: Optional[str] = None
    image_url: Optional[str] = None
    icon: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None
    audience_stage: Optional[str] = None
    i18n: Optional[dict] = None


class FAQCreate(BaseModel):
    question: str
    answer: str
    sort_order: int = 0
    is_active: bool = True
    i18n: Optional[dict] = None


class FAQUpdate(BaseModel):
    question: Optional[str] = None
    answer: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None
    i18n: Optional[dict] = None


# Fechas como datetime (P1-8 / SEC M4): pydantic parsea ISO-8601 y devuelve
# 422 con detalle si el formato es inválido (antes: try/except pass silencioso).
class PromoCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    image_url: Optional[str] = None
    price_text: Optional[str] = None
    cta_label: Optional[str] = "Ver más"
    cta_link: Optional[str] = None
    is_active: bool = True
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    i18n: Optional[dict] = None


class PromoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    price_text: Optional[str] = None
    cta_label: Optional[str] = None
    cta_link: Optional[str] = None
    is_active: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    i18n: Optional[dict] = None


_WHATSAPP_RE = re.compile(r"^[+\d][\d\s\-()]{5,25}$")


class OnboardingRequest(BaseModel):
    name: str
    whatsapp: Optional[str] = None
    email: Optional[EmailStr] = None
    check_in_date: Optional[datetime] = None
    check_out_date: Optional[datetime] = None
    language: str = "es"
    consent_contact: bool = False
    source_qr: Optional[str] = None

    @field_validator("whatsapp")
    @classmethod
    def _validate_whatsapp(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        if not _WHATSAPP_RE.match(v):
            raise ValueError("Número de WhatsApp inválido")
        return v

    @field_validator("email", mode="before")
    @classmethod
    def _empty_email_to_none(cls, v):
        if isinstance(v, str) and v.strip() == "":
            return None
        return v


# Eventos de tracking permitidos (P1-4 / SEC A4)
ALLOWED_EVENT_TYPES = {
    "page_view", "module_open", "faq_open", "promo_click", "whatsapp_click",
    "install_prompt_shown", "install_accepted", "install_dismissed",
    "installed", "onboarding_complete", "post_open", "popup_shown", "popup_click",
    "contact_whatsapp", "contact_phone", "contact_email",
    "language_change", "onboarding_skipped", "gallery_open",
}


class GuestEventRequest(BaseModel):
    """Body del endpoint nuevo POST /api/guest/{slug}/events (P1-4)."""
    event_type: str
    page_view: Optional[str] = None
    guest_lead_id: Optional[int] = None
    source_qr: Optional[str] = None


class EventRequest(BaseModel):
    """Body del endpoint legacy POST /api/guest/events (deprecated)."""
    hotel_id: int
    guest_lead_id: Optional[int] = None
    event_type: str
    page_view: Optional[str] = None
    source_qr: Optional[str] = None
    user_agent: Optional[str] = None


class QRCreate(BaseModel):
    name: str
    source_type: str = "custom"


class PostCreate(BaseModel):
    section: str
    title: str
    subtitle: Optional[str] = ""
    image_url: Optional[str] = None
    content_html: Optional[str] = ""
    button_text: Optional[str] = None
    button_url: Optional[str] = None
    icon: Optional[str] = None
    sort_order: int = 0
    is_active: bool = True
    i18n: Optional[dict] = None


class PostUpdate(BaseModel):
    section: Optional[str] = None
    title: Optional[str] = None
    subtitle: Optional[str] = None
    image_url: Optional[str] = None
    content_html: Optional[str] = None
    button_text: Optional[str] = None
    button_url: Optional[str] = None
    icon: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None
    i18n: Optional[dict] = None


class PopupCreate(BaseModel):
    title: str
    message: Optional[str] = ""
    image_url: Optional[str] = None
    button_text: Optional[str] = None
    button_url: Optional[str] = None
    trigger_type: str = "on_load"
    trigger_seconds: int = 0
    is_active: bool = True
    sort_order: int = 0
    i18n: Optional[dict] = None


class PopupUpdate(BaseModel):
    title: Optional[str] = None
    message: Optional[str] = None
    image_url: Optional[str] = None
    button_text: Optional[str] = None
    button_url: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_seconds: Optional[int] = None
    is_active: Optional[bool] = None
    sort_order: Optional[int] = None
    i18n: Optional[dict] = None


# ── Sections & Gallery schemas (P4) ─────────────────────────────────────────

class SectionCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    icon: Optional[str] = "📌"
    sort_order: int = 0
    is_active: bool = True
    i18n: Optional[dict] = None


class SectionUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    icon: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None
    i18n: Optional[dict] = None


class GalleryCreate(BaseModel):
    image_url: str
    caption: Optional[str] = None
    sort_order: int = 0
    is_active: bool = True
    i18n: Optional[dict] = None


class GalleryUpdate(BaseModel):
    image_url: Optional[str] = None
    caption: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None
    i18n: Optional[dict] = None


class PushKeys(BaseModel):
    p256dh: str
    auth: str


class PushSubscribeRequest(BaseModel):
    endpoint: str
    keys: PushKeys
    guest_lead_id: Optional[int] = None
    lang: str = "es"

    @field_validator("endpoint")
    @classmethod
    def _validate_endpoint(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 1000:
            raise ValueError("endpoint inválido")
        if not v.startswith("https://"):
            raise ValueError("endpoint debe ser https")
        return v


class PushUnsubscribeRequest(BaseModel):
    endpoint: str


class NotificationCreate(BaseModel):
    title: str
    body: str
    url: Optional[str] = None
    scheduled_at: Optional[datetime] = None

    @field_validator("title")
    @classmethod
    def _validate_title(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 120:
            raise ValueError("title debe tener entre 1 y 120 caracteres")
        return v

    @field_validator("body")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 300:
            raise ValueError("body debe tener entre 1 y 300 caracteres")
        return v


# ── Helpers ────────────────────────────────────────────────────────────────

def hotel_to_dict(h: Hotel) -> dict:
    return {
        "id": h.id, "nombre": h.nombre, "slug": h.slug,
        "logo_url": h.logo_url, "cover_url": h.cover_url,
        "primary_color": h.primary_color, "secondary_color": h.secondary_color,
        "accent_color": h.accent_color, "description": h.description,
        "whatsapp": h.whatsapp, "email": h.email, "phone": h.phone,
        "address": h.address, "privacy_policy": h.privacy_policy,
        "default_language": h.default_language, "is_active": h.is_active,
        # custom_js NO se sirve (P1-2 / SEC A2): decisión de producto. La columna
        # sigue en BD pero nunca sale por la API. custom_css se sirve saneado.
        "theme": h.theme, "custom_css": sanitize_custom_css(h.custom_css),
        "theme_id": h.theme_id,
        # Branding extendido
        "font_family": h.font_family, "text_color": h.text_color, "bg_color": h.bg_color,
        # Textos de la experiencia
        "welcome_headline": h.welcome_headline, "welcome_subtitle": h.welcome_subtitle,
        "onboarding_enabled": h.onboarding_enabled,
        "onboarding_title": h.onboarding_title, "onboarding_subtitle": h.onboarding_subtitle,
        # Instalación PWA
        "pwa_enabled": h.pwa_enabled, "pwa_short_name": h.pwa_short_name,
        "pwa_icon_url": h.pwa_icon_url,
        "install_headline": h.install_headline, "install_subtitle": h.install_subtitle,
        # Header configurable + idiomas soportados (P4)
        "header_style": h.header_style,
        "header_config": _parse_json_field(h.header_config),
        "supported_languages": [
            l for l in (h.supported_languages or "es").split(",") if l
        ],
        # SaaS: plan y trial (P5), para el banner del admin
        "plan": h.plan or "active",
        "trial_ends_at": str(h.trial_ends_at) if h.trial_ends_at else None,
        # SaaS: facturación (P6). Solo el booleano — los IDs de Stripe
        # (stripe_customer_id/stripe_subscription_id) NUNCA se exponen aquí:
        # este serializer lo usa también GET /api/guest/{slug}.
        "has_subscription": bool(h.stripe_subscription_id),
    }


def module_to_dict(m: ContentModule) -> dict:
    return {
        "id": m.id, "hotel_id": m.hotel_id, "module_type": m.module_type,
        # content_html saneado también al servir (P1-1: defensa en profundidad
        # para registros guardados antes de la sanitización en escritura)
        "title": m.title, "subtitle": m.subtitle, "content_html": sanitize_html(m.content_html),
        "image_url": m.image_url, "icon": m.icon, "sort_order": m.sort_order,
        "is_active": m.is_active, "audience_stage": m.audience_stage,
        "i18n": _parse_json_field(m.i18n),
    }


def faq_to_dict(f: FAQItem) -> dict:
    return {
        "id": f.id, "hotel_id": f.hotel_id, "question": f.question,
        "answer": f.answer, "sort_order": f.sort_order, "is_active": f.is_active,
        "i18n": _parse_json_field(f.i18n),
    }


def promo_to_dict(p: Promo) -> dict:
    return {
        "id": p.id, "hotel_id": p.hotel_id, "title": p.title,
        "description": p.description, "image_url": p.image_url,
        "price_text": p.price_text, "cta_label": p.cta_label,
        "cta_link": p.cta_link, "is_active": p.is_active,
        "start_date": str(p.start_date) if p.start_date else None,
        "end_date": str(p.end_date) if p.end_date else None,
        "i18n": _parse_json_field(p.i18n),
    }


def section_to_dict(s: Section) -> dict:
    return {
        "id": s.id, "hotel_id": s.hotel_id, "slug": s.slug, "name": s.name,
        "icon": s.icon, "sort_order": s.sort_order, "is_active": s.is_active,
        "i18n": _parse_json_field(s.i18n),
    }


def gallery_to_dict(g: GalleryImage) -> dict:
    return {
        "id": g.id, "hotel_id": g.hotel_id, "image_url": g.image_url,
        "caption": g.caption, "sort_order": g.sort_order, "is_active": g.is_active,
        "i18n": _parse_json_field(g.i18n),
        "created_at": str(g.created_at) if g.created_at else None,
    }


def lead_to_dict(l: GuestLead) -> dict:
    return {
        "id": l.id, "hotel_id": l.hotel_id, "name": l.name,
        "whatsapp": l.whatsapp, "email": l.email,
        "check_in_date": str(l.check_in_date) if l.check_in_date else None,
        "check_out_date": str(l.check_out_date) if l.check_out_date else None,
        "language": l.language, "consent_contact": l.consent_contact,
        "source_qr": l.source_qr,
        "first_seen_at": str(l.first_seen_at) if l.first_seen_at else None,
        "created_at": str(l.created_at) if l.created_at else None,
    }


def post_to_dict(p: Post) -> dict:
    return {
        "id": p.id, "hotel_id": p.hotel_id, "section": p.section,
        "title": p.title, "subtitle": p.subtitle,
        "image_url": p.image_url, "content_html": sanitize_html(p.content_html),
        "button_text": p.button_text, "button_url": p.button_url,
        "icon": p.icon, "sort_order": p.sort_order,
        "is_active": p.is_active,
        "created_at": str(p.created_at) if p.created_at else None,
        "i18n": _parse_json_field(p.i18n),
    }


def popup_to_dict(p: Popup) -> dict:
    return {
        "id": p.id, "hotel_id": p.hotel_id, "title": p.title,
        "message": p.message, "image_url": p.image_url,
        "button_text": p.button_text, "button_url": p.button_url,
        "trigger_type": p.trigger_type, "trigger_seconds": p.trigger_seconds,
        "is_active": p.is_active, "sort_order": p.sort_order,
        "created_at": str(p.created_at) if p.created_at else None,
        "i18n": _parse_json_field(p.i18n),
    }


def notification_to_dict(n: ScheduledNotification) -> dict:
    return {
        "id": n.id, "hotel_id": n.hotel_id, "title": n.title, "body": n.body,
        "url": n.url,
        "scheduled_at": str(n.scheduled_at) if n.scheduled_at else None,
        "status": n.status,
        "sent_at": str(n.sent_at) if n.sent_at else None,
        "sent_count": n.sent_count, "fail_count": n.fail_count,
        "created_at": str(n.created_at) if n.created_at else None,
    }


# ── Push notifications: envío y scheduler de fondo ─────────────────────────

def send_notification(notification_id: int) -> None:
    """Envía una notificación a todas las suscripciones del hotel.

    Síncrona a propósito: pywebpush/requests son bloqueantes. Se ejecuta desde
    `notification_scheduler` con `asyncio.to_thread` para no bloquear el loop.
    Abre su propia sesión de BD (no depende de `Depends(get_db)`).
    """
    db = SessionLocal()
    try:
        notif = db.query(ScheduledNotification).filter(ScheduledNotification.id == notification_id).first()
        if not notif:
            return
        subs = db.query(PushSubscription).filter(PushSubscription.hotel_id == notif.hotel_id).all()
        if not subs:
            notif.status = "sent"
            notif.sent_at = datetime.utcnow()
            notif.sent_count = 0
            notif.fail_count = 0
            db.commit()
            return

        payload = json.dumps({
            "title": notif.title,
            "body": notif.body,
            "url": notif.url or "/",
            "tag": f"hostelflow-notif-{notif.id}",
        })
        sent, failed = 0, 0
        for sub in subs:
            subscription_info = {
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            }
            try:
                webpush(
                    subscription_info=subscription_info,
                    data=payload,
                    vapid_private_key=VAPID_OBJ,
                    vapid_claims={"sub": VAPID_CLAIMS_SUB},
                )
                sent += 1
            except WebPushException as exc:
                status_code = getattr(exc.response, "status_code", None)
                if status_code in (404, 410):
                    # Suscripción muerta (navegador la invalidó) — se descarta.
                    db.query(PushSubscription).filter(PushSubscription.id == sub.id).delete()
                else:
                    failed += 1
            except Exception as exc:
                print(f"[ERROR] send_notification: fallo enviando a sub {sub.id}: {exc}")
                failed += 1

        notif.sent_count = sent
        notif.fail_count = failed
        notif.sent_at = datetime.utcnow()
        notif.status = "sent" if sent > 0 else "failed"
        db.commit()
    except Exception as exc:
        print(f"[ERROR] send_notification({notification_id}): {exc}")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


async def notification_scheduler():
    """Tarea de fondo (lanzada en `lifespan`): cada 30s reclama y envía las
    notificaciones programadas cuya hora ya llegó. El reclamo se hace con un
    UPDATE condicional (`WHERE status='scheduled'`) para que, si algún día
    corre más de un worker, no se envíe la misma notificación dos veces."""
    while True:
        try:
            await asyncio.sleep(30)
            claimed_ids: List[int] = []
            db = SessionLocal()
            try:
                now = datetime.utcnow()
                due = db.query(ScheduledNotification).filter(
                    ScheduledNotification.status == "scheduled",
                    ScheduledNotification.scheduled_at <= now,
                ).all()
                for n in due:
                    updated = db.query(ScheduledNotification).filter(
                        ScheduledNotification.id == n.id,
                        ScheduledNotification.status == "scheduled",
                    ).update({"status": "sending"})
                    if updated:
                        claimed_ids.append(n.id)
                db.commit()
            finally:
                db.close()

            for nid in claimed_ids:
                await asyncio.to_thread(send_notification, nid)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[ERROR] notification_scheduler: {exc}")


# ── Seed data ──────────────────────────────────────────────────────────────

_DEFAULT_SECTIONS = [
    dict(slug="restaurant", name="Restaurantes y Servicios", icon="🍽️", sort_order=1, is_active=True),
    dict(slug="tour", name="Tours y Experiencias", icon="🥾", sort_order=2, is_active=True),
    dict(slug="guide", name="Guía Turística", icon="🧭", sort_order=3, is_active=True),
]


def _create_hotel(db, h, modules, faqs, promos, posts, popup, qr_list, admins, pw, sections=None, gallery=None):
    """Helper to create a hotel with all its content in one shot."""
    hotel = Hotel(**h); db.add(hotel); db.flush()
    for q in qr_list: db.add(QRSource(hotel_id=hotel.id, **q))
    for m in modules: db.add(ContentModule(hotel_id=hotel.id, **m))
    for f in faqs: db.add(FAQItem(hotel_id=hotel.id, **f))
    for p in promos: db.add(Promo(hotel_id=hotel.id, **p))
    for p in posts: db.add(Post(hotel_id=hotel.id, **p))
    db.add(Popup(hotel_id=hotel.id, **popup))
    for s in (sections if sections is not None else _DEFAULT_SECTIONS):
        db.add(Section(hotel_id=hotel.id, **s))
    for g in (gallery or []):
        db.add(GalleryImage(hotel_id=hotel.id, **g))
    for email, name in admins:
        db.add(User(email=email, password_hash=hash_password(pw), name=name, role=UserRole.hotel_admin, hotel_id=hotel.id, is_active=True))
    db.flush()
    return hotel

def seed_data():
    db = SessionLocal()
    try:
        if db.query(Hotel).count() > 0: return
        pw = os.getenv("SEED_ADMIN_PASSWORD") or "HostelFlow2026!"
        db.add(User(email="admin@hostelflow.com", password_hash=hash_password(pw), name="Admin", role=UserRole.super_admin, is_active=True))
        db.flush()
        
        # ════════════════════════════════════════════
        # 1) CASA DEL MAR — Beachfront Luxury
        # ════════════════════════════════════════════
        _create_hotel(db, h=dict(nombre="Casa del Mar", slug="casa-del-mar", theme="boutique",
                logo_url="https://images.unsplash.com/photo-1544636331-e26879cd4d9b?w=200&h=200&fit=crop",
                cover_url="https://images.unsplash.com/photo-1571896349842-33c89424de2d?w=1200&h=600&fit=crop",
                primary_color="#0F2B5C", secondary_color="#2A5C9A", accent_color="#C9A961",
                description="Boutique hotel frente al mar con 22 suites de lujo, spa de clase mundial y restaurante con estrella.",
                whatsapp="+529991234567", email="concierge@casadelmar.com", phone="+529991234567",
                address="Blvd. Costero 456, Zona Hotelera, Cancún, QROO 77500",
                privacy_policy="Tus datos están seguros con nosotros. Solo los usamos para mejorar tu estancia.",
                default_language="es", is_active=True, font_family="Playfair Display", text_color="#1A1A2E", bg_color="#F8F4ED",
                welcome_headline="Bienvenido a Casa del Mar", welcome_subtitle="Donde el lujo se encuentra con el océano infinito.",
                onboarding_enabled=True, onboarding_title="Reserva tu experiencia", onboarding_subtitle="Cuéntanos tus preferencias para recibirte como mereces.",
                pwa_enabled=True, pwa_short_name="Casa del Mar", install_headline="Lleva el paraíso contigo", install_subtitle="Accede a todos los servicios desde tu celular.",
                header_style="classic", supported_languages="es,en"),
            modules=[
                dict(module_type="wifi", title="WiFi Premium", subtitle="Alta velocidad incluida", content_html="<p><strong>Red:</strong> CasaDelMar_Guest</p><p><strong>Contraseña:</strong> Mar2026!</p><p>WiFi de alta velocidad en todo el hotel, habitaciones y áreas comunes.</p>", icon="wifi", sort_order=1, is_active=True, audience_stage="all"),
                dict(module_type="hours", title="Horarios", subtitle="Servicios del hotel", content_html="<p><strong>Check-in:</strong> 15:00</p><p><strong>Check-out:</strong> 12:00</p><p><strong>Restaurante:</strong> 7:00-23:00</p><p><strong>Spa:</strong> 9:00-21:00</p><p><strong>Alberca:</strong> 7:00-22:00</p>", icon="clock", sort_order=2, is_active=True, audience_stage="all"),
                dict(module_type="rules", title="Código de Estancia", subtitle="Disfruta con responsabilidad", content_html="<p><strong>Horario de silencio:</strong> 23:00-08:00</p><p><strong>Áreas designadas para fumar</strong></p><p><strong>Mascotas:</strong> No permitidas</p><p><strong>Toallas de alberca:</strong> Solicitar en palapa</p>", icon="alert-circle", sort_order=3, is_active=True, audience_stage="all"),
                dict(module_type="location", title="Ubicación", subtitle="Zona Hotelera", content_html="<p><strong>Dirección:</strong> Blvr. Costero 456</p><p><strong>Desde aeropuerto:</strong> 25 min en auto</p><p><strong>Estacionamiento:</strong> Valet parking incluido</p>", icon="map-pin", sort_order=4, is_active=True, audience_stage="pre_arrival"),
                dict(module_type="services", title="Amenidades", subtitle="Todo incluido", content_html="<p><strong>Alberca infinity</strong> frente al mar</p><p><strong>Spa Mar de Cortés</strong> masajes y tratamientos</p><p><strong>Gimnasio</strong> equipado 24h</p><p><strong>Club de niños</strong> supervisado</p><p><strong>Butler</strong> servicio personalizado</p>", icon="star", sort_order=5, is_active=True, audience_stage="in_stay"),
                dict(module_type="dining", title="Restaurante Mare Nostrum", subtitle="Cocina mediterránea de autor", content_html="<p><strong>Mare Nostrum</strong> — Chef Miguel Ángel</p><p><strong>Desayuno:</strong> 7:00-11:00</p><p><strong>Comida:</strong> 13:00-17:00</p><p><strong>Cena:</strong> 19:00-23:00</p><p><strong>Bar de tapas:</strong> 18:00-01:00 en azotea</p>", icon="utensils", sort_order=6, is_active=True, audience_stage="in_stay"),
                dict(module_type="events", title="Actividades diarias", subtitle="Programa semanal", content_html="<p><strong>Lunes:</strong> Clase de coctelería 18:00</p><p><strong>Miércoles:</strong> Noche de vinos 20:00</p><p><strong>Viernes:</strong> Cena show flamenco 21:00</p><p><strong>Sábado:</strong> Yoga al amanecer 7:00</p><p><strong>Domingo:</strong> Brunch 11:00-15:00</p>", icon="calendar", sort_order=7, is_active=True, audience_stage="in_stay"),
                dict(module_type="checkout", title="Checkout", subtitle="Hasta tu salida", content_html="<p><strong>Check-out:</strong> 12:00</p><p><strong>Late checkout:</strong> Sujeto a disponibilidad (+$350 MXN)</p><p><strong>Guarda equipaje:</strong> Gratis todo el día</p><p><strong>Transporte aeropuerto:</strong> Solicitar 24h antes ($250 MXN)</p>", icon="log-out", sort_order=8, is_active=True, audience_stage="pre_checkout"),
            ],
            faqs=[
                dict(question="¿Hay transporte del aeropuerto?", answer="Sí, ofrecemos traslado ejecutivo por $250 MXN. Solicítalo 24h antes con el código de vuelo.", sort_order=1, is_active=True),
                dict(question="¿El spa requiere reservación?", answer="Recomendamos reservar con 2h de anticipación. Masajes, faciales y tratamentos de 30 a 90 min.", sort_order=2, is_active=True),
                dict(question="¿Se puede celebrar una cena especial?", answer="Sí, nuestro chef prepara cenas privadas en la terraza, en la playa o en tu suite. Consulta el menú degustación.", sort_order=3, is_active=True),
                dict(question="¿Hay estacionamiento?", answer="Valet parking incluido en tu tarifa. También tenemos estacionamiento subterráneo gratuito.", sort_order=4, is_active=True),
                dict(question="¿Puedo extender mi estancia?", answer="Sujeto a disponibilidad. Notifica a recepción antes de las 10:00 del día de check-out.", sort_order=5, is_active=True),
            ],
            promos=[
                dict(title="Cena Bajo las Estrellas", description="Menú degustación de 5 tiempos en la terraza privada con maridaje de vinos. Incluye botella de champagne.", price_text="$2,900 MXN por pareja", cta_label="Reservar ahora", cta_link="https://wa.me/529991234567?text=Quiero%20la%20Cena%20Bajo%20las%20Estrellas", is_active=True),
                dict(title="Escapada Romántica", description="2 noches en suite junior + desayuno en cama + spa duo 60min + cena en la playa.", price_text="$9,990 MXN", cta_label="Reservar paquete", cta_link="https://wa.me/529991234567?text=Quiero%20la%20Escapada%20Romántica", is_active=True),
                dict(title="Día de Spa", description="Circuito de aguas, masaje relajante 60 min, manicure y té herbal. Válido de lunes a jueves.", price_text="$1,490 MXN", cta_label="Reservar spa", cta_link="https://wa.me/529991234567?text=Quiero%20el%20Dia%20de%20Spa", is_active=True),
            ],
            posts=[
                dict(section="restaurant", title="Mare Nostrum", subtitle="Cocina mediterránea de autor", image_url="https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=600&h=400&fit=crop", content_html="<p><strong>Mare Nostrum</strong> es el restaurante insignia de Casa del Mar, liderado por el Chef Miguel Ángel.</p><p><strong>Especialidades:</strong> Paella de mariscos, Pulpo a la gallega, Lubina al horno, Risotto de langosta.</p><p><strong>Horario:</strong> 7:00-23:00</p><p><strong>Ubicación:</strong> Planta baja con terraza frente al mar</p><p><strong>Reservaciones:</strong> Recomendadas para cena</p>", button_text="Reservar mesa", button_url="https://wa.me/529991234567?text=Quiero%20reservar%20en%20Mare%20Nostrum", icon="🍽️", sort_order=1, is_active=True),
                dict(section="restaurant", title="Bar Azotea Eclipse", subtitle="Cócteles con vista al infinito", image_url="https://images.unsplash.com/photo-1470337458703-46ad1756a187?w=600&h=400&fit=crop", content_html="<p><strong>Eclipse</strong> el bar en la azotea con vista panorámica de 360°.</p><p><strong>Martes:</strong> 2x1 en margaritas</p><p><strong>Jueves:</strong> Noche de jazz 21:00</p><p><strong>Sábado:</strong> DJ set 22:00</p><p><strong>Horario:</strong> 18:00-01:00</p><p><strong>Código de vestimenta:</strong> Elegante casual</p>", button_text="Reservar mesa", button_url="https://wa.me/529991234567?text=Quiero%20reservar%20Eclipse", icon="🍸", sort_order=2, is_active=True),
                dict(section="restaurant", title="Café del Mar", subtitle="Desayunos y brunch", image_url="https://images.unsplash.com/photo-1554118811-1e0d58224f24?w=600&h=400&fit=crop", content_html="<p><strong>Café del Mar</strong> es el lugar perfecto para empezar el día.</p><p><strong>Desayuno buffet:</strong> 7:00-11:00</p><p><strong>Brunch domingo:</strong> 11:00-15:00</p><p><strong>Destacados:</strong> Huevos benedictinos, Hotcakes de coco, Jugos naturales, Café de especialidad</p>", button_text="Ver menú", button_url="https://wa.me/529991234567?text=Menú%20Café%20del%20Mar", icon="☕", sort_order=3, is_active=True),
                dict(section="tour", title="Isla Mujeres en Catamarán", subtitle="Tour de día completo", image_url="https://images.unsplash.com/photo-1540202404-a2f29016b523?w=600&h=400&fit=crop", content_html="<p><strong>Duración:</strong> 8:00-17:00</p><p><strong>Incluye:</strong> Transporte, snorkel, comida buffet, open bar, visita a Isla Mujeres</p><p><strong>$1,200 MXN por persona</strong></p><p><strong>Salida:</strong> Muelle del hotel</p>", button_text="Reservar tour", button_url="https://wa.me/529991234567?text=Quiero%20el%20tour%20a%20Isla%20Mujeres", icon="⛵", sort_order=1, is_active=True),
                dict(section="tour", title="Snorkel en Arrecife", subtitle="Arrecife de coral", image_url="https://images.unsplash.com/photo-1546026423-cc4642628d2b?w=600&h=400&fit=crop", content_html="<p><strong>Duración:</strong> 3h (9:00-12:00)</p><p><strong>Incluye:</strong> Equipo completo, guía, fotos subacuáticas, snack</p><p><strong>$750 MXN por persona</strong></p><p><strong>Nivel:</strong> Principiantes y avanzados</p>", button_text="Reservar", button_url="https://wa.me/529991234567?text=Quiero%20snorkel", icon="🤿", sort_order=2, is_active=True),
                dict(section="tour", title="Atardecer en Velero", subtitle="2 horas en el mar", image_url="https://images.unsplash.com/photo-1505228395891-9a51e7e86bf6?w=600&h=400&fit=crop", content_html="<p><strong>Horario:</strong> 17:00-19:00</p><p><strong>Incluye:</strong> Copa de champagne, botana, fotografía profesional</p><p><strong>$900 MXN por persona</strong></p><p><strong>Cupo limitado a 8 personas</strong></p>", button_text="Reservar", button_url="https://wa.me/529991234567?text=Quiero%20atardecer%20en%20velero", icon="⛵", sort_order=3, is_active=True),
                dict(section="guide", title="Zona Arqueológica Tulum", subtitle="Patrimonio de la humanidad", image_url="https://images.unsplash.com/photo-1518638150340-f4b5264a5f9e?w=600&h=400&fit=crop", content_html="<p><strong>Distancia:</strong> 1h 30min en auto</p><p><strong>Horario:</strong> 9:00-17:00</p><p><strong>Entrada:</strong> $240 MXN</p><p><strong>Transporte:</strong> Podemos gestionar tour privado ($1,200 MXN por persona incluye entrada y guía)</p>", button_text="Reservar tour", button_url="https://wa.me/529991234567?text=Quiero%20Tulum", icon="🏛️", sort_order=1, is_active=True),
                dict(section="guide", title="Quinta Avenida Playa", subtitle="Compras y vida nocturna", image_url="https://images.unsplash.com/photo-1516483638261-f4dbaf036963?w=600&h=400&fit=crop", content_html="<p><strong>Distancia:</strong> 10 min en taxi ($150 MXN)</p><p><strong>Imperdibles:</strong> Artesanías, restaurantes, bares</p><p><strong>Recomendación:</strong> Visitar después de las 17:00 para disfrutar el ambiente nocturno</p>", button_text="Cómo llegar", button_url="https://maps.google.com/?q=5ta+avenida+playa+del+carmen", icon="🛍️", sort_order=2, is_active=True),
            ],
            popup=dict(title="Bienvenido a Casa del Mar", message="Estamos encantados de recibirte. Descubre nuestras experiencias gastronómicas, spa y tours exclusivos.", button_text="Ver experiencias", button_url="#promos", trigger_type="on_load", trigger_seconds=0, is_active=True, sort_order=1),
            qr_list=[dict(name="Recepción", source_type="lobby", code="CDM-LOBBY", url_generated="/g/casa-del-mar?source=lobby", is_active=True), dict(name="Habitación Suite", source_type="room", code="CDM-ROOM", url_generated="/g/casa-del-mar?source=room", is_active=True)],
            admins=[("admin@casa-del-mar.com", "Sofia Gerente")],
            pw=pw,
            gallery=[
                dict(image_url="https://images.unsplash.com/photo-1571896349842-33c89424de2d?w=900&h=600&fit=crop", caption="Alberca infinity frente al mar", sort_order=1, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1540202404-a2f29016b523?w=900&h=600&fit=crop", caption="Vista al mar Caribe", sort_order=2, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1520250497591-112f2f40a3f4?w=900&h=600&fit=crop", caption="Playa privada del hotel", sort_order=3, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1611892440504-42a792e24d32?w=900&h=600&fit=crop", caption="Suite de lujo con terraza", sort_order=4, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1591088398332-8a7791972843?w=900&h=600&fit=crop", caption="Spa Mar de Cortés", sort_order=5, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=900&h=600&fit=crop", caption="Restaurante Mare Nostrum", sort_order=6, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1505228395891-9a51e7e86bf6?w=900&h=600&fit=crop", caption="Atardecer en velero", sort_order=7, is_active=True),
            ],
        )
        print("[SEED] 1/4 Casa del Mar")

        # ════════════════════════════════════════════
        # 2) ÁTICO CORPORATIVO — Executive City
        # ════════════════════════════════════════════
        _create_hotel(db, h=dict(nombre="Ático Corporativo", slug="atico-corporativo", theme="urban",
                logo_url="https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=200&h=200&fit=crop",
                cover_url="https://images.unsplash.com/photo-1487958449943-2429e8be8625?w=1200&h=600&fit=crop",
                description="Hotel ejecutivo en el piso 42 del corporativo más alto de la ciudad. Diseñado para el líder que exige excelencia.",
                whatsapp="+528188880001", email="recepcion@aticocorporativo.com", phone="+528188880001",
                address="Av. Vasconcelos 1500, Piso 42, San Pedro Garza García, NL 66220",
                privacy_policy="Privacidad corporativa. Tus datos protegidos bajo estándares empresariales.",
                default_language="es", is_active=True, font_family="Inter",
                welcome_headline="Bienvenido a Ático Corporativo", welcome_subtitle="El poder de los negocios, la comodidad del hogar.",
                onboarding_enabled=True, onboarding_title="Registro Ejecutivo", onboarding_subtitle="Agiliza tu llegada. Datos corporativos protegidos.",
                pwa_enabled=True, pwa_short_name="Ático Corp", install_headline="Tu oficina móvil", install_subtitle="Agenda salas, room service y traslados.",
                header_style="split", supported_languages="es"),
            modules=[
                dict(module_type="wifi", title="Fibra Óptica 1GB", subtitle="Red corporativa dedicada", content_html="<p><strong>Red:</strong> AticoCorp_Guest</p><p><strong>Contraseña:</strong> Ejecutivo2026</p><p>VPN permitida. Soporte técnico 24h marcando *800.</p>", icon="wifi", sort_order=1, is_active=True, audience_stage="all"),
                dict(module_type="hours", title="Horario Ejecutivo", subtitle="24/7", content_html="<p><strong>Business Center:</strong> 24h con café y té</p><p><strong>Room Service:</strong> 6:00-23:00</p><p><strong>Gimnasio:</strong> 5:00-23:00</p><p><strong>Sala de juntas:</strong> 7:00-22:00 (reservación)</p>", icon="clock", sort_order=2, is_active=True, audience_stage="all"),
                dict(module_type="rules", title="Políticas Corporativas", subtitle="Alto nivel", content_html="<p><strong>No fumar</strong> en pisos ejecutivos</p><p><strong>Código de vestimenta:</strong> Formal en áreas comunes</p><p><strong>Visitas:</strong> Registrarse en recepción</p><p><strong>Silencio:</strong> 22:00-07:00</p>", icon="alert-circle", sort_order=3, is_active=True, audience_stage="all"),
                dict(module_type="location", title="Ubicación", subtitle="San Pedro", content_html="<p><strong>Dirección:</strong> Av. Vasconcelos 1500, Piso 42</p><p><strong>Aeropuerto:</strong> 35 min</p><p><strong>Estacionamiento:</strong> Valet + subterráneo gratuito</p>", icon="map-pin", sort_order=4, is_active=True, audience_stage="pre_arrival"),
                dict(module_type="services", title="Servicios Ejecutivos", subtitle="Productividad total", content_html="<p><strong>Sala de juntas</strong> para 12 personas con videoconferencia</p><p><strong>Business Center</strong> impresión, escaneo, oficinas temporales</p><p><strong>Conserjería</strong> 24h</p><p><strong>Lavandería</strong> exprés 4h</p><p><strong>Traslado ejecutivo</strong> dentro de la ciudad</p>", icon="star", sort_order=5, is_active=True, audience_stage="in_stay"),
                dict(module_type="dining", title="Restaurante Ático 42", subtitle="Alta cocina con vista", content_html="<p><strong>Ático 42</strong> — Cocina fusión con vista panorámica 360°</p><p><strong>Desayuno:</strong> 6:30-10:30</p><p><strong>Comida ejecutiva:</strong> 13:00-16:00</p><p><strong>Cena:</strong> 19:00-23:00</p><p><strong>Sushi Bar:</strong> 13:00-22:00</p>", icon="utensils", sort_order=6, is_active=True, audience_stage="in_stay"),
                dict(module_type="events", title="Networking", subtitle="Eventos semanales", content_html="<p><strong>Martes:</strong> Networking cocktail 19:00</p><p><strong>Jueves:</strong> After office con jazz 18:00</p><p><strong>Talleres de liderazgo</strong> mensuales</p>", icon="calendar", sort_order=7, is_active=True, audience_stage="in_stay"),
                dict(module_type="checkout", title="Express Checkout", subtitle="Sin filas", content_html="<p><strong>Check-out:</strong> 12:00</p><p><strong>Check-out exprés:</strong> Deja llave en buzón, factura por email</p><p><strong>Late checkout:</strong> Hasta 15:00 ($400 MXN)</p>", icon="log-out", sort_order=8, is_active=True, audience_stage="pre_checkout"),
            ],
            faqs=[
                dict(question="¿Cómo facturar?", answer="Solicita en recepción o deja tu RFC al check-in y te enviamos factura electrónica.", sort_order=1, is_active=True),
                dict(question="¿Sala de juntas?", answer="3 salas ejecutivas con videoconferencia, pizarrón y catering. Reserva con 24h de anticipación.", sort_order=2, is_active=True),
                dict(question="¿Gimnasio?", answer="Abierto 5:00-23:00. Toallas, agua y fruta incluidos. Trainer disponible 7:00-11:00.", sort_order=3, is_active=True),
                dict(question="¿Traslado aeropuerto?", answer="Camioneta ejecutiva $400 MXN. Sedán $300 MXN. Solicitar 24h antes.", sort_order=4, is_active=True),
                dict(question="¿Check-in anticipado?", answer="Sujeto a disponibilidad. Garantizamos habitación desde 12:00 si llegas temprano.", sort_order=5, is_active=True),
            ],
            promos=[
                dict(title="Suite Presidencial", description="Piso 42, sala separada, jacuzzi con vista, mayordomo personal y desayuno incluido.", price_text="$4,900 MXN/noche", cta_label="Reservar suite", cta_link="https://wa.me/528188880001?text=Quiero%20la%20Suite%20Presidencial", is_active=True),
                dict(title="Paquete Corporativo", description="3 noches + sala de juntas 4h + traslado aeropuerto + desayuno buffet.", price_text="$8,500 MXN", cta_label="Reservar paquete", cta_link="https://wa.me/528188880001?text=Quiero%20Paquete%20Corporativo", is_active=True),
            ],
            posts=[
                dict(section="restaurant", title="Ático 42", subtitle="Fusión con vista 360°", image_url="https://images.unsplash.com/photo-1572802419224-296b0aeee0d9?w=600&h=400&fit=crop", content_html="<p><strong>Ático 42</strong> en el piso 42 con vista panorámica de toda la ciudad.</p><p><strong>Chef:</strong> Ricardo Sandoval (cocina fusión mexicano-japonesa)</p><p><strong>Horario:</strong> 6:30-23:00</p><p><strong>Menú ejecutivo (comida):</strong> $280 MXN</p>", button_text="Reservar", button_url="https://wa.me/528188880001?text=Reservar%20%C3%81tico%2042", icon="🥩", sort_order=1, is_active=True),
                dict(section="restaurant", title="Sushi Bar Koi", subtitle="Japonés contemporáneo", image_url="https://images.unsplash.com/photo-1579871494447-9811cf80d66c?w=600&h=400&fit=crop", content_html="<p><strong>Sushi Bar Koi</strong> dentro del hotel.</p><p><strong>Horario:</strong> 13:00-22:00</p><p><strong>Especialidades:</strong> Rollo Ático (langosta), Nigiri premium, Sashimi del día</p>", button_text="Reservar", button_url="https://wa.me/528188880001?text=Reservar%20Koi", icon="🍣", sort_order=2, is_active=True),
                dict(section="restaurant", title="Café Capital", subtitle="Coffee & grab & go", image_url="https://images.unsplash.com/photo-1501339847302-ac426a4a7cbb?w=600&h=400&fit=crop", content_html="<p><strong>Café Capital</strong> en el lobby. Café de especialidad, sándwiches, ensaladas.</p><p><strong>Horario:</strong> 6:30-20:00</p><p>Ideal para llevar a tu habitación u oficina.</p>", button_text="Ver menú", button_url="https://wa.me/528188880001?text=Menú%20Café", icon="☕", sort_order=3, is_active=True),
                dict(section="tour", title="City Tour Ejecutivo", subtitle="Centro de Monterrey", image_url="https://images.unsplash.com/photo-1514924013411-cbf25faa35bb?w=600&h=400&fit=crop", content_html="<p><strong>Duración:</strong> 3h en vehículo ejecutivo con aire</p><p><strong>Incluye:</strong> Macroplaza, Palacio de Gobierno, Barrio Antiguo, Museo MARCO</p>", button_text="Reservar", button_url="https://wa.me/528188880001?text=Quiero%20City%20Tour", icon="🏛️", sort_order=1, is_active=True),
                dict(section="tour", title="Ruta de Vinos", subtitle="Valle de Guadalupe corporativo", image_url="https://images.unsplash.com/photo-1506377247377-2a5b3b417ebb?w=600&h=400&fit=crop", content_html="<p><strong>Duración:</strong> 8h (día completo)</p><p><strong>Transporte:</strong> Camioneta ejecutiva</p><p><strong>Incluye:</strong> 3 bodegas, comida maridaje, guía sommelier</p>", button_text="Reservar", button_url="https://wa.me/528188880001?text=Quiero%20Ruta%20de%20Vinos", icon="🍷", sort_order=2, is_active=True),
                dict(section="tour", title="Golf en Campestre", subtitle="Campo privado 18 hoyos", image_url="https://images.unsplash.com/photo-1587174486073-ae5e5cff23aa?w=600&h=400&fit=crop", content_html="<p><strong>Incluye:</strong> Green fee, carrito, toalla y agua</p><p><strong>$1,500 MXN por persona</strong></p><p><strong>Transporte:</strong> 15 min del hotel</p>", button_text="Reservar", button_url="https://wa.me/528188880001?text=Quiero%20Golf", icon="🏌️", sort_order=3, is_active=True),
                dict(section="guide", title="Museo MARCO", subtitle="Arte contemporáneo", image_url="https://images.unsplash.com/photo-1566127992631-137a642a90f4?w=600&h=400&fit=crop", content_html="<p>A 10 min del hotel. Entrada $100 MXN. Domingos gratis.</p>", button_text="Ver ubicación", button_url="https://maps.google.com/?q=Museo+MARCO+Monterrey", icon="🎨", sort_order=1, is_active=True),
                dict(section="guide", title="Parque Fundidora", subtitle="Área verde y cultural", image_url="https://images.unsplash.com/photo-1519331379826-f10be5486c6f?w=600&h=400&fit=crop", content_html="<p>A 15 min en uber. Ideal para correr, pasear en bici o visitar la Cineteca.</p>", button_text="Ver más", button_url="https://maps.google.com/?q=Parque+Fundidora+Monterrey", icon="🌳", sort_order=2, is_active=True),
            ],
            popup=dict(title="Bienvenido Ejecutivo", message="Tu base de operaciones en la ciudad. Accede a sala de juntas, business center y más desde la app.", button_text="Ver servicios ejecutivos", button_url="#promos", trigger_type="on_load", trigger_seconds=0, is_active=True, sort_order=1),
            qr_list=[dict(name="Lobby Ejecutivo", source_type="lobby", code="AC-LOBBY", url_generated="/g/atico-corporativo?source=lobby", is_active=True), dict(name="Sala de Juntas", source_type="room", code="AC-JUNTAS", url_generated="/g/atico-corporativo?source=boardroom", is_active=True)],
            admins=[("admin@atico-corporativo.com", "Ricardo Director")],
            pw=pw,
            gallery=[
                dict(image_url="https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=900&h=600&fit=crop", caption="Torre corporativa", sort_order=1, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1487958449943-2429e8be8625?w=900&h=600&fit=crop", caption="Skyline desde el piso 42", sort_order=2, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1497366216548-37526070297c?w=900&h=600&fit=crop", caption="Sala de juntas ejecutiva", sort_order=3, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=900&h=600&fit=crop", caption="Business center 24h", sort_order=4, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1568084680786-a84f91d1153c?w=900&h=600&fit=crop", caption="Lobby corporativo", sort_order=5, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1572802419224-296b0aeee0d9?w=900&h=600&fit=crop", caption="Restaurante Ático 42", sort_order=6, is_active=True),
            ],
        )
        print("[SEED] 2/4 Ático Corporativo")

        # ════════════════════════════════════════════
        # 3) EL REFUGIO — Mountain Nature
        # ════════════════════════════════════════════
        _create_hotel(db, h=dict(nombre="El Refugio", slug="el-refugio", theme="zen",
                logo_url="https://images.unsplash.com/photo-1510798831971-3f5f3a5b6e8a?w=200&h=200&fit=crop",
                cover_url="https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1200&h=600&fit=crop",
                description="Cabañas sostenibles en la Sierra Madre. Donde el silencio habla y el aire sabe a pino.",
                whatsapp="+528123456001", email="hola@elrefugio.mx", phone="+528123456001",
                address="Km 32 Carretera Nacional, Santiago, NL 67300", privacy_policy="Protegemos tu privacidad y el bosque que nos rodea.",
                default_language="es", is_active=True, font_family="Inter",
                welcome_headline="Bienvenido a El Refugio", welcome_subtitle="Desconecta para reconectar contigo mismo.",
                onboarding_enabled=True, onboarding_title="Prepara tu llegada", onboarding_subtitle="Cuéntanos sobre ti y tendremos todo listo para tu escapada.",
                pwa_enabled=True, pwa_short_name="El Refugio", install_headline="Lleva el bosque contigo", install_subtitle="Senderos, fogatas y servicios en tu bolsillo.",
                header_style="classic", supported_languages="es"),
            modules=[
                dict(module_type="wifi", title="Desconexión", subtitle="WiFi disponible", content_html="<p><strong>Red:</strong> ElRefugio_Guest</p><p><strong>Contraseña:</strong> Bosque2026</p><p>El WiFi está disponible en el lobby y zona de cabañas cercanas. Te recomendamos desconectar y disfrutar del bosque.</p>", icon="wifi", sort_order=1, is_active=True, audience_stage="all"),
                dict(module_type="hours", title="Ritmo de Montaña", subtitle="Horarios", content_html="<p><strong>Recepción:</strong> 7:00-21:00</p><p><strong>Restaurante El Nido:</strong> 8:00-21:00</p><p><strong>Spa rústico:</strong> 10:00-19:00</p><p><strong>Fogata nocturna:</strong> 20:00</p>", icon="clock", sort_order=2, is_active=True, audience_stage="all"),
                dict(module_type="rules", title="Reglas del Bosque", subtitle="Conciencia ecológica", content_html="<p><strong>No dejar rastro</strong> — Lleva tu basura contigo</p><p><strong>Fogatas</strong> solo supervisadas por staff</p><p><strong>Mascotas:</strong> Bienvenidas con correa</p><p><strong>Silencio:</strong> 22:00-08:00</p>", icon="alert-circle", sort_order=3, is_active=True, audience_stage="all"),
                dict(module_type="location", title="Cómo Llegar", subtitle="Ruta escénica", content_html="<p><strong>Dirección:</strong> Km 32 Carretera Nacional, Santiago, NL</p><p><strong>Desde Monterrey:</strong> 40 min</p><p><strong>Camino:</strong> Los últimos 2 km son de terracería</p><p><strong>Auto recomendado:</strong> SUV recomendado pero no necesario</p><p><strong>Estacionamiento:</strong> Techado gratuito</p>", icon="map-pin", sort_order=4, is_active=True, audience_stage="pre_arrival"),
                dict(module_type="services", title="Experiencias Incluidas", subtitle="En tu estancia", content_html="<p><strong>Senderismo</strong> 3 rutas señalizadas</p><p><strong>Fogata nocturna</strong> con malvaviscos</p><p><strong>Yoga al amanecer</strong> en el mirador</p><p><strong>Huerto orgánico</strong> visita guiada</p><p><strong>Astroturismo</strong> telescopio disponible</p>", icon="star", sort_order=5, is_active=True, audience_stage="in_stay"),
                dict(module_type="dining", title="Restaurante El Nido", subtitle="Cocina de temporada", content_html="<p><strong>El Nido</strong> — Cocina de campo con ingredientes del huerto</p><p><strong>Desayuno:</strong> 8:00-11:00</p><p><strong>Comida:</strong> 13:00-17:00</p><p><strong>Cena:</strong> 19:00-21:00</p><p>Menú vegetariano disponible</p>", icon="utensils", sort_order=6, is_active=True, audience_stage="in_stay"),
                dict(module_type="events", title="Actividades Semanales", subtitle="Conecta con la naturaleza", content_html="<p><strong>Lunes:</strong> Taller de huerto 10:00</p><p><strong>Miércoles:</strong> Astroturismo 21:00</p><p><strong>Viernes:</strong> Fogata con cuentacuentos 20:00</p><p><strong>Sábado:</strong> Senderismo guiado 8:00</p><p><strong>Domingo:</strong> Yoga al amanecer 7:00</p>", icon="calendar", sort_order=7, is_active=True, audience_stage="in_stay"),
                dict(module_type="checkout", title="Checkout Slow", subtitle="Sin prisas", content_html="<p><strong>Check-out:</strong> 12:00</p><p><strong>Late checkout:</strong> $150 MXN (sujeto a disponibilidad)</p><p><strong>Después del check-out:</strong> Puedes quedarte en las áreas comunes y senderos hasta las 17:00</p>", icon="log-out", sort_order=8, is_active=True, audience_stage="pre_checkout"),
            ],
            faqs=[
                dict(question="¿Qué clima hace?", answer="Templado todo el año. 18-28°C de día, 8-15°C de noche. Siempre llevar suéter.", sort_order=1, is_active=True),
                dict(question="¿Puedo llevar a mi perro?", answer="Sí, tenemos cabañas pet-friendly con jardín cerrado. $250 MXN por noche. Lleva su cama y platos.", sort_order=2, is_active=True),
                dict(question="¿Hay señal celular?", answer="Hay señal en el lobby y cabañas cercanas. En cabañas del fondo puede ser limitada. Ideal para desconectar.", sort_order=3, is_active=True),
                dict(question="¿Qué llevar?", answer="Ropa cómoda para senderismo, traje de baño para el río, repelente, linterna y suéter.", sort_order=4, is_active=True),
                dict(question="¿Precios del restaurante?", answer="Desayuno incluido en tu estancia. Comida $180-280 MXN. Cena $250-350 MXN.", sort_order=5, is_active=True),
            ],
            promos=[
                dict(title="Paquete Romance del Bosque", description="Cabaña con chimenea + cena a la luz de velas (3 tiempos) + masaje para dos + desayuno en cabaña.", price_text="$4,200 MXN", cta_label="Reservar romance", cta_link="https://wa.me/528123456001?text=Quiero%20el%20Paquete%20Romance", is_active=True),
                dict(title="Aventura Completa", description="2 noches + senderismo guiado + fogata + taller de huerto + picnic en el mirador.", price_text="$5,900 MXN", cta_label="Reservar aventura", cta_link="https://wa.me/528123456001?text=Quiero%20Aventura%20Completa", is_active=True),
                dict(title="Spa Rústico", description="Masaje con piedras calientes 60min + sauna seco + té de hierbas del huerto.", price_text="$890 MXN", cta_label="Reservar spa", cta_link="https://wa.me/528123456001?text=Quiero%20Spa%20Rustico", is_active=True),
            ],
            posts=[
                dict(section="restaurant", title="El Nido", subtitle="Cocina de campo con ingredientes del huerto", image_url="https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=600&h=400&fit=crop", content_html="<p><strong>El Nido</strong> es el corazón gastronómico de El Refugio.</p><p><strong>Ingredientes:</strong> 70% de nuestro huerto orgánico</p><p><strong>Especialidades:</strong> Trucha al carbón, Mole de la casa, Queso de cabra artesanal</p><p><strong>Horario:</strong> 8:00-21:00</p><p><strong>Menú vegetariano y vegano disponible</strong></p>", button_text="Reservar mesa", button_url="https://wa.me/528123456001?text=Reservar%20El%20Nido", icon="🍲", sort_order=1, is_active=True),
                dict(section="restaurant", title="Fogata Nocturna", subtitle="Noches de leyenda", image_url="https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?w=600&h=400&fit=crop", content_html="<p><strong>Todos los viernes y sábados 20:00</strong></p><p>Malvaviscos, chocolate caliente y leyendas de la sierra narradas por Don Pancho, nuestro guardabosques.</p><p>Actividad gratuita incluida en tu estancia.</p>", button_text="Reservar lugar", button_url="https://wa.me/528123456001?text=Fogata", icon="🔥", sort_order=2, is_active=True),
                dict(section="restaurant", title="Picnic en el Mirador", subtitle="Canasta preparada", image_url="https://images.unsplash.com/photo-1504674900247-0877df9cc836?w=600&h=400&fit=crop", content_html="<p><strong>Canasta para dos:</strong> $350 MXN</p><p>Quesos artesanales, fruta de temporada, pan artesanal, vino tinto o agua fresca.</p><p>Pide tu canasta en recepción antes de las 11:00.</p>", button_text="Ordenar picnic", button_url="https://wa.me/528123456001?text=Quiero%20picnic", icon="🧺", sort_order=3, is_active=True),
                dict(section="tour", title="Sendero del Colibrí", subtitle="Ruta corta 1.5km", image_url="https://images.unsplash.com/photo-1551632811-561732d1e306?w=600&h=400&fit=crop", content_html="<p><strong>Dificultad:</strong> Fácil</p><p><strong>Duración:</strong> 45 min ida y vuelta</p><p><strong>Desnivel:</strong> 80m</p><p><strong>Recomendado:</strong> Familias y principiantes</p>", button_text="Ver ruta", button_url="https://wa.me/528123456001?text=Sendero%20Colibri", icon="🥾", sort_order=1, is_active=True),
                dict(section="tour", title="Ruta del Mirador", subtitle="6km con vista espectacular", image_url="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=600&h=400&fit=crop", content_html="<p><strong>Dificultad:</strong> Moderada</p><p><strong>Duración:</strong> 3h ida y vuelta</p><p><strong>Desnivel:</strong> 350m</p><p><strong>Salida:</strong> 8:00 desde recepción</p><p><strong>Incluye:</strong> Guía, snack, agua</p>", button_text="Reservar tour", button_url="https://wa.me/528123456001?text=Ruta%20Mirador", icon="🏔️", sort_order=2, is_active=True),
                dict(section="tour", title="Avistamiento de Aves", subtitle="Guía especializado", image_url="https://images.unsplash.com/photo-1470071459604-3b5ec3a7fe05?w=600&h=400&fit=crop", content_html="<p><strong>Domingos 7:00</strong></p><p><strong>Duración:</strong> 2.5h</p><p><strong>Incluye:</strong> Guía ornitólogo, binoculares, lista de aves</p><p><strong>Más de 60 especies</strong> registradas en el área</p>", button_text="Reservar", button_url="https://wa.me/528123456001?text=Aves", icon="🦅", sort_order=3, is_active=True),
                dict(section="guide", title="Pueblo de Santiago", subtitle="Pueblo mágico", image_url="https://images.unsplash.com/photo-1516483638261-f4dbaf036963?w=600&h=400&fit=crop", content_html="<p>A 15 min del refugio. Plaza principal, artesanías en madera, cocina regional.</p><p><strong>Imperdible:</strong> Cabalgata en la plaza los fines de semana.</p>", button_text="Cómo llegar", button_url="https://maps.google.com/?q=Santiago+NL", icon="🏘️", sort_order=1, is_active=True),
                dict(section="guide", title="Cascada Cola de Caballo", subtitle="30 min en auto", image_url="https://images.unsplash.com/photo-1505228395891-9a51e7e86bf6?w=600&h=400&fit=crop", content_html="<p><strong>Horario:</strong> 8:00-17:00</p><p><strong>Entrada:</strong> $120 MXN</p><p><strong>Recomendación:</strong> Ir temprano, caminata de 20 min desde la entrada</p>", button_text="Ver más", button_url="https://maps.google.com/?q=Cascada+Cola+de+Caballo+NL", icon="🏞️", sort_order=2, is_active=True),
            ],
            popup=dict(title="Bienvenido a El Refugio", message="Respira profundo. Estás en el lugar correcto para desconectar. Explora senderos, fogatas y más.", button_text="Ver actividades", button_url="#promos", trigger_type="on_load", trigger_seconds=0, is_active=True, sort_order=1),
            qr_list=[dict(name="Recepción", source_type="lobby", code="REF-LOBBY", url_generated="/g/el-refugio?source=lobby", is_active=True), dict(name="Cabaña", source_type="room", code="REF-CAB", url_generated="/g/el-refugio?source=cabana", is_active=True)],
            admins=[("admin@el-refugio.com", "Ana Directora")],
            pw=pw,
            gallery=[
                dict(image_url="https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=900&h=600&fit=crop", caption="Vista panorámica de la sierra", sort_order=1, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=900&h=600&fit=crop", caption="Ruta del mirador", sort_order=2, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1441974231531-c6227db76b6e?w=900&h=600&fit=crop", caption="Bosque de pinos al amanecer", sort_order=3, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1478131143081-80f7f84ca84d?w=900&h=600&fit=crop", caption="Fogata nocturna", sort_order=4, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?w=900&h=600&fit=crop", caption="Cabaña sostenible", sort_order=5, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1470071459604-3b5ec3a7fe05?w=900&h=600&fit=crop", caption="Avistamiento de aves", sort_order=6, is_active=True),
            ],
        )
        print("[SEED] 3/4 El Refugio")

        # ════════════════════════════════════════════
        # 4) ONE ACTIVE — Sports & Wellness Resort
        # ════════════════════════════════════════════
        _create_hotel(db, h=dict(nombre="One Active Resort", slug="one-active", theme="resort",
                logo_url="https://images.unsplash.com/photo-1534438327276-14e5300c3a48?w=200&h=200&fit=crop",
                cover_url="https://images.unsplash.com/photo-1571902943202-507ec2618e8f?w=1200&h=600&fit=crop",
                description="El primer resort deportivo todo incluido. Canchas profesionales, spa regenerativo y nutrición deportiva.",
                whatsapp="+528188882222", email="hola@oneactive.com", phone="+528188882222",
                address="Autopista Nacional 1500, Km 12, San Pedro Garza García, NL 66200",
                privacy_policy="Tu rendimiento nos importa. Tus datos para mejorar tu experiencia deportiva.",
                default_language="es", is_active=True, font_family="Inter",
                welcome_headline="Bienvenido a One Active", welcome_subtitle="Muévete, recupérate, repite. Tu mejor versión te espera.",
                onboarding_enabled=True, onboarding_title="Perfil Deportivo", onboarding_subtitle="Cuéntanos tu nivel y deportes favoritos para personalizar tu estancia.",
                pwa_enabled=True, pwa_short_name="One Active", install_headline="Tu club en tu bolsillo", install_subtitle="Reserva canchas, clases y spa desde la app.",
                header_style="centered", header_config=json.dumps({"show_name": True, "overlay": 0.45}),
                supported_languages="es"),
            modules=[
                dict(module_type="wifi", title="WiFi 5G", subtitle="Cobertura total", content_html="<p><strong>Red:</strong> OneActive_Guest</p><p><strong>Contraseña:</strong> Active2026</p><p>WiFi de alta velocidad en todo el resort. Streaming sin cortes.</p>", icon="wifi", sort_order=1, is_active=True, audience_stage="all"),
                dict(module_type="hours", title="Horario Deportivo", subtitle="Instalaciones", content_html="<p><strong>Canchas:</strong> 6:00-22:00</p><p><strong>Gimnasio:</strong> 5:00-23:00</p><p><strong>Alberca olímpica:</strong> 6:00-21:00</p><p><strong>Spa:</strong> 8:00-21:00</p><p><strong>Restaurante:</strong> 6:30-22:00</p>", icon="clock", sort_order=2, is_active=True, audience_stage="all"),
                dict(module_type="rules", title="Código Activo", subtitle="Reglas del club", content_html="<p><strong>Vestimenta:</strong> Blanca en tenis, adecuada en gimnasio</p><p><strong>Reservaciones:</strong> Canchas con 24h de anticipación</p><p><strong>Toallas:</strong> Disponibles en cada área</p><p><strong>Hidratación:</strong> Estaciones de agua gratuitas</p>", icon="alert-circle", sort_order=3, is_active=True, audience_stage="all"),
                dict(module_type="location", title="Ubicación", subtitle="San Pedro", content_html="<p><strong>Dirección:</strong> Autopista Nacional 1500, Km 12</p><p><strong>Desde Monterrey:</strong> 20 min</p><p><strong>Aeropuerto:</strong> 40 min</p><p><strong>Estacionamiento:</strong> Valet + gratuito</p>", icon="map-pin", sort_order=4, is_active=True, audience_stage="pre_arrival"),
                dict(module_type="services", title="Instalaciones", subtitle="Todo incluido", content_html="<p><strong>6 canchas de tenis</strong> (arcilla y dura)</p><p><strong>4 canchas de pádel</strong> cubiertas</p><p><strong>Alberca olímpica</strong> 25m x 50m</p><p><strong>Gimnasio 600m²</strong> con cardio, peso libre y funcional</p><p><strong>Cancha de squash</strong> y frontón</p><p><strong>Pista de atletismo</strong> 200m</p><p><strong>Spa regenerativo</strong> 2000m²</p>", icon="star", sort_order=5, is_active=True, audience_stage="in_stay"),
                dict(module_type="dining", title="Zona de Nutrición", subtitle="Come para rendir", content_html="<p><strong>The Protein House:</strong> Altas proteínas, baja grasa</p><p><strong>Smoothie Bar Active:</strong> Licuados funcionales y bowls</p><p><strong>Poolside Grill:</strong> Snacks saludables junto a la alberca</p><p><strong>Bar Recuperación:</strong> Jugos detox y tés</p>", icon="utensils", sort_order=6, is_active=True, audience_stage="in_stay"),
                dict(module_type="events", title="Agenda Deportiva", subtitle="Clases y torneos", content_html="<p><strong>Clases grupales:</strong> Yoga 7am, CrossFit 8am, Spinning 9am</p><p><strong>Torneo de tenis:</strong> Último sábado del mes</p><p><strong>Clinics:</strong> Con entrenadores certificados</p><p><strong>Retos semanales:</strong> 5km run, 1000 cal swim</p>", icon="calendar", sort_order=7, is_active=True, audience_stage="in_stay"),
                dict(module_type="checkout", title="Recuperación Activa", subtitle="Hasta el último momento", content_html="<p><strong>Check-out:</strong> 12:00</p><p><strong>Después del check-out:</strong> Acceso a instalaciones hasta 18:00</p><p><strong>Regaderas y lockers:</strong> Disponibles todo el día de tu salida</p>", icon="log-out", sort_order=8, is_active=True, audience_stage="pre_checkout"),
            ],
            faqs=[
                dict(question="¿Necesito llevar mi propio equipo?", answer="Rentamos raquetas ($100), palas de pádel ($80), balones y toallas. Trae tu ropa deportiva.", sort_order=1, is_active=True),
                dict(question="¿Hay entrenadores personales?", answer="Sí, contamos con 5 entrenadores certificados. Sesión individual $400/h, pareja $600/h.", sort_order=2, is_active=True),
                dict(question="¿Clases grupales?", answer="Incluidas en tu estancia. Yoga, CrossFit, Spinning, Natación, Pilates. Consulta horarios en la app.", sort_order=3, is_active=True),
                dict(question="¿El spa está incluido?", answer="Acceso a sauna, vapor y jacuzzi incluido. Masajes y tratamientos tienen costo adicional.", sort_order=4, is_active=True),
                dict(question="¿Puedo invitar a alguien del exterior?", answer="Pase de día: $500 MXN por persona. Incluye acceso a todas las instalaciones deportivas.", sort_order=5, is_active=True),
            ],
            promos=[
                dict(title="Pase de Día Activo", description="Acceso completo a instalaciones: canchas, gimnasio, alberca, clases grupales y sauna.", price_text="$500 MXN", cta_label="Reservar pase", cta_link="https://wa.me/528188882222?text=Quiero%20Pase%20de%20Dia", is_active=True),
                dict(title="Reto 30 Días", description="Habitación + plan de entrenamiento personalizado + evaluación física + nutrición + acceso ilimitado a clases.", price_text="$18,900 MXN/mes", cta_label="Inscribirme", cta_link="https://wa.me/528188882222?text=Quiero%20el%20Reto%2030%20Dias", is_active=True),
                dict(title="Spa Regenerativo", description="Masaje descontracturante 60min + crioterapia 10min + sauna + smoothie funcional.", price_text="$1,690 MXN", cta_label="Reservar spa", cta_link="https://wa.me/528188882222?text=Quiero%20Spa%20Regenerativo", is_active=True),
            ],
            posts=[
                dict(section="restaurant", title="The Protein House", subtitle="Alta proteína, bajo cheat", image_url="https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=600&h=400&fit=crop", content_html="<p><strong>The Protein House</strong> es el restaurante principal de One Active.</p><p><strong>Menú diseñado por nutriólogos deportivos</strong></p><p><strong>Horario:</strong> 6:30-22:00</p><p><strong>Especialidades:</strong> Bowl de quinoa con salmón, Pechuga rellena, Smoothie de proteína, Burrito fitness</p>", button_text="Ver menú", button_url="https://wa.me/528188882222?text=Menú%20Protein%20House", icon="🥩", sort_order=1, is_active=True),
                dict(section="restaurant", title="Smoothie Bar Active", subtitle="Nutrición líquida", image_url="https://images.unsplash.com/photo-1505252585461-04db1eb84625?w=600&h=400&fit=crop", content_html="<p><strong>Smoothie Bar Active</strong> — Licuados funcionales post-entreno.</p><p><strong>Horario:</strong> 6:00-20:00</p><p><strong>Destacados:</strong> Prote Warrior (proteína + banana), Green Detox, Berry Blast</p><p><strong>+Bowls</strong> de açaí, granola y fruta</p>", button_text="Ver menú", button_url="https://wa.me/528188882222?text=Menú%20Smoothie%20Bar", icon="🥤", sort_order=2, is_active=True),
                dict(section="restaurant", title="Poolside Grill", subtitle="Snacks junto a la alberca", image_url="https://images.unsplash.com/photo-1524666643752-b381eb00effb?w=600&h=400&fit=crop", content_html="<p><strong>Poolside Grill</strong> — Comida ligera y bebidas.</p><p><strong>Horario:</strong> 10:00-19:00</p><p><strong>Opciones:</strong> Tacos de pescado, Ceviche, Wrap de pollo, Hamburguesa proteica, Aguas frescas</p>", button_text="Reservar", button_url="https://wa.me/528188882222?text=Poolside", icon="🍹", sort_order=3, is_active=True),
                dict(section="tour", title="Canchas de Tenis", subtitle="6 profesionales", image_url="https://images.unsplash.com/photo-1622279457486-62dbc1250985?w=600&h=400&fit=crop", content_html="<p><strong>Superficie:</strong> 3 arcilla, 3 dura</p><p><strong>Horario:</strong> 6:00-22:00</p><p><strong>Iluminación:</strong> Todas las canchas con luz nocturna</p><p><strong>Profesionales:</strong> Clases con entrenador certificado</p>", button_text="Reservar cancha", button_url="https://wa.me/528188882222?text=Reservar%20tenis", icon="🎾", sort_order=1, is_active=True),
                dict(section="tour", title="Pádel Cubierto", subtitle="4 canchas", image_url="https://images.unsplash.com/photo-1554068865-2ce524bd1d24?w=600&h=400&fit=crop", content_html="<p><strong>Pádel</strong> en canchas cubiertas con clima controlado.</p><p><strong>Horario:</strong> 7:00-23:00</p><p><strong>Renta de palas:</strong> $80 MXN</p><p><strong>Torneo mensual</strong> con premios</p>", button_text="Reservar", button_url="https://wa.me/528188882222?text=Padel", icon="🏓", sort_order=2, is_active=True),
                dict(section="tour", title="CrossFit Active Box", subtitle="Box funcional", image_url="https://images.unsplash.com/photo-1534258936925-c58bed479fcb?w=600&h=400&fit=crop", content_html="<p><strong>Box funcional</strong> al aire libre y cubierto.</p><p><strong>Clases:</strong> Lunes a Sábado 7:00, 8:00, 9:00, 17:00, 18:00</p><p><strong>WODs</strong> diseñados para todos los niveles</p>", button_text="Ver horarios", button_url="https://wa.me/528188882222?text=CrossFit", icon="🏋️", sort_order=3, is_active=True),
                dict(section="guide", title="Spa Regenerativo", subtitle="Recupérate como un atleta", image_url="https://images.unsplash.com/photo-1544161515-4ab6ce6db874?w=600&h=400&fit=crop", content_html="<p><strong>2000m² de bienestar</strong></p><p><strong>Incluido:</strong> Sauna seco, baño de vapor, jacuzzi, regaderas de contraste</p><p><strong>Servicios:</strong> Masaje deportivo, crioterapia, compresión, flotación</p>", button_text="Reservar spa", button_url="https://wa.me/528188882222?text=Reservar%20spa", icon="🧖", sort_order=1, is_active=True),
                dict(section="guide", title="Alberca Olímpica", subtitle="25m x 50m", image_url="https://images.unsplash.com/photo-1576610616656-d3aa5d1f4534?w=600&h=400&fit=crop", content_html="<p><strong>Carriles designados:</strong> 8 carriles</p><p><strong>Clases:</strong> Natación para adultos, Aqua fitness, Polo acuático</p><p><strong>Horario:</strong> 6:00-21:00</p>", button_text="Ver horarios", button_url="https://wa.me/528188882222?text=Alberca", icon="🏊", sort_order=2, is_active=True),
            ],
            popup=dict(title="¡A Moverse!", message="Bienvenido a One Active. Revisa la agenda de clases, reserva canchas y conoce el spa.", button_text="Ver actividades", button_url="#promos", trigger_type="on_load", trigger_seconds=0, is_active=True, sort_order=1),
            qr_list=[dict(name="Recepción", source_type="lobby", code="OA-LOBBY", url_generated="/g/one-active?source=lobby", is_active=True), dict(name="Vestidores", source_type="room", code="OA-VEST", url_generated="/g/one-active?source=locker", is_active=True)],
            admins=[("admin@one-active.com", "Entrenador Jefe")],
            pw=pw,
            gallery=[
                dict(image_url="https://images.unsplash.com/photo-1571902943202-507ec2618e8f?w=900&h=600&fit=crop", caption="Instalaciones deportivas", sort_order=1, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1622279457486-62dbc1250985?w=900&h=600&fit=crop", caption="Canchas de tenis profesionales", sort_order=2, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1576610616656-d3aa5d1f4534?w=900&h=600&fit=crop", caption="Alberca olímpica", sort_order=3, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1534438327276-14e5300c3a48?w=900&h=600&fit=crop", caption="Gimnasio funcional", sort_order=4, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1554068865-2ce524bd1d24?w=900&h=600&fit=crop", caption="Pádel cubierto", sort_order=5, is_active=True),
                dict(image_url="https://images.unsplash.com/photo-1544161515-4ab6ce6db874?w=900&h=600&fit=crop", caption="Spa regenerativo", sort_order=6, is_active=True),
            ],
        )
        print("[SEED] 4/4 One Active")

        # ════════════════════════════════════════════
        # 5) Usuarios de permisos multi-hotel + hotel demo con trial vencido (P5)
        # ════════════════════════════════════════════
        casa_del_mar = db.query(Hotel).filter(Hotel.slug == "casa-del-mar").first()
        atico = db.query(Hotel).filter(Hotel.slug == "atico-corporativo").first()

        # Editor: solo puede gestionar contenido de Casa del Mar (sin acceso a
        # hotel/usuarios/notificaciones/QR de escritura — ver require_manager).
        editor_user = User(
            email="editor@casadelmar.com", password_hash=hash_password(pw),
            name="Editor Casa del Mar", role=UserRole.hotel_admin,
            hotel_id=casa_del_mar.id, is_active=True,
        )
        db.add(editor_user); db.flush()
        db.add(UserHotel(user_id=editor_user.id, hotel_id=casa_del_mar.id, role="editor"))

        # Multi-hotel: admin en Casa del Mar, editor en Ático Corporativo.
        gerente_user = User(
            email="gerente@hostelflow.com", password_hash=hash_password(pw),
            name="Gerente Multi-Hotel", role=UserRole.hotel_admin,
            hotel_id=casa_del_mar.id, is_active=True,
        )
        db.add(gerente_user); db.flush()
        db.add(UserHotel(user_id=gerente_user.id, hotel_id=casa_del_mar.id, role="admin"))
        db.add(UserHotel(user_id=gerente_user.id, hotel_id=atico.id, role="editor"))

        # Hotel con trial vencido (ayer) para probar el bloqueo de escrituras
        # y el aviso trial_expired en la guía de huésped.
        hotel_vencida = Hotel(
            nombre="Hotel Prueba Vencida", slug="hotel-prueba-vencida", theme="boutique",
            is_active=True, plan="trial", trial_ends_at=datetime.utcnow() - timedelta(days=1),
            default_language="es",
        )
        db.add(hotel_vencida); db.flush()
        db.add(ContentModule(
            hotel_id=hotel_vencida.id, module_type="wifi", title="WiFi",
            content_html="<p><strong>Red:</strong> Vencida_Guest</p>",
            icon="wifi", sort_order=1, is_active=True, audience_stage="all",
        ))
        db.add(ContentModule(
            hotel_id=hotel_vencida.id, module_type="hours", title="Horarios",
            content_html="<p><strong>Check-in:</strong> 15:00</p>",
            icon="clock", sort_order=2, is_active=True, audience_stage="all",
        ))
        for s in _DEFAULT_SECTIONS:
            db.add(Section(hotel_id=hotel_vencida.id, **s))
        vencida_admin = User(
            email="admin@hotel-prueba-vencida.com", password_hash=hash_password(pw),
            name="Admin Hotel Vencido", role=UserRole.hotel_admin,
            hotel_id=hotel_vencida.id, is_active=True,
        )
        db.add(vencida_admin); db.flush()
        db.add(UserHotel(user_id=vencida_admin.id, hotel_id=hotel_vencida.id, role="admin"))
        print("[SEED] 5/5 Usuarios permisos multi-hotel + Hotel Prueba Vencida")

        db.commit()
        print("Seed data created successfully")
    except Exception as e:
        db.rollback()
        print(f"Seed error: {e}")
        import traceback; traceback.print_exc()
    finally:
        db.close()


@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request, req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token = create_access_token({"sub": str(user.id)})
    return {
        "access_token": token,
        "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600,  # segundos (P1-3)
        "user": {
            "id": user.id, "email": user.email, "name": user.name,
            "role": user.role, "hotel_id": user.hotel_id,
        },
        "hotels": _user_hotels_list(db, user),  # P5: hoteles/roles del usuario
    }


@app.get("/api/auth/me")
def get_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {
        "id": user.id, "email": user.email, "name": user.name,
        "role": user.role, "hotel_id": user.hotel_id,
        "hotels": _user_hotels_list(db, user),  # P5
    }


@app.post("/api/signup")
@limiter.limit("3/minute")
def signup(request: Request, req: SignupRequest, db: Session = Depends(get_db)):
    """Registro público (P5, objetivo 2): crea un hotel en trial de 14 días
    + su hotel_admin, y devuelve el mismo contrato que login para auto-login."""
    email = req.email.strip().lower()
    if db.query(User).filter(func.lower(User.email) == email).first():
        raise HTTPException(status_code=409, detail="El email ya está registrado")

    base_slug = _slugify(req.hotel_name)
    slug = base_slug
    counter = 1
    while db.query(Hotel).filter(Hotel.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    hotel = Hotel(
        nombre=req.hotel_name, slug=slug, theme="boutique", is_active=True,
        plan="trial", trial_ends_at=datetime.utcnow() + timedelta(days=14),
        default_language="es",
    )
    db.add(hotel)
    db.flush()
    for s in _DEFAULT_SECTIONS:
        db.add(Section(hotel_id=hotel.id, **s))

    user = User(
        email=email, password_hash=hash_password(req.password), name=req.name,
        role=UserRole.hotel_admin, hotel_id=hotel.id, is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(UserHotel(user_id=user.id, hotel_id=hotel.id, role="admin"))
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": str(user.id)})
    return {
        "access_token": token,
        "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        "user": {
            "id": user.id, "email": user.email, "name": user.name,
            "role": user.role, "hotel_id": user.hotel_id,
        },
        "hotels": _user_hotels_list(db, user),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC GUEST ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/guest/{slug}")
def get_guest_app(slug: str, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    trial_vencido = hotel.plan == "trial" and hotel.trial_ends_at and hotel.trial_ends_at < datetime.utcnow()
    if hotel.plan == "suspended" or trial_vencido:
        return {
            "trial_expired": True,
            "hotel": {
                "nombre": hotel.nombre, "slug": hotel.slug,
                "logo_url": hotel.logo_url, "primary_color": hotel.primary_color,
            },
        }
    modules = db.query(ContentModule).filter(
        ContentModule.hotel_id == hotel.id, ContentModule.is_active == True
    ).order_by(ContentModule.sort_order).all()
    faqs = db.query(FAQItem).filter(
        FAQItem.hotel_id == hotel.id, FAQItem.is_active == True
    ).order_by(FAQItem.sort_order).all()
    promos = db.query(Promo).filter(
        Promo.hotel_id == hotel.id, Promo.is_active == True
    ).order_by(Promo.created_at.desc()).all()
    posts = db.query(Post).filter(
        Post.hotel_id == hotel.id, Post.is_active == True
    ).order_by(Post.sort_order).all()
    popups = db.query(Popup).filter(
        Popup.hotel_id == hotel.id, Popup.is_active == True
    ).order_by(Popup.sort_order).all()
    sections = db.query(Section).filter(
        Section.hotel_id == hotel.id, Section.is_active == True
    ).order_by(Section.sort_order).all()
    gallery = db.query(GalleryImage).filter(
        GalleryImage.hotel_id == hotel.id, GalleryImage.is_active == True
    ).order_by(GalleryImage.sort_order).all()
    # Resolver theme CSS
    theme_css_url = None
    if hotel.theme_id:
        theme = db.query(Theme).filter(Theme.id == hotel.theme_id, Theme.is_active == True).first()
        if theme and theme.css_content:
            theme_css_url = f"/api/theme/{hotel.theme_id}/css"
    return {
        "hotel": hotel_to_dict(hotel),
        "modules": [module_to_dict(m) for m in modules],
        "faqs": [faq_to_dict(f) for f in faqs],
        "promos": [promo_to_dict(p) for p in promos],
        "posts": [post_to_dict(p) for p in posts],
        "popups": [popup_to_dict(p) for p in popups],
        "sections": [section_to_dict(s) for s in sections],
        "gallery": [gallery_to_dict(g) for g in gallery],
        "theme_css_url": theme_css_url,
    }


@app.post("/api/guest/{slug}/onboarding")
@limiter.limit("30/minute")
def guest_onboarding(request: Request, slug: str, req: OnboardingRequest, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    # Fechas ya validadas por pydantic (P1-8): formato inválido → 422 automático
    lead = GuestLead(
        hotel_id=hotel.id, name=req.name, whatsapp=req.whatsapp, email=req.email,
        check_in_date=req.check_in_date, check_out_date=req.check_out_date,
        language=req.language, consent_contact=req.consent_contact,
        source_qr=req.source_qr, first_seen_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow(),
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return {"id": lead.id, "name": lead.name, "message": "Bienvenido/a, " + lead.name}


def _record_guest_event(db: Session, hotel: Hotel, event_type: str,
                        guest_lead_id: Optional[int], page_view: Optional[str],
                        source_qr: Optional[str], request: Request) -> dict:
    """Validación común de eventos de tracking (P1-4 / SEC A4)."""
    if event_type not in ALLOWED_EVENT_TYPES:
        raise HTTPException(status_code=422, detail="Tipo de evento no válido")
    # Un guest_lead_id de otro hotel se guarda como null (no se confía en el cliente)
    lead_id = None
    if guest_lead_id:
        lead = db.query(GuestLead).filter(
            GuestLead.id == guest_lead_id, GuestLead.hotel_id == hotel.id
        ).first()
        if lead:
            lead_id = lead.id
    user_agent = (request.headers.get("User-Agent") or "")[:300]
    log = AccessLog(
        hotel_id=hotel.id, guest_lead_id=lead_id,
        event_type=event_type, page_view=page_view,
        source_qr=source_qr, user_agent=user_agent,
        created_at=datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    return {"ok": True}


@app.post("/api/guest/{slug}/events")
@limiter.limit("30/minute")
def log_guest_event(request: Request, slug: str, req: GuestEventRequest, db: Session = Depends(get_db)):
    """Registra un evento de tracking derivando el hotel del slug (P1-4)."""
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    return _record_guest_event(db, hotel, req.event_type, req.guest_lead_id,
                               req.page_view, req.source_qr, request)


@app.post("/api/guest/events", deprecated=True)
@limiter.limit("30/minute")
def log_event(request: Request, req: EventRequest, db: Session = Depends(get_db)):
    """DEPRECATED: usar POST /api/guest/{slug}/events. Se mantiene para clientes
    cacheados; aplica la misma validación derivando el hotel de hotel_id."""
    hotel = db.query(Hotel).filter(Hotel.id == req.hotel_id, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    return _record_guest_event(db, hotel, req.event_type, req.guest_lead_id,
                               req.page_view, req.source_qr, request)


@app.post("/api/guest/{slug}/install-event")
@limiter.limit("30/minute")
def install_event(slug: str, req: InstallEventRequest, request: Request, db: Session = Depends(get_db)):
    """Registra un evento de instalación PWA. Deriva hotel_id del slug (§6)."""
    if req.event not in ALLOWED_INSTALL_EVENTS:
        raise HTTPException(status_code=400, detail="Evento de instalación no válido")
    hotel = db.query(Hotel).filter(Hotel.slug == slug).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")

    # Actualiza flags en el GuestLead si viene identificado
    if req.guest_lead_id:
        lead = db.query(GuestLead).filter(
            GuestLead.id == req.guest_lead_id, GuestLead.hotel_id == hotel.id
        ).first()
        if lead:
            if req.event == "prompt_shown":
                lead.install_prompt_shown = True
            elif req.event == "installed":
                lead.installed_flag = True
                lead.install_prompt_shown = True
            lead.last_seen_at = datetime.utcnow()

    # Deja traza en AccessLog
    log = AccessLog(
        hotel_id=hotel.id, guest_lead_id=req.guest_lead_id,
        event_type=f"install_{req.event}",
        user_agent=request.headers.get("User-Agent"),
        created_at=datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
#  PUSH NOTIFICATIONS — Público (huésped)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/guest/{slug}/push/public-key")
@limiter.limit("10/minute")
def get_push_public_key(request: Request, slug: str, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    return {"public_key": VAPID_PUBLIC_KEY}


@app.post("/api/guest/{slug}/push/subscribe")
@limiter.limit("10/minute")
def push_subscribe(request: Request, slug: str, req: PushSubscribeRequest, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")

    lead_id = None
    if req.guest_lead_id:
        lead = db.query(GuestLead).filter(
            GuestLead.id == req.guest_lead_id, GuestLead.hotel_id == hotel.id
        ).first()
        if lead:
            lead_id = lead.id

    sub = db.query(PushSubscription).filter(PushSubscription.endpoint == req.endpoint).first()
    if sub:
        sub.hotel_id = hotel.id
        sub.p256dh = req.keys.p256dh
        sub.auth = req.keys.auth
        sub.guest_lead_id = lead_id
        sub.lang = req.lang or "es"
    else:
        sub = PushSubscription(
            hotel_id=hotel.id, endpoint=req.endpoint,
            p256dh=req.keys.p256dh, auth=req.keys.auth,
            guest_lead_id=lead_id, lang=req.lang or "es",
        )
        db.add(sub)
    db.commit()
    return {"ok": True}


@app.post("/api/guest/{slug}/push/unsubscribe")
@limiter.limit("10/minute")
def push_unsubscribe(request: Request, slug: str, req: PushUnsubscribeRequest, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    db.query(PushSubscription).filter(
        PushSubscription.endpoint == req.endpoint, PushSubscription.hotel_id == hotel.id
    ).delete()
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════

# Tipos de fuente de QR permitidos (endurecimiento §7)
ALLOWED_QR_SOURCE_TYPES = {"lobby", "room", "pre_arrival", "website", "custom"}

# Eventos de instalación PWA permitidos (§6)
ALLOWED_INSTALL_EVENTS = {"prompt_shown", "accepted", "dismissed", "installed"}


# ── Permisos multi-hotel (P5) ───────────────────────────────────────────────

_WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _allowed_hotels(db: Session, user: User) -> Optional[dict]:
    """Hoteles a los que `user` tiene acceso y su rol en cada uno.

    - super_admin → None (acceso a todos, rol implícito "admin" en cualquiera).
    - Resto → {hotel_id: role} desde `user_hotels`; si `user.hotel_id` (hotel
      principal legacy) no está en la tabla, se añade con rol "admin" para
      mantener compatibilidad con usuarios creados antes de este modelo.
    """
    if user.role == UserRole.super_admin:
        return None
    rows = db.query(UserHotel).filter(UserHotel.user_id == user.id).all()
    allowed = {r.hotel_id: r.role for r in rows}
    if user.hotel_id and user.hotel_id not in allowed:
        allowed[user.hotel_id] = "admin"
    return allowed


def _role_in_hotel(db: Session, user: User, hid: int) -> str:
    """Rol efectivo de `user` en el hotel `hid`: "super" | "admin" | "editor"."""
    if user.role == UserRole.super_admin:
        return "super"
    allowed = _allowed_hotels(db, user) or {}
    return allowed.get(hid, "editor")


# Prefijos de path exentos del bloqueo de trial/suspensión (P6): un hotel con
# el trial vencido o suspendido tiene que poder seguir pagando — si no, queda
# atrapado sin forma de reactivarse por sí mismo.
_TRIAL_ENFORCEMENT_EXEMPT_PREFIXES = ("/api/admin/billing/",)


def _enforce_trial_write(db: Session, hid: int, request: Request) -> None:
    """403 en escrituras (POST/PUT/DELETE/PATCH) si el hotel resuelto está en
    trial vencido o suspendido (P5, objetivo 2). Las lecturas (GET) nunca se
    bloquean para que el panel siga mostrando el aviso. Excepción (P6): las
    rutas de facturación (`/api/admin/billing/*`) nunca se bloquean, para que
    un hotel vencido/suspendido pueda pagar y reactivarse."""
    if request.method not in _WRITE_METHODS:
        return
    if request.url.path.startswith(_TRIAL_ENFORCEMENT_EXEMPT_PREFIXES):
        return
    hotel = db.query(Hotel).filter(Hotel.id == hid).first()
    if not hotel:
        return
    trial_vencido = hotel.plan == "trial" and hotel.trial_ends_at and hotel.trial_ends_at < datetime.utcnow()
    if hotel.plan == "suspended" or trial_vencido:
        raise HTTPException(
            status_code=403,
            detail="El período de prueba ha terminado. Contacta a HostelFlow para activar tu plan.",
        )


def _default_hotel_for_user(user: User, allowed: Optional[dict]) -> Optional[int]:
    """Hotel activo por defecto cuando no se manda X-Hotel-Id: el hotel
    principal legacy si sigue entre los permitidos, si no el primero asignado."""
    if not allowed:
        return user.hotel_id
    if user.hotel_id and user.hotel_id in allowed:
        return user.hotel_id
    return next(iter(allowed), None)


def _resolve_hotel_id(user: User, request: Request) -> int:
    """
    Resuelve el hotel activo para el usuario autenticado (contrato §1, P5).

    - super_admin: usa el header ``X-Hotel-Id`` (o query ``?hotel_id=``) si el
      hotel existe; en su defecto, el primer hotel activo por id. Nunca hardcodea 1.
    - Resto de usuarios: si mandan X-Hotel-Id/?hotel_id y ese hotel está entre
      sus permitidos (`_allowed_hotels`) → lo usa; si mandan uno NO permitido
      → 403; sin header → su hotel principal o el primero asignado; sin
      ninguno asignado → 403.

    El resultado se cachea en `request.state` (mismo hotel durante toda la
    request) para no repetir la resolución cuando varias dependencias/rutas
    la invocan sobre el mismo request.
    """
    cached = getattr(request.state, "_hf_hotel_id", None)
    if cached is not None:
        return cached

    db = SessionLocal()
    try:
        raw = request.headers.get("X-Hotel-Id") or request.query_params.get("hotel_id")
        requested_id = None
        if raw:
            try:
                requested_id = int(raw)
            except (ValueError, TypeError):
                requested_id = None

        if user.role == UserRole.super_admin:
            hid = None
            if requested_id is not None:
                hotel = db.query(Hotel).filter(Hotel.id == requested_id).first()
                if hotel:
                    hid = hotel.id
            if hid is None:
                first = db.query(Hotel).filter(Hotel.is_active == True).order_by(Hotel.id).first()
                if not first:
                    raise HTTPException(status_code=404, detail="No hay hoteles disponibles")
                hid = first.id
        else:
            allowed = _allowed_hotels(db, user) or {}
            if requested_id is not None:
                if requested_id in allowed:
                    hid = requested_id
                else:
                    raise HTTPException(status_code=403, detail="No tienes acceso a este hotel")
            else:
                hid = _default_hotel_for_user(user, allowed)
            if hid is None:
                raise HTTPException(status_code=403, detail="Tu usuario no tiene un hotel asignado")

        _enforce_trial_write(db, hid, request)
        request.state._hf_hotel_id = hid
        return hid
    finally:
        db.close()


def require_manager(request: Request, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)) -> User:
    """Dependencia reutilizable (P5): exige rol base admin (super_admin o
    hotel_admin) Y que el rol efectivo en el hotel activo NO sea "editor".
    Úsala en vez de `require_role(super_admin, hotel_admin)` en endpoints
    reservados a administradores (gestión de usuarios, hotel, notificaciones,
    creación/borrado de QR)."""
    if user.role not in (UserRole.super_admin, UserRole.hotel_admin):
        raise HTTPException(status_code=403, detail="Sin permisos")
    hid = _resolve_hotel_id(user, request)
    if _role_in_hotel(db, user, hid) == "editor":
        raise HTTPException(status_code=403, detail="No tienes permisos para esta acción")
    return user


def _user_hotels_list(db: Session, user: User) -> list:
    """Hoteles visibles para `user` con su rol en cada uno (P5), usado en
    GET /api/auth/me y en las respuestas de login/signup."""
    if user.role == UserRole.super_admin:
        hotels = db.query(Hotel).order_by(Hotel.nombre).all()
        return [{"id": h.id, "nombre": h.nombre, "slug": h.slug, "role": "admin"} for h in hotels]
    allowed = _allowed_hotels(db, user) or {}
    if not allowed:
        return []
    hotels = db.query(Hotel).filter(Hotel.id.in_(allowed.keys())).all()
    return [{"id": h.id, "nombre": h.nombre, "slug": h.slug, "role": allowed[h.id]} for h in hotels]


def _leads_by_date(db: Session, hid: int) -> list[dict]:
    """Leads de los últimos 30 días agrupados por fecha (P3 dashboard/analytics)."""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    rows = db.query(
        func.date(GuestLead.created_at).label("date"),
        func.count(GuestLead.id).label("count")
    ).filter(GuestLead.hotel_id == hid, GuestLead.created_at >= thirty_days_ago).group_by(func.date(GuestLead.created_at)).all()
    return [{"date": str(r.date), "count": r.count} for r in rows]


def _top_modules(db: Session, hid: int) -> list[dict]:
    """Top 5 módulos más abiertos (eventos module_open; page_view lleva el título)."""
    rows = db.query(
        AccessLog.page_view, func.count(AccessLog.id)
    ).filter(AccessLog.hotel_id == hid, AccessLog.event_type == "module_open",
             AccessLog.page_view.isnot(None)).group_by(AccessLog.page_view).order_by(func.count(AccessLog.id).desc()).limit(5).all()
    return [{"module": r[0], "views": r[1]} for r in rows]


def _visits_by_date(db: Session, hid: int) -> list[dict]:
    """Page views de los últimos 30 días agrupados por fecha (P3 dashboard)."""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    rows = db.query(
        func.date(AccessLog.created_at).label("date"),
        func.count(AccessLog.id).label("count")
    ).filter(
        AccessLog.hotel_id == hid, AccessLog.event_type == "page_view",
        AccessLog.created_at >= thirty_days_ago,
    ).group_by(func.date(AccessLog.created_at)).all()
    return [{"date": str(r.date), "count": r.count} for r in rows]


@app.get("/api/admin/dashboard")
def admin_dashboard(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    week_ago = datetime.utcnow() - timedelta(days=7)
    total_leads = db.query(func.count(GuestLead.id)).filter(GuestLead.hotel_id == hid).scalar()
    leads_this_week = db.query(func.count(GuestLead.id)).filter(
        GuestLead.hotel_id == hid, GuestLead.created_at >= week_ago
    ).scalar()
    total_modules = db.query(func.count(ContentModule.id)).filter(ContentModule.hotel_id == hid).scalar()
    total_faqs = db.query(func.count(FAQItem.id)).filter(FAQItem.hotel_id == hid).scalar()
    total_promos = db.query(func.count(Promo.id)).filter(Promo.hotel_id == hid).scalar()
    total_popups = db.query(func.count(Popup.id)).filter(Popup.hotel_id == hid).scalar()
    recent_leads = db.query(GuestLead).filter(GuestLead.hotel_id == hid).order_by(GuestLead.created_at.desc()).limit(5).all()
    push_subscribers = db.query(func.count(PushSubscription.id)).filter(PushSubscription.hotel_id == hid).scalar()
    return {
        "total_leads": total_leads,
        "leads_this_week": leads_this_week,
        "total_modules": total_modules,
        "total_faqs": total_faqs,
        "total_promos": total_promos,
        "total_popups": total_popups,
        "recent_leads": [lead_to_dict(l) for l in recent_leads],
        "visits_by_date": _visits_by_date(db, hid),
        "leads_by_date": _leads_by_date(db, hid),
        "push_subscribers": push_subscribers,
        "top_modules": _top_modules(db, hid),
    }


# ── Hotel profile ──────────────────────────────────────────────────────────

@app.get("/api/admin/hotel")
def get_hotel(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == _resolve_hotel_id(user, request)).first()
    return hotel_to_dict(hotel)


def _apply_hotel_field(hotel: Hotel, k: str, v):
    """Aplica un campo de HotelUpdate a la instancia, con validación/saneado
    especial para custom_css, header_style, header_config y supported_languages (P4)."""
    if k == "custom_css":
        v = sanitize_custom_css(v)  # P1-2 / SEC A2
    elif k == "header_style":
        v = _validate_header_style(v)
    elif k == "header_config":
        v = _validate_header_config(v)
    elif k == "supported_languages":
        v = _validate_supported_languages(v)
    elif k == "plan":
        if v not in ("trial", "active", "suspended"):
            raise HTTPException(status_code=422, detail="plan inválido (trial|active|suspended)")
    setattr(hotel, k, v)


@app.put("/api/admin/hotel")
def update_hotel(data: HotelUpdate, request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == _resolve_hotel_id(user, request)).first()
    for k, v in data.model_dump(exclude_unset=True).items():
        _apply_hotel_field(hotel, k, v)
    db.commit()
    return hotel_to_dict(hotel)


# ── Themes CRUD (super_admin only) ──────────────────────────────────────────

@app.get("/api/admin/themes")
def list_themes(request: Request, user: User = Depends(require_role(UserRole.super_admin)), db: Session = Depends(get_db)):
    themes = db.query(Theme).order_by(Theme.name).all()
    return [{"id": t.id, "name": t.name, "description": t.description,
             "is_active": t.is_active, "created_at": t.created_at.isoformat() if t.created_at else None}
            for t in themes]


@app.post("/api/admin/themes")
def create_theme(data: ThemeCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin)), db: Session = Depends(get_db)):
    theme = Theme(name=data.name, description=data.description,
                  css_content=data.css_content, is_active=data.is_active,
                  created_by=user.id)
    db.add(theme)
    db.commit()
    db.refresh(theme)
    return {"id": theme.id, "name": theme.name, "description": theme.description,
            "is_active": theme.is_active, "css_content": theme.css_content}


@app.get("/api/admin/themes/{theme_id}")
def get_theme(theme_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin)), db: Session = Depends(get_db)):
    theme = db.query(Theme).filter(Theme.id == theme_id).first()
    if not theme:
        raise HTTPException(status_code=404, detail="Theme no encontrado")
    return {"id": theme.id, "name": theme.name, "description": theme.description,
            "is_active": theme.is_active, "css_content": theme.css_content,
            "created_at": theme.created_at.isoformat() if theme.created_at else None}


@app.put("/api/admin/themes/{theme_id}")
def update_theme(theme_id: int, data: ThemeUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin)), db: Session = Depends(get_db)):
    theme = db.query(Theme).filter(Theme.id == theme_id).first()
    if not theme:
        raise HTTPException(status_code=404, detail="Theme no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(theme, k, v)
    db.commit()
    db.refresh(theme)
    return {"id": theme.id, "name": theme.name, "description": theme.description,
            "is_active": theme.is_active, "css_content": theme.css_content}


@app.delete("/api/admin/themes/{theme_id}")
def delete_theme(theme_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin)), db: Session = Depends(get_db)):
    theme = db.query(Theme).filter(Theme.id == theme_id).first()
    if not theme:
        raise HTTPException(status_code=404, detail="Theme no encontrado")
    # Desvincular de hoteles que lo usen
    db.query(Hotel).filter(Hotel.theme_id == theme_id).update({"theme_id": None})
    db.delete(theme)
    db.commit()
    return {"ok": True}


# ── Public theme CSS endpoint ───────────────────────────────────────────────

@app.get("/api/theme/{theme_id}/css")
def serve_theme_css(theme_id: int, db: Session = Depends(get_db)):
    theme = db.query(Theme).filter(Theme.id == theme_id, Theme.is_active == True).first()
    if not theme:
        return Response(content="/* theme not found */", media_type="text/css")
    return Response(content=theme.css_content or "/* empty */", media_type="text/css")


# ── Modules CRUD ───────────────────────────────────────────────────────────

@app.get("/api/admin/modules")
def list_modules(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    modules = db.query(ContentModule).filter(ContentModule.hotel_id == _resolve_hotel_id(user, request)).order_by(ContentModule.sort_order).all()
    return [module_to_dict(m) for m in modules]


@app.post("/api/admin/modules")
def create_module(data: ModuleCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    payload = data.model_dump()
    payload["content_html"] = sanitize_html(payload.get("content_html"))  # P1-1
    payload["i18n"] = _validate_and_sanitize_i18n(payload.get("i18n"), html_fields=frozenset({"content_html"}))
    mod = ContentModule(hotel_id=_resolve_hotel_id(user, request), **payload)
    db.add(mod)
    db.commit()
    db.refresh(mod)
    return module_to_dict(mod)


@app.put("/api/admin/modules/{module_id}")
def update_module(module_id: int, data: ModuleUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    mod = db.query(ContentModule).filter(ContentModule.id == module_id, ContentModule.hotel_id == _resolve_hotel_id(user, request)).first()
    if not mod:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "content_html":
            v = sanitize_html(v)  # P1-1
        elif k == "i18n":
            v = _validate_and_sanitize_i18n(v, html_fields=frozenset({"content_html"}))
        setattr(mod, k, v)
    db.commit()
    return module_to_dict(mod)


@app.delete("/api/admin/modules/{module_id}")
def delete_module(module_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    mod = db.query(ContentModule).filter(ContentModule.id == module_id, ContentModule.hotel_id == _resolve_hotel_id(user, request)).first()
    if not mod:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    db.delete(mod)
    db.commit()
    return {"ok": True}


# ── FAQs CRUD ──────────────────────────────────────────────────────────────

@app.get("/api/admin/faqs")
def list_faqs(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faqs = db.query(FAQItem).filter(FAQItem.hotel_id == _resolve_hotel_id(user, request)).order_by(FAQItem.sort_order).all()
    return [faq_to_dict(f) for f in faqs]


@app.post("/api/admin/faqs")
def create_faq(data: FAQCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    payload = data.model_dump()
    payload["i18n"] = _validate_and_sanitize_i18n(payload.get("i18n"))
    faq = FAQItem(hotel_id=_resolve_hotel_id(user, request), **payload)
    db.add(faq)
    db.commit()
    db.refresh(faq)
    return faq_to_dict(faq)


@app.put("/api/admin/faqs/{faq_id}")
def update_faq(faq_id: int, data: FAQUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faq = db.query(FAQItem).filter(FAQItem.id == faq_id, FAQItem.hotel_id == _resolve_hotel_id(user, request)).first()
    if not faq:
        raise HTTPException(status_code=404, detail="FAQ no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "i18n":
            v = _validate_and_sanitize_i18n(v)
        setattr(faq, k, v)
    db.commit()
    return faq_to_dict(faq)


@app.delete("/api/admin/faqs/{faq_id}")
def delete_faq(faq_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faq = db.query(FAQItem).filter(FAQItem.id == faq_id, FAQItem.hotel_id == _resolve_hotel_id(user, request)).first()
    if not faq:
        raise HTTPException(status_code=404, detail="FAQ no encontrado")
    db.delete(faq)
    db.commit()
    return {"ok": True}


# ── Promos CRUD ────────────────────────────────────────────────────────────

@app.get("/api/admin/promos")
def list_promos(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promos = db.query(Promo).filter(Promo.hotel_id == _resolve_hotel_id(user, request)).order_by(Promo.created_at.desc()).all()
    return [promo_to_dict(p) for p in promos]


@app.post("/api/admin/promos")
def create_promo(data: PromoCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    # Fechas ya validadas/parseadas por pydantic (P1-8): inválidas → 422
    d = data.model_dump()
    d["i18n"] = _validate_and_sanitize_i18n(d.get("i18n"))
    promo = Promo(hotel_id=_resolve_hotel_id(user, request), **d)
    db.add(promo)
    db.commit()
    db.refresh(promo)
    return promo_to_dict(promo)


@app.put("/api/admin/promos/{promo_id}")
def update_promo(promo_id: int, data: PromoUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promo = db.query(Promo).filter(Promo.id == promo_id, Promo.hotel_id == _resolve_hotel_id(user, request)).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Promo no encontrada")
    d = data.model_dump(exclude_unset=True)
    for k, v in d.items():
        if k == "i18n":
            v = _validate_and_sanitize_i18n(v)
        setattr(promo, k, v)
    db.commit()
    return promo_to_dict(promo)


@app.delete("/api/admin/promos/{promo_id}")
def delete_promo(promo_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promo = db.query(Promo).filter(Promo.id == promo_id, Promo.hotel_id == _resolve_hotel_id(user, request)).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Promo no encontrada")
    db.delete(promo)
    db.commit()
    return {"ok": True}


# ── Posts CRUD ────────────────────────────────────────────────────────────

@app.get("/api/admin/posts")
def list_posts(request: Request, section: Optional[str] = None, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    q = db.query(Post).filter(Post.hotel_id == hid)
    if section:
        q = q.filter(Post.section == section)
    posts = q.order_by(Post.sort_order).all()
    return [post_to_dict(p) for p in posts]


@app.post("/api/admin/posts")
def create_post(data: PostCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    payload = data.model_dump()
    payload["content_html"] = sanitize_html(payload.get("content_html"))  # P1-1
    payload["i18n"] = _validate_and_sanitize_i18n(payload.get("i18n"), html_fields=frozenset({"content_html"}))
    post = Post(hotel_id=_resolve_hotel_id(user, request), **payload)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post_to_dict(post)


@app.put("/api/admin/posts/{post_id}")
def update_post(post_id: int, data: PostUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.hotel_id == _resolve_hotel_id(user, request)).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "content_html":
            v = sanitize_html(v)  # P1-1
        elif k == "i18n":
            v = _validate_and_sanitize_i18n(v, html_fields=frozenset({"content_html"}))
        setattr(post, k, v)
    db.commit()
    return post_to_dict(post)


@app.delete("/api/admin/posts/{post_id}")
def delete_post(post_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.hotel_id == _resolve_hotel_id(user, request)).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post no encontrado")
    db.delete(post)
    db.commit()
    return {"ok": True}


# ── Popups CRUD ──────────────────────────────────────────────────────────

@app.get("/api/admin/popups")
def list_popups(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popups = db.query(Popup).filter(Popup.hotel_id == _resolve_hotel_id(user, request)).order_by(Popup.sort_order).all()
    return [popup_to_dict(p) for p in popups]


@app.post("/api/admin/popups")
def create_popup(data: PopupCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    payload = data.model_dump()
    payload["i18n"] = _validate_and_sanitize_i18n(payload.get("i18n"))
    popup = Popup(hotel_id=_resolve_hotel_id(user, request), **payload)
    db.add(popup)
    db.commit()
    db.refresh(popup)
    return popup_to_dict(popup)


@app.put("/api/admin/popups/{popup_id}")
def update_popup(popup_id: int, data: PopupUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popup = db.query(Popup).filter(Popup.id == popup_id, Popup.hotel_id == _resolve_hotel_id(user, request)).first()
    if not popup:
        raise HTTPException(status_code=404, detail="Popup no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "i18n":
            v = _validate_and_sanitize_i18n(v)
        setattr(popup, k, v)
    db.commit()
    return popup_to_dict(popup)


@app.delete("/api/admin/popups/{popup_id}")
def delete_popup(popup_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popup = db.query(Popup).filter(Popup.id == popup_id, Popup.hotel_id == _resolve_hotel_id(user, request)).first()
    if not popup:
        raise HTTPException(status_code=404, detail="Popup no encontrado")
    db.delete(popup)
    db.commit()
    return {"ok": True}


# ── Sections CRUD ────────────────────────────────────────────────────────

def _unique_section_slug(db: Session, hid: int, base_text: str, exclude_id: Optional[int] = None) -> str:
    base_slug = _slugify(base_text)
    slug = base_slug
    counter = 2
    while True:
        q = db.query(Section).filter(Section.hotel_id == hid, Section.slug == slug)
        if exclude_id is not None:
            q = q.filter(Section.id != exclude_id)
        if not q.first():
            return slug
        slug = f"{base_slug}-{counter}"
        counter += 1


@app.get("/api/admin/sections")
def list_sections(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    sections = db.query(Section).filter(Section.hotel_id == _resolve_hotel_id(user, request)).order_by(Section.sort_order).all()
    return [section_to_dict(s) for s in sections]


@app.post("/api/admin/sections")
def create_section(data: SectionCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    i18n_json = _validate_and_sanitize_i18n(data.i18n)
    slug = _unique_section_slug(db, hid, data.slug or data.name)
    section = Section(
        hotel_id=hid, slug=slug, name=data.name, icon=data.icon,
        sort_order=data.sort_order, is_active=data.is_active, i18n=i18n_json,
    )
    db.add(section)
    db.commit()
    db.refresh(section)
    return section_to_dict(section)


@app.put("/api/admin/sections/{section_id}")
def update_section(section_id: int, data: SectionUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    section = db.query(Section).filter(Section.id == section_id, Section.hotel_id == hid).first()
    if not section:
        raise HTTPException(status_code=404, detail="Sección no encontrada")
    updates = data.model_dump(exclude_unset=True)
    if "slug" in updates:
        base_text = updates["slug"] or updates.get("name") or section.name
        updates["slug"] = _unique_section_slug(db, hid, base_text, exclude_id=section_id)
    if "i18n" in updates:
        updates["i18n"] = _validate_and_sanitize_i18n(updates["i18n"])
    for k, v in updates.items():
        setattr(section, k, v)
    db.commit()
    return section_to_dict(section)


@app.delete("/api/admin/sections/{section_id}")
def delete_section(section_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    section = db.query(Section).filter(Section.id == section_id, Section.hotel_id == hid).first()
    if not section:
        raise HTTPException(status_code=404, detail="Sección no encontrada")
    has_posts = db.query(Post).filter(Post.hotel_id == hid, Post.section == section.slug).first()
    if has_posts:
        raise HTTPException(status_code=409, detail="La sección tiene publicaciones; muévelas o elimínalas primero")
    db.delete(section)
    db.commit()
    return {"ok": True}


# ── Gallery CRUD ─────────────────────────────────────────────────────────

@app.get("/api/admin/gallery")
def list_gallery(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    images = db.query(GalleryImage).filter(GalleryImage.hotel_id == _resolve_hotel_id(user, request)).order_by(GalleryImage.sort_order).all()
    return [gallery_to_dict(g) for g in images]


@app.post("/api/admin/gallery")
def create_gallery_image(data: GalleryCreate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    payload = data.model_dump()
    payload["i18n"] = _validate_and_sanitize_i18n(payload.get("i18n"))
    image = GalleryImage(hotel_id=_resolve_hotel_id(user, request), **payload)
    db.add(image)
    db.commit()
    db.refresh(image)
    return gallery_to_dict(image)


@app.put("/api/admin/gallery/{image_id}")
def update_gallery_image(image_id: int, data: GalleryUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    image = db.query(GalleryImage).filter(GalleryImage.id == image_id, GalleryImage.hotel_id == _resolve_hotel_id(user, request)).first()
    if not image:
        raise HTTPException(status_code=404, detail="Imagen de galería no encontrada")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "i18n":
            v = _validate_and_sanitize_i18n(v)
        setattr(image, k, v)
    db.commit()
    return gallery_to_dict(image)


@app.delete("/api/admin/gallery/{image_id}")
def delete_gallery_image(image_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    image = db.query(GalleryImage).filter(GalleryImage.id == image_id, GalleryImage.hotel_id == _resolve_hotel_id(user, request)).first()
    if not image:
        raise HTTPException(status_code=404, detail="Imagen de galería no encontrada")
    db.delete(image)
    db.commit()
    return {"ok": True}


# ── Image Upload ──────────────────────────────────────────────────────────

UPLOAD_DIR = STATIC_DIR / "uploads"
ALLOWED_MIME_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/admin/upload")
async def upload_image(file: UploadFile = File(...),
                        user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin))):
    """Upload image and return URL. Requires auth; rejects non-images and oversized files."""
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=415, detail="Tipo de archivo no permitido. Solo imágenes JPEG, PNG o WebP")
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Archivo demasiado grande. Máximo 5 MB")
    ext = ALLOWED_MIME_TYPES[file.content_type]
    filename = f"{secrets.token_hex(8)}{ext}"
    filepath = UPLOAD_DIR / filename
    filepath.write_bytes(content)
    return {"url": f"/static/uploads/{filename}", "filename": filename}


# ── Leads ──────────────────────────────────────────────────────────────────

@app.get("/api/admin/leads")
def list_leads(request: Request, limit: int = Query(50, le=200), offset: int = 0, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    total = db.query(func.count(GuestLead.id)).filter(GuestLead.hotel_id == hid).scalar()
    leads = db.query(GuestLead).filter(GuestLead.hotel_id == hid).order_by(GuestLead.created_at.desc()).offset(offset).limit(limit).all()
    return {"leads": [lead_to_dict(l) for l in leads], "total": total}


# ── QR Sources ─────────────────────────────────────────────────────────────

@app.get("/api/admin/qr")
def list_qr(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    sources = db.query(QRSource).filter(QRSource.hotel_id == _resolve_hotel_id(user, request)).all()
    return [{"id": s.id, "name": s.name, "source_type": s.source_type, "code": s.code, "url_generated": s.url_generated, "is_active": s.is_active} for s in sources]


@app.post("/api/admin/qr")
def create_qr(data: QRCreate, request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if data.source_type not in ALLOWED_QR_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail="Tipo de fuente de QR no válido")
    code = f"{data.source_type.upper()}-{secrets.token_hex(4).upper()}"
    hotel = db.query(Hotel).filter(Hotel.id == _resolve_hotel_id(user, request)).first()
    relative_url = f"/g/{hotel.slug}?source={code}"
    absolute_url = f"{request.base_url.scheme}://{request.base_url.netloc}{relative_url}"
    src = QRSource(hotel_id=_resolve_hotel_id(user, request), name=data.name, source_type=data.source_type, code=code, url_generated=relative_url, is_active=True)
    db.add(src)
    db.commit()
    db.refresh(src)
    # Generate QR image
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(absolute_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    qr_path = QR_DIR / f"{code}.png"
    img.save(str(qr_path))
    # Also generate SVG
    svg_qr = qrcode.QRCode(version=1, box_size=10, border=4)
    svg_qr.add_data(absolute_url)
    svg_qr.make(fit=True)
    svg_img = svg_qr.make_image(image_factory=SvgPathImage)
    svg_path = QR_DIR / f"{code}.svg"
    svg_img.save(str(svg_path))
    return {"id": src.id, "name": src.name, "source_type": src.source_type, "code": src.code, "url_generated": src.url_generated}


@app.get("/api/admin/qr/{qr_id}/image")
def get_qr_image(qr_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    src = db.query(QRSource).filter(QRSource.id == qr_id, QRSource.hotel_id == _resolve_hotel_id(user, request)).first()
    if not src:
        raise HTTPException(status_code=404, detail="QR no encontrado")
    qr_path = QR_DIR / f"{src.code}.png"
    if not qr_path.exists():
        # Generate on the fly
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(src.url_generated)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(str(qr_path))
    return FileResponse(str(qr_path), media_type="image/png")


@app.get("/api/admin/qr/{qr_id}/image.svg")
def get_qr_svg(qr_id: int, request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    src = db.query(QRSource).filter(QRSource.id == qr_id, QRSource.hotel_id == _resolve_hotel_id(user, request)).first()
    if not src:
        raise HTTPException(status_code=404, detail="QR no encontrado")
    svg_path = QR_DIR / f"{src.code}.svg"
    if not svg_path.exists():
        # Regenerate SVG on the fly
        from qrcode.image.svg import SvgPathImage
        svg_qr = qrcode.QRCode(version=1, box_size=10, border=4)
        svg_qr.add_data(src.url_generated)
        svg_qr.make(fit=True)
        svg_img = svg_qr.make_image(image_factory=SvgPathImage)
        svg_img.save(str(svg_path))
    return Response(content=svg_path.read_text(), media_type="image/svg+xml")


# ── Hotels (multi-tenant management) ──────────────────────────────────────

@app.get("/api/admin/hotels")
def list_hotels(request: Request, user: User = Depends(require_role(UserRole.super_admin)),
                 db: Session = Depends(get_db)):
    hotels = db.query(Hotel).order_by(Hotel.nombre).all()
    result = []
    for h in hotels:
        leads_count = db.query(func.count(GuestLead.id)).filter(GuestLead.hotel_id == h.id).scalar()
        result.append({
            "id": h.id, "nombre": h.nombre, "slug": h.slug,
            "is_active": h.is_active, "logo_url": h.logo_url,
            "primary_color": h.primary_color, "leads_count": leads_count,
        })
    return result


@app.post("/api/admin/hotels")
def create_hotel(data: HotelUpdate, request: Request, user: User = Depends(require_role(UserRole.super_admin)),
                  db: Session = Depends(get_db)):
    import re
    nombre = data.nombre or "Nuevo Hotel"
    base_slug = nombre.lower().replace(" ", "-").replace("ñ", "n")
    base_slug = re.sub(r"[^a-z0-9-]", "", base_slug) or "hotel"
    slug = base_slug
    counter = 1
    while db.query(Hotel).filter(Hotel.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1
    # Usar TODO el branding recibido (no solo el nombre)
    payload = data.model_dump(exclude_unset=True)
    payload.pop("nombre", None)
    if "custom_css" in payload:
        payload["custom_css"] = sanitize_custom_css(payload["custom_css"])  # P1-2
    if "header_style" in payload:
        payload["header_style"] = _validate_header_style(payload["header_style"])
    if "header_config" in payload:
        payload["header_config"] = _validate_header_config(payload["header_config"])
    if "supported_languages" in payload:
        payload["supported_languages"] = _validate_supported_languages(payload["supported_languages"])
    hotel = Hotel(nombre=nombre, slug=slug, is_active=True, **payload)
    db.add(hotel)
    db.commit()
    db.refresh(hotel)
    return hotel_to_dict(hotel)


@app.get("/api/admin/hotels/{hotel_id}")
def get_hotel_by_id(hotel_id: int, user: User = Depends(require_role(UserRole.super_admin)),
                    db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == hotel_id).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    return hotel_to_dict(hotel)


@app.put("/api/admin/hotels/{hotel_id}")
def update_hotel_by_id(hotel_id: int, data: HotelSuperUpdate,
                       user: User = Depends(require_role(UserRole.super_admin)),
                       db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == hotel_id).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        _apply_hotel_field(hotel, k, v)
    db.commit()
    db.refresh(hotel)
    return hotel_to_dict(hotel)


@app.delete("/api/admin/hotels/{hotel_id}")
def delete_hotel_by_id(hotel_id: int, user: User = Depends(require_role(UserRole.super_admin)),
                       db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == hotel_id).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    # No permitir archivar el hotel propio en uso
    if user.hotel_id and user.hotel_id == hotel_id:
        raise HTTPException(status_code=400, detail="No puedes archivar tu propio hotel en uso")
    # Soft delete: nunca borrado físico
    hotel.is_active = False
    db.commit()
    return {"ok": True, "id": hotel.id, "is_active": hotel.is_active}


# ── User management (P5: super_admin ve todo; hotel_admin gestiona su hotel) ─

def user_to_dict(u: User, db: Optional[Session] = None) -> dict:
    """Serializa un usuario SIN exponer el password_hash. Si se pasa `db`,
    incluye la lista de asignaciones hotel/rol (P5)."""
    d = {
        "id": u.id, "email": u.email, "name": u.name,
        "role": u.role, "hotel_id": u.hotel_id, "is_active": u.is_active,
        "created_at": str(u.created_at) if u.created_at else None,
    }
    if db is not None:
        assigns = db.query(UserHotel).filter(UserHotel.user_id == u.id).all()
        d["hotels"] = [{"hotel_id": a.hotel_id, "role": a.role} for a in assigns]
    return d


def _target_hotel_ids(db: Session, target: User) -> set:
    """Hoteles a los que `target` tiene acceso (user_hotels + hotel_id legacy)."""
    ids = {r.hotel_id for r in db.query(UserHotel).filter(UserHotel.user_id == target.id).all()}
    if target.hotel_id:
        ids.add(target.hotel_id)
    return ids


def _assert_user_in_scope(db: Session, actor: User, request: Request, target: User) -> None:
    """404 si `target` no está dentro del alcance de gestión de `actor`.

    super_admin ve/gestiona a todos. hotel_admin (rol admin, ya filtrado de
    editores por `require_manager`) solo ve usuarios con acceso a su hotel
    activo, y nunca puede tocar a un super_admin (se le oculta con 404)."""
    if actor.role == UserRole.super_admin:
        return
    if target.role == UserRole.super_admin:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    active_hid = _resolve_hotel_id(actor, request)
    if active_hid not in _target_hotel_ids(db, target):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")


def _count_active_admins(db: Session, hid: int, exclude_user_id: Optional[int] = None) -> int:
    q = db.query(UserHotel).join(User, User.id == UserHotel.user_id).filter(
        UserHotel.hotel_id == hid, UserHotel.role == "admin", User.is_active == True,
    )
    if exclude_user_id is not None:
        q = q.filter(UserHotel.user_id != exclude_user_id)
    return q.count()


def _ensure_not_last_admin(db: Session, hid: int, exclude_user_id: int) -> None:
    if _count_active_admins(db, hid, exclude_user_id=exclude_user_id) == 0:
        raise HTTPException(status_code=400, detail="No puedes dejar el hotel sin un administrador activo")


def _ensure_can_deactivate(db: Session, target: User) -> None:
    """Bloquea desactivar/quitar el último admin de cualquier hotel donde
    `target` figure como admin."""
    if target.role == UserRole.super_admin:
        return
    assigns = db.query(UserHotel).filter(UserHotel.user_id == target.id, UserHotel.role == "admin").all()
    hids = {a.hotel_id for a in assigns}
    if target.hotel_id and target.hotel_id not in {a.hotel_id for a in db.query(UserHotel).filter(UserHotel.user_id == target.id).all()}:
        # hotel_id legacy sin fila en user_hotels: cuenta como admin de ese hotel
        hids.add(target.hotel_id)
    for hid in hids:
        _ensure_not_last_admin(db, hid, exclude_user_id=target.id)


@app.get("/api/admin/users")
def list_users(request: Request, hotel_id: Optional[int] = None,
                user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if user.role == UserRole.super_admin:
        q = db.query(User)
        if hotel_id:
            ids = {r.user_id for r in db.query(UserHotel).filter(UserHotel.hotel_id == hotel_id).all()}
            q = q.filter(User.id.in_(ids) | (User.hotel_id == hotel_id))
    else:
        active_hid = _resolve_hotel_id(user, request)
        ids = {r.user_id for r in db.query(UserHotel).filter(UserHotel.hotel_id == active_hid).all()}
        q = db.query(User).filter(User.id.in_(ids) | (User.hotel_id == active_hid))
    users = q.order_by(User.email).all()
    return [user_to_dict(u, db) for u in users]


@app.post("/api/admin/users")
def create_user(data: UserCreate, request: Request, user: User = Depends(require_manager),
                db: Session = Depends(get_db)):
    email = (data.email or "").strip().lower()
    if not email or not data.password or not data.name:
        raise HTTPException(status_code=400, detail="email, name y password son obligatorios")
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres")
    if data.role not in (UserRole.hotel_admin, UserRole.super_admin):
        raise HTTPException(status_code=400, detail="Rol no válido")
    if data.role == UserRole.super_admin and user.role != UserRole.super_admin:
        raise HTTPException(status_code=403, detail="Solo un super_admin puede crear otro super_admin")
    if db.query(User).filter(func.lower(User.email) == email).first():
        raise HTTPException(status_code=409, detail="El email ya está registrado")

    hotels_payload = list(data.hotels or [])
    if user.role != UserRole.super_admin:
        # hotel_admin solo puede crear usuarios de SU hotel activo
        active_hid = _resolve_hotel_id(user, request)
        if not hotels_payload:
            hotels_payload = [UserHotelAssignment(hotel_id=active_hid, role="admin")]
        elif any(h.hotel_id != active_hid for h in hotels_payload):
            raise HTTPException(status_code=403, detail="Solo puedes asignar usuarios a tu hotel activo")

    if data.role == UserRole.hotel_admin and not hotels_payload:
        raise HTTPException(status_code=400, detail="hotels es obligatorio para hotel_admin")

    hotel_ids = {h.hotel_id for h in hotels_payload}
    if hotel_ids:
        found = {h.id for h in db.query(Hotel).filter(Hotel.id.in_(hotel_ids)).all()}
        missing = hotel_ids - found
        if missing:
            raise HTTPException(status_code=404, detail="Hotel no encontrado")

    legacy_hotel_id = hotels_payload[0].hotel_id if hotels_payload else None
    new_user = User(
        email=email,
        password_hash=hash_password(data.password),
        name=data.name,
        role=data.role,
        hotel_id=legacy_hotel_id if data.role == UserRole.hotel_admin else None,
        is_active=True,
    )
    db.add(new_user)
    db.flush()
    for h in hotels_payload:
        db.add(UserHotel(user_id=new_user.id, hotel_id=h.hotel_id, role=h.role))
    db.commit()
    db.refresh(new_user)
    return user_to_dict(new_user, db)


@app.put("/api/admin/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, request: Request,
                user: User = Depends(require_manager), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    _assert_user_in_scope(db, user, request, target)

    if data.hotels is not None:
        new_hotel_ids = {h.hotel_id for h in data.hotels}
        if user.role != UserRole.super_admin:
            active_hid = _resolve_hotel_id(user, request)
            if any(h.hotel_id != active_hid for h in data.hotels):
                raise HTTPException(status_code=403, detail="Solo puedes asignar tu hotel activo")
            if target.id == user.id and active_hid not in new_hotel_ids:
                raise HTTPException(status_code=400, detail="No puedes quitarte el acceso a tu propio hotel")
        if new_hotel_ids:
            found = {h.id for h in db.query(Hotel).filter(Hotel.id.in_(new_hotel_ids)).all()}
            missing = new_hotel_ids - found
            if missing:
                raise HTTPException(status_code=404, detail="Hotel no encontrado")
        # Si se le quita el rol admin en un hotel donde era el único admin, bloquear
        current = {r.hotel_id: r.role for r in db.query(UserHotel).filter(UserHotel.user_id == target.id).all()}
        for hid, role in current.items():
            if role == "admin" and hid not in new_hotel_ids:
                _ensure_not_last_admin(db, hid, exclude_user_id=target.id)
        db.query(UserHotel).filter(UserHotel.user_id == target.id).delete()
        for h in data.hotels:
            db.add(UserHotel(user_id=target.id, hotel_id=h.hotel_id, role=h.role))
        target.hotel_id = data.hotels[0].hotel_id if data.hotels else None

    if data.name is not None:
        target.name = data.name.strip() or target.name

    if data.is_active is not None and data.is_active != target.is_active:
        if data.is_active is False:
            if target.id == user.id:
                raise HTTPException(status_code=400, detail="No puedes desactivarte a ti mismo")
            _ensure_can_deactivate(db, target)
        target.is_active = data.is_active

    db.commit()
    db.refresh(target)
    return user_to_dict(target, db)


@app.post("/api/admin/users/{user_id}/reset-password")
def reset_user_password(user_id: int, data: ResetPasswordRequest, request: Request,
                        user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if not data.new_password or len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe tener al menos 8 caracteres")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    _assert_user_in_scope(db, user, request, target)
    target.password_hash = hash_password(data.new_password)
    db.commit()
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, request: Request, user: User = Depends(require_manager),
                db: Session = Depends(get_db)):
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="No puedes desactivarte a ti mismo")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    _assert_user_in_scope(db, user, request, target)
    _ensure_can_deactivate(db, target)
    target.is_active = False
    db.commit()
    return {"ok": True, "id": target.id, "is_active": target.is_active}


@app.post("/api/admin/change-password")
def change_password(data: ChangePasswordRequest,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña actual incorrecta")
    if not data.new_password or len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe tener al menos 8 caracteres")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {"ok": True}


@app.get("/api/admin/hotel/app-url")
def get_app_url(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)),
                 db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == _resolve_hotel_id(user, request)).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    return {"slug": hotel.slug, "app_url": f"/g/{hotel.slug}"}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/api/admin/analytics")
def get_analytics(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)

    # Events breakdown
    events = db.query(
        AccessLog.event_type, func.count(AccessLog.id)
    ).filter(AccessLog.hotel_id == hid).group_by(AccessLog.event_type).all()

    return {
        "leads_by_date": _leads_by_date(db, hid),
        "events_breakdown": {r[0]: r[1] for r in events},
        "top_modules": _top_modules(db, hid),
    }


# ── Push Notifications (admin) ──────────────────────────────────────────────

@app.get("/api/admin/notifications")
def list_notifications(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    notifications = db.query(ScheduledNotification).filter(
        ScheduledNotification.hotel_id == hid
    ).order_by(ScheduledNotification.created_at.desc()).all()
    return [notification_to_dict(n) for n in notifications]


@app.post("/api/admin/notifications")
def create_notification(data: NotificationCreate, request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    now = datetime.utcnow()
    scheduled_at = data.scheduled_at
    # El admin envía ISO con zona (…Z); la BD y el scheduler trabajan en UTC naive
    if scheduled_at is not None and scheduled_at.tzinfo is not None:
        scheduled_at = scheduled_at.astimezone(timezone.utc).replace(tzinfo=None)
    if scheduled_at is not None and scheduled_at < now - timedelta(minutes=1):
        raise HTTPException(status_code=400, detail="scheduled_at no puede estar en el pasado")
    notif = ScheduledNotification(
        hotel_id=hid, title=data.title, body=data.body, url=data.url,
        scheduled_at=scheduled_at or now, status="scheduled",
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)
    return notification_to_dict(notif)


@app.delete("/api/admin/notifications/{notification_id}")
def cancel_notification(notification_id: int, request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    notif = db.query(ScheduledNotification).filter(
        ScheduledNotification.id == notification_id, ScheduledNotification.hotel_id == hid
    ).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notificación no encontrada")
    if notif.status != "scheduled":
        raise HTTPException(status_code=400, detail="Solo se pueden cancelar notificaciones programadas")
    notif.status = "cancelled"
    db.commit()
    return {"ok": True}


@app.get("/api/admin/push/stats")
def push_stats(request: Request, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _resolve_hotel_id(user, request)
    count = db.query(func.count(PushSubscription.id)).filter(PushSubscription.hotel_id == hid).scalar()
    return {"subscribers": count}


# ── Billing (Stripe) ───────────────────────────────────────────────────────
#
# Un solo plan (STRIPE_PRICE_ID), cupones nativos de Stripe Checkout
# (allow_promotion_codes) y facturas manuales gestionadas desde el dashboard
# de Stripe (no hay endpoint propio para listarlas/emitirlas). El estado de
# la suscripción se sincroniza vía webhook (checkout.session.completed,
# customer.subscription.updated, customer.subscription.deleted) hacia
# Hotel.plan/trial_ends_at — ver mapa de estados en docs/API.md.

def _base_url(request: Request) -> str:
    """Origen público a partir del request (respeta X-Forwarded-Proto detrás
    de proxy TLS, igual que SecurityHeadersMiddleware)."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{scheme}://{request.url.netloc}"


def _find_hotel_by_stripe_customer(db: Session, customer_id: Optional[str]) -> Optional[Hotel]:
    if not customer_id:
        return None
    return db.query(Hotel).filter(Hotel.stripe_customer_id == customer_id).first()


def _find_hotel_by_stripe_subscription(db: Session, subscription_id: Optional[str]) -> Optional[Hotel]:
    if not subscription_id:
        return None
    return db.query(Hotel).filter(Hotel.stripe_subscription_id == subscription_id).first()


@app.post("/api/admin/billing/checkout")
def create_billing_checkout(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if not BILLING_ENABLED:
        raise HTTPException(status_code=503, detail="La facturación no está configurada")
    hid = _resolve_hotel_id(user, request)
    hotel = db.query(Hotel).filter(Hotel.id == hid).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")

    if not hotel.stripe_customer_id:
        customer = stripe.Customer.create(email=user.email, metadata={"hotel_id": str(hotel.id)})
        hotel.stripe_customer_id = customer.id
        db.commit()

    base = _base_url(request)
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=hotel.stripe_customer_id,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        allow_promotion_codes=True,
        client_reference_id=str(hotel.id),
        metadata={"hotel_id": str(hotel.id)},
        success_url=f"{base}/admin?billing=success",
        cancel_url=f"{base}/admin?billing=cancelled",
    )
    return {"url": session.url}


@app.get("/api/admin/billing/portal")
def get_billing_portal(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if not BILLING_ENABLED:
        raise HTTPException(status_code=503, detail="La facturación no está configurada")
    hid = _resolve_hotel_id(user, request)
    hotel = db.query(Hotel).filter(Hotel.id == hid).first()
    if not hotel or not hotel.stripe_customer_id:
        raise HTTPException(status_code=404, detail="Este hotel no tiene una suscripción")

    base = _base_url(request)
    session = stripe.billing_portal.Session.create(
        customer=hotel.stripe_customer_id,
        return_url=f"{base}/admin",
    )
    return {"url": session.url}


def _hotel_from_billing_event(db: Session, event_data: dict) -> Optional[Hotel]:
    """Localiza el hotel de un evento de checkout.session.completed:
    metadata.hotel_id o, si falta, client_reference_id."""
    metadata = event_data.get("metadata") or {}
    raw_hid = metadata.get("hotel_id") or event_data.get("client_reference_id")
    if not raw_hid:
        return None
    try:
        hid = int(raw_hid)
    except (TypeError, ValueError):
        return None
    return db.query(Hotel).filter(Hotel.id == hid).first()


@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    if not BILLING_ENABLED:
        raise HTTPException(status_code=503, detail="La facturación no está configurada")
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Firma de webhook inválida")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        hotel = _hotel_from_billing_event(db, data)
        if hotel:
            customer_id = data.get("customer")
            subscription_id = data.get("subscription")
            if customer_id:
                hotel.stripe_customer_id = customer_id
            if subscription_id:
                hotel.stripe_subscription_id = subscription_id
            hotel.plan = "active"
            hotel.trial_ends_at = None
            db.commit()
        else:
            print("[BILLING] checkout.session.completed sin hotel resoluble (evento ignorado)")

    elif event_type == "customer.subscription.updated":
        subscription_id = data.get("id")
        hotel = _find_hotel_by_stripe_subscription(db, subscription_id) or _find_hotel_by_stripe_customer(db, data.get("customer"))
        if hotel:
            status = data.get("status")
            hotel.stripe_subscription_id = subscription_id
            if status in ("active", "trialing", "past_due"):
                # past_due: periodo de gracia mientras Stripe reintenta el cobro.
                hotel.plan = "active"
            elif status in ("canceled", "unpaid", "incomplete_expired"):
                hotel.plan = "suspended"
            db.commit()
        else:
            print(f"[BILLING] customer.subscription.updated sin hotel resoluble (status={data.get('status')})")

    elif event_type == "customer.subscription.deleted":
        subscription_id = data.get("id")
        hotel = _find_hotel_by_stripe_subscription(db, subscription_id) or _find_hotel_by_stripe_customer(db, data.get("customer"))
        if hotel:
            hotel.plan = "suspended"
            hotel.stripe_subscription_id = None
            db.commit()
        else:
            print("[BILLING] customer.subscription.deleted sin hotel resoluble (evento ignorado)")

    else:
        print(f"[BILLING] evento ignorado: {event_type}")

    return {"received": True}


# ── QR redirect ────────────────────────────────────────────────────────────

@app.get("/api/qr/{code}")
def qr_redirect(code: str, db: Session = Depends(get_db)):
    src = db.query(QRSource).filter(QRSource.code == code, QRSource.is_active == True).first()
    if not src:
        raise HTTPException(status_code=404, detail="QR no válido")
    return RedirectResponse(url=src.url_generated)


# ═══════════════════════════════════════════════════════════════════════════
#  STATIC & PWA ROUTES
# ═══════════════════════════════════════════════════════════════════════════

def _load_html(filename: str) -> str:
    path = TEMPLATES_DIR / filename
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.get("/", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
def serve_admin():
    return HTMLResponse(content=_load_html("admin.html"))


@app.get("/g/{slug}", response_class=HTMLResponse)
def serve_guest(slug: str):
    return HTMLResponse(content=_load_html("guest.html"))


def _hex_to_rgb(color: str, fallback=(30, 58, 95)):
    try:
        c = (color or "").lstrip("#")
        if len(c) == 3:
            c = "".join(ch * 2 for ch in c)
        return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))
    except Exception:
        return fallback


def _generate_hotel_icon(hotel: Hotel, size: int) -> bytes:
    """Genera un PNG cuadrado con el color de marca y la inicial del hotel."""
    from io import BytesIO
    from PIL import Image, ImageDraw, ImageFont

    bg = _hex_to_rgb(hotel.primary_color, (30, 58, 95))
    img = Image.new("RGB", (size, size), bg)
    draw = ImageDraw.Draw(img)
    letter = (hotel.nombre or "H").strip()[:1].upper() or "H"

    # Color de texto legible sobre el fondo
    luminance = (0.299 * bg[0] + 0.587 * bg[1] + 0.114 * bg[2])
    fg = (26, 26, 46) if luminance > 160 else (255, 255, 255)

    font = None
    try:
        font = ImageFont.truetype("arial.ttf", int(size * 0.55))
    except Exception:
        try:
            font = ImageFont.truetype("DejaVuSans-Bold.ttf", int(size * 0.55))
        except Exception:
            font = ImageFont.load_default()
    try:
        bbox = draw.textbbox((0, 0), letter, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((size - tw) / 2 - bbox[0], (size - th) / 2 - bbox[1]), letter, fill=fg, font=font)
    except Exception:
        draw.text((size / 2, size / 2), letter, fill=fg)

    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@app.get("/g/{slug}/icon-{size}.png")
def serve_hotel_icon(slug: str, size: int, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    if size not in (192, 512):
        size = 192
    png = _generate_hotel_icon(hotel, size)
    return Response(content=png, media_type="image/png")


@app.get("/g/{slug}/manifest.webmanifest")
def serve_hotel_manifest(slug: str, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    short_name = hotel.pwa_short_name or hotel.nombre
    icon_url = hotel.pwa_icon_url or "/static/icon-192.png"
    icon_512 = hotel.pwa_icon_url or "/static/icon-512.png"
    manifest = {
        "name": hotel.nombre,
        "short_name": short_name,
        "start_url": f"/g/{hotel.slug}",
        "scope": f"/g/{hotel.slug}",
        "display": "standalone",
        "background_color": hotel.bg_color or "#FFFFFF",
        "theme_color": hotel.primary_color or "#1E3A5F",
        "icons": [
            {"src": icon_url, "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": icon_512, "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ],
    }
    return JSONResponse(content=manifest, media_type="application/manifest+json")


@app.get("/manifest.json")
def serve_manifest():
    manifest = {
        "name": "HostelFlow Guest Guide",
        "short_name": "HostelFlow",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#1E3A5F",
        "icons": [
            {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ]
    }
    return JSONResponse(content=manifest)


@app.get("/sw.js")
def serve_sw():
    sw = """
const CACHE_NAME = 'hostelflow-v2';
const urlsToCache = ['/', '/admin', '/manifest.json'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(urlsToCache)));
});
self.addEventListener('fetch', e => {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});

self.addEventListener('push', e => {
    let data = {};
    try {
        data = e.data ? e.data.json() : {};
    } catch (err) {
        data = { title: 'HostelFlow', body: e.data ? e.data.text() : '' };
    }
    const title = data.title || 'HostelFlow';
    const options = {
        body: data.body || '',
        icon: data.icon || '/static/icon-192.png',
        badge: data.badge || '/static/icon-192.png',
        tag: data.tag || 'hostelflow-notif',
        data: { url: data.url || '/' },
    };
    e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', e => {
    e.notification.close();
    const url = (e.notification.data && e.notification.data.url) || '/';
    e.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
            for (const client of windowClients) {
                if (client.url === url && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(url);
            }
        })
    );
});
"""
    return Response(content=sw, media_type="application/javascript")


# ── Mount static LAST (before catch-all) ──────────────────────────────────
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"HostelFlow running on http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
