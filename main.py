"""
HostelFlow — FastAPI main application.
SaaS digital guest guide platform for hotels.
"""

import io
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List

import qrcode
from fastapi import FastAPI, Depends, HTTPException, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session

from models import (
    Base, User, Hotel, GuestLead, ContentModule, FAQItem, Promo,
    AccessLog, QRSource, Post, Popup, UserRole,
)

# ── Config ─────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("HOSTELFLOW_SECRET", "hostelflow-dev-secret-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hostelflow.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
QR_DIR = STATIC_DIR / "qr"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
QR_DIR.mkdir(parents=True, exist_ok=True)

# ── Password hashing ───────────────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# ── JWT helpers ────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── FastAPI app ────────────────────────────────────────────────────────────

app = FastAPI(title="HostelFlow", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    except JWTError:
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


# ── Pydantic schemas ──────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


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
    custom_js: Optional[str] = None


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


class FAQCreate(BaseModel):
    question: str
    answer: str
    sort_order: int = 0
    is_active: bool = True


class FAQUpdate(BaseModel):
    question: Optional[str] = None
    answer: Optional[str] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None


class PromoCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    image_url: Optional[str] = None
    price_text: Optional[str] = None
    cta_label: Optional[str] = "Ver más"
    cta_link: Optional[str] = None
    is_active: bool = True
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class PromoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    price_text: Optional[str] = None
    cta_label: Optional[str] = None
    cta_link: Optional[str] = None
    is_active: Optional[bool] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class OnboardingRequest(BaseModel):
    name: str
    whatsapp: Optional[str] = None
    email: Optional[str] = None
    check_in_date: Optional[str] = None
    check_out_date: Optional[str] = None
    language: str = "es"
    consent_contact: bool = False
    source_qr: Optional[str] = None


class EventRequest(BaseModel):
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
        "theme": h.theme, "custom_css": h.custom_css, "custom_js": h.custom_js,
    }


def module_to_dict(m: ContentModule) -> dict:
    return {
        "id": m.id, "hotel_id": m.hotel_id, "module_type": m.module_type,
        "title": m.title, "subtitle": m.subtitle, "content_html": m.content_html,
        "image_url": m.image_url, "icon": m.icon, "sort_order": m.sort_order,
        "is_active": m.is_active, "audience_stage": m.audience_stage,
    }


def faq_to_dict(f: FAQItem) -> dict:
    return {
        "id": f.id, "hotel_id": f.hotel_id, "question": f.question,
        "answer": f.answer, "sort_order": f.sort_order, "is_active": f.is_active,
    }


def promo_to_dict(p: Promo) -> dict:
    return {
        "id": p.id, "hotel_id": p.hotel_id, "title": p.title,
        "description": p.description, "image_url": p.image_url,
        "price_text": p.price_text, "cta_label": p.cta_label,
        "cta_link": p.cta_link, "is_active": p.is_active,
        "start_date": str(p.start_date) if p.start_date else None,
        "end_date": str(p.end_date) if p.end_date else None,
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
        "image_url": p.image_url, "content_html": p.content_html,
        "button_text": p.button_text, "button_url": p.button_url,
        "icon": p.icon, "sort_order": p.sort_order,
        "is_active": p.is_active,
        "created_at": str(p.created_at) if p.created_at else None,
    }


def popup_to_dict(p: Popup) -> dict:
    return {
        "id": p.id, "hotel_id": p.hotel_id, "title": p.title,
        "message": p.message, "image_url": p.image_url,
        "button_text": p.button_text, "button_url": p.button_url,
        "trigger_type": p.trigger_type, "trigger_seconds": p.trigger_seconds,
        "is_active": p.is_active, "sort_order": p.sort_order,
        "created_at": str(p.created_at) if p.created_at else None,
    }


# ── Seed data ──────────────────────────────────────────────────────────────

def seed_data():
    db = SessionLocal()
    try:
        if db.query(Hotel).count() > 0:
            return

        # Hotel
        hotel = Hotel(
            nombre="Hotel Azul",
            slug="hotel-azul",
            logo_url="https://images.unsplash.com/photo-1566073771259-6a8506099945?w=200&h=200&fit=crop",
            cover_url="https://images.unsplash.com/photo-1582719508461-905c673771fd?w=1200&h=600&fit=crop",
            primary_color="#1E3A5F",
            secondary_color="#4A90D9",
            accent_color="#F0B429",
            description="Hotel boutique frente al mar con vista panorámica. Estancia cómoda y servicio personalizado.",
            whatsapp="+528112345678",
            email="info@hotelazul.com",
            phone="+528112345678",
            address="Av. Costera 123, Zona Centro, Monterrey, NL 64000",
            privacy_policy="Recopilamos datos básicos para mejorar tu estancia. No compartimos con terceros.",
            default_language="es",
            is_active=True,
        )
        db.add(hotel)
        db.flush()

        # Users
        admin = User(
            email="admin@hostelflow.com",
            password_hash=hash_password("admin123"),
            name="Admin HostelFlow",
            role=UserRole.super_admin,
            is_active=True,
        )
        hotel_admin = User(
            email="admin@hotel-azul.com",
            password_hash=hash_password("admin123"),
            name="Carlos Manager",
            role=UserRole.hotel_admin,
            hotel_id=hotel.id,
            is_active=True,
        )
        db.add_all([admin, hotel_admin])
        db.flush()

        # Content modules
        modules = [
            ContentModule(hotel_id=hotel.id, module_type="wifi", title="WiFi Gratis", subtitle="Conéctate sin costo", content_html="<p><strong>Red:</strong> HotelAzul_Guest</p><p><strong>Contraseña:</strong> Azul2026!</p><p>WiFi disponible en todas las áreas comunes y habitaciones.</p>", icon="wifi", sort_order=1, is_active=True, audience_stage="all"),
            ContentModule(hotel_id=hotel.id, module_type="hours", title="Horarios", subtitle="Horarios del hotel", content_html="<p><strong>Recepción:</strong> 24 horas</p><p><strong>Check-in:</strong> 15:00 hrs</p><p><strong>Check-out:</strong> 12:00 hrs</p><p><strong>Restaurante:</strong> 7:00 - 23:00 hrs</p><p><strong>Alberca:</strong> 8:00 - 21:00 hrs</p><p><strong>Gimnasio:</strong> 6:00 - 22:00 hrs</p>", icon="clock", sort_order=2, is_active=True, audience_stage="all"),
            ContentModule(hotel_id=hotel.id, module_type="rules", title="Reglas del Hotel", subtitle="House rules", content_html="<p><strong>Silencio:</strong> De 23:00 a 07:00 hrs</p><p><strong>No fumar:</strong> Prohibido en todas las instalaciones</p><p><strong>Mascotas:</strong> No se permiten mascotas</p><p><strong>Visitas:</strong> Solo huéspedes registrados</p><p><strong>Alberca:</strong> Toalla propia o solicitar en recepción</p>", icon="alert-circle", sort_order=3, is_active=True, audience_stage="all"),
            ContentModule(hotel_id=hotel.id, module_type="location", title="Cómo Llegar", subtitle="Ubicación y transporte", content_html="<p><strong>Dirección:</strong> Av. Costera 123, Zona Centro, Monterrey, NL 64000</p><p><strong>Desde aeropuerto:</strong> 45 min en auto</p><p><strong>Estacionamiento:</strong> Gratis para huéspedes</p><p><strong>Transporte:</strong> Solicitar en recepción con cargo adicional</p>", icon="map-pin", sort_order=4, is_active=True, audience_stage="pre_arrival"),
            ContentModule(hotel_id=hotel.id, module_type="services", title="Servicios y Amenidades", subtitle="Todo lo que ofrecemos", content_html="<p><strong>Alberca infinity</strong> con vista al mar</p><p><strong>Gimnasio</strong> equipado 24h</p><p><strong>Spa</strong> masajes y tratamientos</p><p><strong>Sala de juegos</strong> para niños</p><p><strong>Business center</strong> con impresora</p><p><strong>Lavandería</strong> servicio exprés</p>", icon="star", sort_order=5, is_active=True, audience_stage="in_stay"),
            ContentModule(hotel_id=hotel.id, module_type="dining", title="Restaurantes", subtitle="Dónde comer cerca", content_html="<p><strong>Restaurante El Mar:</strong> Cocina mediterránea, 50m del hotel</p><p><strong>Café Azul:</strong> Desayunos y brunch, dentro del hotel</p><p><strong>Tacos El Güero:</strong> Comida callejera, 100m al norte</p><p><strong>Pizzería Napoli:</strong> Pizza artesanal, 200m al sur</p>", icon="utensils", sort_order=6, is_active=True, audience_stage="in_stay"),
            ContentModule(hotel_id=hotel.id, module_type="events", title="Eventos y Actividades", subtitle="Qué hacer durante tu estancia", content_html="<p><strong>Viernes:</strong> Noche de karaoke en la azotea 20:00 hrs</p><p><strong>Sábados:</strong> Clase de yoga en la playa 08:00 hrs</p><p><strong>Domingos:</strong> Brunch en la terraza 10:00 hrs</p><p><strong>Todos los días:</strong> Tours guiados (consultar en recepción)</p>", icon="calendar", sort_order=7, is_active=True, audience_stage="in_stay"),
            ContentModule(hotel_id=hotel.id, module_type="checkout", title="Información de Checkout", subtitle="Prepara tu salida", content_html="<p><strong>Check-out:</strong> 12:00 hrs máximo</p><p><strong>Late checkout:</strong> Disponible previa solicitud (+$200 MXN)</p><p><strong>Depósito:</strong> Se revisa habitación. Deposito se libera en 3-5 días hábiles</p><p><strong>Transporte al aeropuerto:</strong> Solicitar antes de las 18:00 hrs del día anterior</p>", icon="log-out", sort_order=8, is_active=True, audience_stage="pre_checkout"),
        ]
        db.add_all(modules)

        # FAQs
        faqs = [
            FAQItem(hotel_id=hotel.id, question="¿A qué hora es el check-in?", answer="El check-in es a partir de las 15:00 hrs. Si llegas antes, puedes dejar tu equipaje en recepción y comenzar a disfrutar de las instalaciones.", sort_order=1, is_active=True),
            FAQItem(hotel_id=hotel.id, question="¿Puedo solicitar late checkout?", answer="Sí, el late checkout está disponible previa solicitud en recepción con un costo adicional de $200 MXN. Sujeto a disponibilidad.", sort_order=2, is_active=True),
            FAQItem(hotel_id=hotel.id, question="¿Hay estacionamiento disponible?", answer="Sí, contamos con estacionamiento gratuito para todos nuestros huéspedes. No es necesario reservar con anticipación.", sort_order=3, is_active=True),
            FAQItem(hotel_id=hotel.id, question="¿El hotel acepta mascotas?", answer="Lamentablemente no aceptamos mascotas en nuestras instalaciones. Si viajas con tu mascota, podemos recomendarte opciones cercanas.", sort_order=4, is_active=True),
            FAQItem(hotel_id=hotel.id, question="¿Cómo puedo contactar a recepción?", answer="Puedes llamar al +52 81 1234 5678, enviar un WhatsApp al mismo número, o acudir directamente a la recepción que está disponible 24 horas.", sort_order=5, is_active=True),
        ]
        db.add_all(faqs)

        # Promos
        promos = [
            Promo(hotel_id=hotel.id, title="Spa Day Pass", description="Disfruta de masaje relajante de 60 minutos, acceso a zona de vapor y té herbal. Válido para huéspedes y visitantes.", price_text="$899 MXN", cta_label="Reservar", cta_link="https://wa.me/528112345678?text=Quiero%20reservar%20Spa%20Day%20Pass", is_active=True),
            Promo(hotel_id=hotel.id, title="Paquete Romántico", description="Cena para dos en la terraza, botella de vino, flores y desayuno en cama. Perfecto para parejas.", price_text="$2,499 MXN", cta_label="Reservar", cta_link="https://wa.me/528112345678?text=Quiero%20el%20Paquete%20Romántico", is_active=True),
        ]
        db.add_all(promos)

        # QR Sources
        qr_sources = [
            QRSource(hotel_id=hotel.id, name="Lobby Principal", source_type="lobby", code="LOBBY-AZUL-001", url_generated="/g/hotel-azul?source=lobby", is_active=True),
            QRSource(hotel_id=hotel.id, name="Habitación", source_type="room", code="ROOM-AZUL-001", url_generated="/g/hotel-azul?source=room", is_active=True),
            QRSource(hotel_id=hotel.id, name="Pre-llegada", source_type="pre_arrival", code="PRE-AZUL-001", url_generated="/g/hotel-azul?source=pre_arrival", is_active=True),
        ]
        db.add_all(qr_sources)

        # Posts (Restaurants, Tours, Guide)
        posts = [
            # Restaurants
            Post(hotel_id=hotel.id, section="restaurant", title="Café Azul", subtitle="Desayunos y brunch gourmet", image_url="https://images.unsplash.com/photo-1554118811-1e0d58224f24?w=600&h=400&fit=crop", content_html="<p><strong>Café Azul</strong> es nuestro restaurante insignia dentro del hotel.</p><p>Ofrecemos desayunos estilo buffet y a la carta con ingredientes frescos y locales.</p><p><strong>Horario:</strong> 7:00 - 11:00 hrs</p><p><strong>Ubicación:</strong> Planta baja, junto al lobby</p><p><strong>Destacados:</strong> Huevos Benedictinos, Tostadas de atún, Jugos naturales</p>", button_text="Ver menú", button_url="https://wa.me/528112345678?text=Quiero%20ver%20el%20menú%20de%20Café%20Azul", icon="☕", sort_order=1, is_active=True),
            Post(hotel_id=hotel.id, section="restaurant", title="Restaurante El Mar", subtitle="Cocina mediterránea frente al mar", image_url="https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=600&h=400&fit=crop", content_html="<p><strong>Restaurante El Mar</strong> ofrece la mejor cocina mediterránea con vista al océano.</p><p><strong>Horario:</strong> 12:00 - 23:00 hrs</p><p><strong>Ubicación:</strong> Terraza del hotel, piso 2</p><p><strong>Destacados:</strong> Paella valenciana, Salmón al horno, Risotto de mariscos</p><p><strong>Chef recomendación:</strong>尝尝我们的招牌海鲜意面</p>", button_text="Reservar mesa", button_url="https://wa.me/528112345678?text=Quiero%20reservar%20en%20El%20Mar", icon="🍽️", sort_order=2, is_active=True),
            Post(hotel_id=hotel.id, section="restaurant", title="Sky Bar & Lounge", subtitle="Cócteles y tapas con vista panorámica", image_url="https://images.unsplash.com/photo-1470337458703-46ad1756a187?w=600&h=400&fit=crop", content_html="<p><strong>Sky Bar & Lounge</strong> en la azotea del hotel.</p><p>Disfruta de cócteles artesanales y tapas mientras contemplas la ciudad al atardecer.</p><p><strong>Horario:</strong> 18:00 - 01:00 hrs</p><p><strong>Ubicación:</strong> Azotea, piso 8</p><p><strong>Destacados:</strong> Mojito de mango, Margarita premium, Patatas bravas</p>", button_text="Reservar", button_url="https://wa.me/528112345678?text=Quiero%20reservar%20en%20Sky%20Bar", icon="🍸", sort_order=3, is_active=True),
            # Tours
            Post(hotel_id=hotel.id, section="tour", title="City Tour Histórico", subtitle="Recorre los monumentos más importantes", image_url="https://images.unsplash.com/photo-1499856871958-5b9627545d1a?w=600&h=400&fit=crop", content_html="<p>Descubre la historia y cultura de la ciudad en un recorrido guiado de 4 horas.</p><p><strong>Duración:</strong> 4 horas</p><p><strong>Salida:</strong> Lobby del hotel, 9:00 AM</p><p><strong>Incluye:</strong> Transporte, guía bilingüe, entrada a museos</p><p><strong>Itinerario:</strong></p><ul><li>Centro histórico y catedral</li><li>Museo de arte contemporáneo</li><li>Mercado artesanal</li><li>Plaza principal y fuente monumental</li></ul>", button_text="Reservar tour", button_url="https://wa.me/528112345678?text=Quiero%20reservar%20City%20Tour%20Histórico", icon="🏛️", sort_order=1, is_active=True),
            Post(hotel_id=hotel.id, section="tour", title="Aventura en Kayak", subtitle="Explora la costa desde el agua", image_url="https://images.unsplash.com/photo-1544551763-46a013bb70d5?w=600&h=400&fit=crop", content_html="<p>Vive una experiencia única navegando por la costa en kayak.</p><p><strong>Duración:</strong> 2.5 horas</p><p><strong>Salida:</strong> Playa principal, 8:00 AM</p><p><strong>Incluye:</strong> Kayak, chaleco salvavidas, instructor, snack</p><p><strong>Nivel:</strong> Principiante a intermedio</p><p><strong>Lo que verás:</strong> Acantilados, cuevas marinas, fauna silvestre</p>", button_text="Reservar", button_url="https://wa.me/528112345678?text=Quiero%20reservar%20Kayak", icon="🛶", sort_order=2, is_active=True),
            Post(hotel_id=hotel.id, section="tour", title="Ruta del Vino", subtitle="Visita viñedos y bodegas premium", image_url="https://images.unsplash.com/photo-1506377247377-2a5b3b417ebb?w=600&h=400&fit=crop", content_html="<p>Disfruta de una experiencia enoturística visitando las mejores bodegas de la región.</p><p><strong>Duración:</strong> 6 horas (día completo)</p><p><strong>Salida:</strong> Lobby del hotel, 10:00 AM</p><p><strong>Incluye:</strong> Transporte, degustación en 3 bodegas, almuerzo, guía especializado</p><p><strong>Bodegas visitadas:</strong></p><ul><li>Bodega Santa Rosa - Vinos tintos premium</li><li>Viñedo del Valle - Rosados y blancos</li><li>Casa Madero - Historia y tradición</li></ul>", button_text="Reservar", button_url="https://wa.me/528112345678?text=Quiero%20reservar%20Ruta%20del%20Vino", icon="🍷", sort_order=3, is_active=True),
            # Guide
            Post(hotel_id=hotel.id, section="guide", title="Playa Principal", subtitle="La playa más cercana al hotel", image_url="https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=600&h=400&fit=crop", content_html="<p><strong>Playa Principal</strong> está a solo 200 metros del hotel.</p><p><strong>Acceso:</strong> Caminata de 3 minutos por la Av. Costera</p><p><strong>Servicios:</strong> Sombrillas, sillas, duchas, baños públicos</p><p><strong>Restaurantes cercanos:</strong> 5 opciones de comida</p><p><strong>Consejo:</strong> Ve temprano para conseguir mejor lugar. La mejor hora es antes de las 10 AM.</p><p><strong>Seguridad:</strong> Playa vigilada de 8:00 a 18:00 hrs</p>", button_text="Ver en mapa", button_url="https://maps.google.com/?q=playa+principal", icon="🏖️", sort_order=1, is_active=True),
            Post(hotel_id=hotel.id, section="guide", title="Mercado Artesanal", subtitle="Artesanías y comida local auténtica", image_url="https://images.unsplash.com/photo-1555507036-ab1f4038024a?w=600&h=400&fit=crop", content_html="<p>El mercado artesanal es el lugar perfecto para llevar recuerdos únicos.</p><p><strong>Ubicación:</strong> Centro histórico, 10 minutos en taxi</p><p><strong>Horario:</strong> 8:00 - 18:00 hrs (lunes a domingo)</p><p><strong>Qué encontrarás:</strong></p><ul><li>Artesanías de barro y cerámica</li><li>Textiles bordados a mano</li><li>Joyería tradicional</li><li>Comida callejera: tacos, elotes, nieves</li></ul><p><strong>Tip:</strong> ¡Regatea con amabilidad! Es parte de la experiencia.</p>", button_text="Ver ubicación", button_url="https://maps.google.com/?q=mercado+artesanal", icon="🛍️", sort_order=2, is_active=True),
            Post(hotel_id=hotel.id, section="guide", title="Mirador del Cerro", subtitle="Vista panorámica espectacular al atardecer", image_url="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=600&h=400&fit=crop", content_html="<p>El Mirador del Cerro ofrece la mejor vista de la ciudad y el mar.</p><p><strong>Ubicación:</strong> Cerro San Miguel, 15 minutos en auto</p><p><strong>Mejor hora:</strong> Atardecer (consultar hora exacta en recepción)</p><p><strong>Actividades:</strong></p><ul><li>Fotografía panorámica</li><li>Caminata por senderos naturales</li><li>Observación de aves</li></ul><p><strong>Incluye:</strong> Transporte desde el hotel ida y vuelta</p><p><strong>Precio:</strong> $150 MXN por persona</p>", button_text="Reservar traslado", button_url="https://wa.me/528112345678?text=Quiero%20ir%20al%20Mirador", icon="🏔️", sort_order=3, is_active=True),
        ]
        db.add_all(posts)

        # Popup
        popup = Popup(
            hotel_id=hotel.id,
            title="¡Bienvenido!",
            message="Gracias por hospedarte en Hotel Azul. Descubre todos los servicios y promociones que tenemos para ti.",
            button_text="Ver ofertas",
            button_url="#promos",
            trigger_type="on_load",
            trigger_seconds=0,
            is_active=True,
            sort_order=1,
        )
        db.add(popup)

        db.commit()
        print("Seed data created successfully")
    except Exception as e:
        db.rollback()
        print(f"Seed error: {e}")
    finally:
        db.close()


# ── Startup ────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine, checkfirst=True)
    seed_data()


# ═══════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token = create_access_token({"sub": str(user.id)})
    return {
        "access_token": token,
        "user": {
            "id": user.id, "email": user.email, "name": user.name,
            "role": user.role, "hotel_id": user.hotel_id,
        },
    }


@app.get("/api/auth/me")
def get_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id, "email": user.email, "name": user.name,
        "role": user.role, "hotel_id": user.hotel_id,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC GUEST ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/guest/{slug}")
def get_guest_app(slug: str, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug, Hotel.is_active == True).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
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
    return {
        "hotel": hotel_to_dict(hotel),
        "modules": [module_to_dict(m) for m in modules],
        "faqs": [faq_to_dict(f) for f in faqs],
        "promos": [promo_to_dict(p) for p in promos],
        "posts": [post_to_dict(p) for p in posts],
        "popups": [popup_to_dict(p) for p in popups],
    }


@app.post("/api/guest/{slug}/onboarding")
def guest_onboarding(slug: str, req: OnboardingRequest, db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.slug == slug).first()
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel no encontrado")
    # Convert date strings to datetime objects
    check_in = None
    check_out = None
    if req.check_in_date:
        try:
            check_in = datetime.fromisoformat(req.check_in_date)
        except (ValueError, TypeError):
            pass
    if req.check_out_date:
        try:
            check_out = datetime.fromisoformat(req.check_out_date)
        except (ValueError, TypeError):
            pass
    lead = GuestLead(
        hotel_id=hotel.id, name=req.name, whatsapp=req.whatsapp, email=req.email,
        check_in_date=check_in, check_out_date=check_out,
        language=req.language, consent_contact=req.consent_contact,
        source_qr=req.source_qr, first_seen_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow(),
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return {"id": lead.id, "name": lead.name, "message": "Bienvenido/a, " + lead.name}


@app.post("/api/guest/events")
def log_event(req: EventRequest, db: Session = Depends(get_db)):
    log = AccessLog(
        hotel_id=req.hotel_id, guest_lead_id=req.guest_lead_id,
        event_type=req.event_type, page_view=req.page_view,
        source_qr=req.source_qr, user_agent=req.user_agent,
        created_at=datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════

def _get_hotel_id(user: User) -> int:
    """Get hotel_id for current user (super_admin uses first hotel)."""
    if user.hotel_id:
        return user.hotel_id
    return 1


@app.get("/api/admin/dashboard")
def admin_dashboard(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _get_hotel_id(user)
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
    return {
        "total_leads": total_leads,
        "leads_this_week": leads_this_week,
        "total_modules": total_modules,
        "total_faqs": total_faqs,
        "total_promos": total_promos,
        "total_popups": total_popups,
        "recent_leads": [lead_to_dict(l) for l in recent_leads],
    }


# ── Hotel profile ──────────────────────────────────────────────────────────

@app.get("/api/admin/hotel")
def get_hotel(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == _get_hotel_id(user)).first()
    return hotel_to_dict(hotel)


@app.put("/api/admin/hotel")
def update_hotel(data: HotelUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hotel = db.query(Hotel).filter(Hotel.id == _get_hotel_id(user)).first()
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(hotel, k, v)
    db.commit()
    return hotel_to_dict(hotel)


# ── Modules CRUD ───────────────────────────────────────────────────────────

@app.get("/api/admin/modules")
def list_modules(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    modules = db.query(ContentModule).filter(ContentModule.hotel_id == _get_hotel_id(user)).order_by(ContentModule.sort_order).all()
    return [module_to_dict(m) for m in modules]


@app.post("/api/admin/modules")
def create_module(data: ModuleCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    mod = ContentModule(hotel_id=_get_hotel_id(user), **data.model_dump())
    db.add(mod)
    db.commit()
    db.refresh(mod)
    return module_to_dict(mod)


@app.put("/api/admin/modules/{module_id}")
def update_module(module_id: int, data: ModuleUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    mod = db.query(ContentModule).filter(ContentModule.id == module_id, ContentModule.hotel_id == _get_hotel_id(user)).first()
    if not mod:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(mod, k, v)
    db.commit()
    return module_to_dict(mod)


@app.delete("/api/admin/modules/{module_id}")
def delete_module(module_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    mod = db.query(ContentModule).filter(ContentModule.id == module_id, ContentModule.hotel_id == _get_hotel_id(user)).first()
    if not mod:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    db.delete(mod)
    db.commit()
    return {"ok": True}


# ── FAQs CRUD ──────────────────────────────────────────────────────────────

@app.get("/api/admin/faqs")
def list_faqs(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faqs = db.query(FAQItem).filter(FAQItem.hotel_id == _get_hotel_id(user)).order_by(FAQItem.sort_order).all()
    return [faq_to_dict(f) for f in faqs]


@app.post("/api/admin/faqs")
def create_faq(data: FAQCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faq = FAQItem(hotel_id=_get_hotel_id(user), **data.model_dump())
    db.add(faq)
    db.commit()
    db.refresh(faq)
    return faq_to_dict(faq)


@app.put("/api/admin/faqs/{faq_id}")
def update_faq(faq_id: int, data: FAQUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faq = db.query(FAQItem).filter(FAQItem.id == faq_id, FAQItem.hotel_id == _get_hotel_id(user)).first()
    if not faq:
        raise HTTPException(status_code=404, detail="FAQ no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(faq, k, v)
    db.commit()
    return faq_to_dict(faq)


@app.delete("/api/admin/faqs/{faq_id}")
def delete_faq(faq_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    faq = db.query(FAQItem).filter(FAQItem.id == faq_id, FAQItem.hotel_id == _get_hotel_id(user)).first()
    if not faq:
        raise HTTPException(status_code=404, detail="FAQ no encontrado")
    db.delete(faq)
    db.commit()
    return {"ok": True}


# ── Promos CRUD ────────────────────────────────────────────────────────────

@app.get("/api/admin/promos")
def list_promos(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promos = db.query(Promo).filter(Promo.hotel_id == _get_hotel_id(user)).order_by(Promo.created_at.desc()).all()
    return [promo_to_dict(p) for p in promos]


@app.post("/api/admin/promos")
def create_promo(data: PromoCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    d = data.model_dump()
    if d.get("start_date"):
        d["start_date"] = datetime.fromisoformat(d["start_date"])
    if d.get("end_date"):
        d["end_date"] = datetime.fromisoformat(d["end_date"])
    promo = Promo(hotel_id=_get_hotel_id(user), **d)
    db.add(promo)
    db.commit()
    db.refresh(promo)
    return promo_to_dict(promo)


@app.put("/api/admin/promos/{promo_id}")
def update_promo(promo_id: int, data: PromoUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promo = db.query(Promo).filter(Promo.id == promo_id, Promo.hotel_id == _get_hotel_id(user)).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Promo no encontrada")
    d = data.model_dump(exclude_unset=True)
    if d.get("start_date"):
        d["start_date"] = datetime.fromisoformat(d["start_date"])
    if d.get("end_date"):
        d["end_date"] = datetime.fromisoformat(d["end_date"])
    for k, v in d.items():
        setattr(promo, k, v)
    db.commit()
    return promo_to_dict(promo)


@app.delete("/api/admin/promos/{promo_id}")
def delete_promo(promo_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    promo = db.query(Promo).filter(Promo.id == promo_id, Promo.hotel_id == _get_hotel_id(user)).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Promo no encontrada")
    db.delete(promo)
    db.commit()
    return {"ok": True}


# ── Posts CRUD ────────────────────────────────────────────────────────────

@app.get("/api/admin/posts")
def list_posts(section: Optional[str] = None, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _get_hotel_id(user)
    q = db.query(Post).filter(Post.hotel_id == hid)
    if section:
        q = q.filter(Post.section == section)
    posts = q.order_by(Post.sort_order).all()
    return [post_to_dict(p) for p in posts]


@app.post("/api/admin/posts")
def create_post(data: PostCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    post = Post(hotel_id=_get_hotel_id(user), **data.model_dump())
    db.add(post)
    db.commit()
    db.refresh(post)
    return post_to_dict(post)


@app.put("/api/admin/posts/{post_id}")
def update_post(post_id: int, data: PostUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.hotel_id == _get_hotel_id(user)).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(post, k, v)
    db.commit()
    return post_to_dict(post)


@app.delete("/api/admin/posts/{post_id}")
def delete_post(post_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.hotel_id == _get_hotel_id(user)).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post no encontrado")
    db.delete(post)
    db.commit()
    return {"ok": True}


# ── Popups CRUD ──────────────────────────────────────────────────────────

@app.get("/api/admin/popups")
def list_popups(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popups = db.query(Popup).filter(Popup.hotel_id == _get_hotel_id(user)).order_by(Popup.sort_order).all()
    return [popup_to_dict(p) for p in popups]


@app.post("/api/admin/popups")
def create_popup(data: PopupCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popup = Popup(hotel_id=_get_hotel_id(user), **data.model_dump())
    db.add(popup)
    db.commit()
    db.refresh(popup)
    return popup_to_dict(popup)


@app.put("/api/admin/popups/{popup_id}")
def update_popup(popup_id: int, data: PopupUpdate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popup = db.query(Popup).filter(Popup.id == popup_id, Popup.hotel_id == _get_hotel_id(user)).first()
    if not popup:
        raise HTTPException(status_code=404, detail="Popup no encontrado")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(popup, k, v)
    db.commit()
    return popup_to_dict(popup)


@app.delete("/api/admin/popups/{popup_id}")
def delete_popup(popup_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    popup = db.query(Popup).filter(Popup.id == popup_id, Popup.hotel_id == _get_hotel_id(user)).first()
    if not popup:
        raise HTTPException(status_code=404, detail="Popup no encontrado")
    db.delete(popup)
    db.commit()
    return {"ok": True}


# ── Image Upload ──────────────────────────────────────────────────────────

UPLOAD_DIR = STATIC_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/admin/upload")
async def upload_image(file: UploadFile = File(...)):
    """Upload image and return URL."""
    import uuid
    ext = Path(file.filename).suffix or ".jpg"
    filename = f"{uuid.uuid4().hex[:12]}{ext}"
    filepath = UPLOAD_DIR / filename
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)
    return {"url": f"/static/uploads/{filename}", "filename": filename}


# ── Leads ──────────────────────────────────────────────────────────────────

@app.get("/api/admin/leads")
def list_leads(limit: int = Query(50, le=200), offset: int = 0, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _get_hotel_id(user)
    total = db.query(func.count(GuestLead.id)).filter(GuestLead.hotel_id == hid).scalar()
    leads = db.query(GuestLead).filter(GuestLead.hotel_id == hid).order_by(GuestLead.created_at.desc()).offset(offset).limit(limit).all()
    return {"leads": [lead_to_dict(l) for l in leads], "total": total}


# ── QR Sources ─────────────────────────────────────────────────────────────

@app.get("/api/admin/qr")
def list_qr(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    sources = db.query(QRSource).filter(QRSource.hotel_id == _get_hotel_id(user)).all()
    return [{"id": s.id, "name": s.name, "source_type": s.source_type, "code": s.code, "url_generated": s.url_generated, "is_active": s.is_active} for s in sources]


@app.post("/api/admin/qr")
def create_qr(data: QRCreate, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    code = f"{data.source_type.upper()}-{secrets.token_hex(4).upper()}"
    hotel = db.query(Hotel).filter(Hotel.id == _get_hotel_id(user)).first()
    url = f"/g/{hotel.slug}?source={code}"
    src = QRSource(hotel_id=_get_hotel_id(user), name=data.name, source_type=data.source_type, code=code, url_generated=url, is_active=True)
    db.add(src)
    db.commit()
    db.refresh(src)
    # Generate QR image
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"{request.base_url.scheme}://{request.base_url.netloc}{url}" if request else url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    qr_path = QR_DIR / f"{code}.png"
    img.save(str(qr_path))
    return {"id": src.id, "name": src.name, "source_type": src.source_type, "code": src.code, "url_generated": src.url_generated}


@app.get("/api/admin/qr/{qr_id}/image")
def get_qr_image(qr_id: int, user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    src = db.query(QRSource).filter(QRSource.id == qr_id, QRSource.hotel_id == _get_hotel_id(user)).first()
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


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/api/admin/analytics")
def get_analytics(user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin)), db: Session = Depends(get_db)):
    hid = _get_hotel_id(user)
    # Leads by date (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    leads_by_date = db.query(
        func.date(GuestLead.created_at).label("date"),
        func.count(GuestLead.id).label("count")
    ).filter(GuestLead.hotel_id == hid, GuestLead.created_at >= thirty_days_ago).group_by(func.date(GuestLead.created_at)).all()

    # Events breakdown
    events = db.query(
        AccessLog.event_type, func.count(AccessLog.id)
    ).filter(AccessLog.hotel_id == hid).group_by(AccessLog.event_type).all()

    # Top modules (by access log page_view)
    top_modules = db.query(
        AccessLog.page_view, func.count(AccessLog.id)
    ).filter(AccessLog.hotel_id == hid, AccessLog.page_view.isnot(None)).group_by(AccessLog.page_view).order_by(func.count(AccessLog.id).desc()).limit(5).all()

    return {
        "leads_by_date": [{"date": str(r.date), "count": r.count} for r in leads_by_date],
        "events_breakdown": {r[0]: r[1] for r in events},
        "top_modules": [{"module": r[0], "views": r[1]} for r in top_modules],
    }


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
const CACHE_NAME = 'hostelflow-v1';
const urlsToCache = ['/', '/admin', '/manifest.json'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(urlsToCache)));
});
self.addEventListener('fetch', e => {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
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
