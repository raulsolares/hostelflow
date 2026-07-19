"""
HostelFlow — SQLAlchemy models (SQLAlchemy 2.0 declarative style).
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Shared base class for all models."""
    pass


class UserRole:
    """Role constants for User.role field."""
    super_admin = "super_admin"
    hotel_admin = "hotel_admin"


# ---------------------------------------------------------------------------
# Theme (CSS personalizado, creado por super_admin)
# ---------------------------------------------------------------------------
class Theme(Base):
    __tablename__ = "themes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    css_content = Column(Text, nullable=False, default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def __repr__(self) -> str:
        return f"<Theme id={self.id} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Hotel
# ---------------------------------------------------------------------------
class Hotel(Base):
    __tablename__ = "hotels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    nombre = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    logo_url = Column(String(512))
    cover_url = Column(String(512))
    primary_color = Column(String(7), default=None)
    secondary_color = Column(String(7), default=None)
    accent_color = Column(String(7), default=None)
    description = Column(Text)
    whatsapp = Column(String(30))
    email = Column(String(255))
    phone = Column(String(30))
    address = Column(Text)
    privacy_policy = Column(Text)
    default_language = Column(String(10), default="es")
    is_active = Column(Boolean, default=True)
    theme = Column(String(50), default="boutique")
    custom_css = Column(Text)
    custom_js = Column(Text)

    # Branding extendido (premium)
    font_family = Column(String(120), default="Inter")
    text_color = Column(String(7), default=None)
    bg_color = Column(String(7), default=None)

    # Theme CSS (FK a themes, nullable)
    theme_id = Column(Integer, ForeignKey("themes.id"), nullable=True)

    # Textos de la experiencia (por hotel, reemplazan strings hardcodeados)
    welcome_headline = Column(String(160))
    welcome_subtitle = Column(String(300))
    onboarding_enabled = Column(Boolean, default=True)
    onboarding_title = Column(String(160), default="Cuéntanos de ti")
    onboarding_subtitle = Column(String(300))

    # Instalación PWA (por hotel)
    pwa_enabled = Column(Boolean, default=True)
    pwa_short_name = Column(String(60))
    pwa_icon_url = Column(String(512))  # Icono personalizado para PWA
    install_headline = Column(String(160), default="Instala la app del hotel")
    install_subtitle = Column(String(300), default="Tenla a mano durante toda tu estancia")

    # Header configurable de la guía de huésped (P4)
    header_style = Column(String(20), default="classic")  # classic | centered | split | custom
    header_config = Column(Text, nullable=True)  # JSON string: {show_name, overlay, bg_color, text_color, align, logo_pos}
    supported_languages = Column(String(100), default="es")  # lista separada por comas, subconjunto de es,en,fr,de,pt

    # SaaS: plan y trial (P5)
    plan = Column(String(20), default="active")  # trial | active | suspended
    trial_ends_at = Column(DateTime, nullable=True)

    # SaaS: facturación con Stripe (P6)
    stripe_customer_id = Column(String(100), nullable=True)
    stripe_subscription_id = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="hotel")
    guest_leads = relationship("GuestLead", back_populates="hotel")
    content_modules = relationship("ContentModule", back_populates="hotel")
    faq_items = relationship("FAQItem", back_populates="hotel")
    promos = relationship("Promo", back_populates="hotel")
    access_logs = relationship("AccessLog", back_populates="hotel")
    qr_sources = relationship("QRSource", back_populates="hotel")
    posts = relationship("Post", back_populates="hotel")
    popups = relationship("Popup", back_populates="hotel")
    push_subscriptions = relationship("PushSubscription", back_populates="hotel")
    notifications = relationship("ScheduledNotification", back_populates="hotel")
    sections = relationship("Section", back_populates="hotel")
    gallery_images = relationship("GalleryImage", back_populates="hotel")

    def __repr__(self) -> str:
        return f"<Hotel id={self.id} slug={self.slug!r}>"


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="hotel_admin")  # hotel_admin | super_admin
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="users")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"


# ---------------------------------------------------------------------------
# UserHotel (permisos multi-hotel por usuario, P5)
# ---------------------------------------------------------------------------
class UserHotel(Base):
    """Asignación de un usuario a un hotel con un rol específico (admin|editor).

    Complementa (no reemplaza) `User.hotel_id`, que se mantiene como hotel
    principal legacy para compatibilidad hacia atrás. Un usuario sin filas en
    esta tabla pero con `hotel_id` sigue funcionando como hotel_admin de ese
    hotel (ver `_allowed_hotels` en main.py).
    """
    __tablename__ = "user_hotels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    role = Column(String(20), nullable=False, default="admin")  # admin | editor
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_user_hotels_user_id", "user_id"),
        Index("ix_user_hotels_hotel_id", "hotel_id"),
        UniqueConstraint("user_id", "hotel_id", name="uq_user_hotels_user_hotel"),
    )

    def __repr__(self) -> str:
        return f"<UserHotel user_id={self.user_id} hotel_id={self.hotel_id} role={self.role!r}>"


# ---------------------------------------------------------------------------
# GuestLead
# ---------------------------------------------------------------------------
class GuestLead(Base):
    __tablename__ = "guest_leads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    name = Column(String(255))
    whatsapp = Column(String(30))
    email = Column(String(255))
    check_in_date = Column(DateTime)
    check_out_date = Column(DateTime)
    language = Column(String(10))
    consent_contact = Column(Boolean, default=False)
    source_qr = Column(String(255))
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime)
    install_prompt_shown = Column(Boolean, default=False)
    installed_flag = Column(Boolean, default=False)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="guest_leads")
    access_logs = relationship("AccessLog", back_populates="guest_lead")

    __table_args__ = (
        Index("ix_guest_leads_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<GuestLead id={self.id} name={self.name!r}>"


# ---------------------------------------------------------------------------
# ContentModule
# ---------------------------------------------------------------------------
class ContentModule(Base):
    __tablename__ = "content_modules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    module_type = Column(
        String(20), nullable=False
    )  # wifi | hours | rules | location | services | dining | events | checkout | custom
    title = Column(String(255), nullable=False)
    subtitle = Column(String(255))
    content_html = Column(Text)
    image_url = Column(String(512))
    icon = Column(String(50))
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    audience_stage = Column(
        String(20), default="all"
    )  # pre_arrival | in_stay | pre_checkout | all
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"title": ..., "subtitle": ..., "content_html": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="content_modules")

    __table_args__ = (
        Index("ix_content_modules_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<ContentModule id={self.id} type={self.module_type!r}>"


# ---------------------------------------------------------------------------
# FAQItem
# ---------------------------------------------------------------------------
class FAQItem(Base):
    __tablename__ = "faq_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    question = Column(String(500), nullable=False)
    answer = Column(Text, nullable=False)
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"question": ..., "answer": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="faq_items")

    __table_args__ = (
        Index("ix_faq_items_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<FAQItem id={self.id} q={self.question[:40]!r}>"


# ---------------------------------------------------------------------------
# Promo
# ---------------------------------------------------------------------------
class Promo(Base):
    __tablename__ = "promos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    image_url = Column(String(512))
    price_text = Column(String(100))
    cta_label = Column(String(100))
    cta_link = Column(String(512))
    is_active = Column(Boolean, default=True)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"title": ..., "description": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="promos")

    __table_args__ = (
        Index("ix_promos_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<Promo id={self.id} title={self.title[:40]!r}>"


# ---------------------------------------------------------------------------
# AccessLog
# ---------------------------------------------------------------------------
class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    guest_lead_id = Column(Integer, ForeignKey("guest_leads.id"), nullable=True)
    source_qr = Column(String(255))
    page_view = Column(String(255))
    event_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    user_agent = Column(Text)

    hotel = relationship("Hotel", back_populates="access_logs")
    guest_lead = relationship("GuestLead", back_populates="access_logs")

    __table_args__ = (
        Index("ix_access_logs_hotel_id", "hotel_id"),
        Index("ix_access_logs_guest_lead_id", "guest_lead_id"),
    )

    def __repr__(self) -> str:
        return f"<AccessLog id={self.id} event={self.event_type!r}>"


# ---------------------------------------------------------------------------
# QRSource
# ---------------------------------------------------------------------------
class QRSource(Base):
    __tablename__ = "qr_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    name = Column(String(255), nullable=False)
    source_type = Column(
        String(20), nullable=False
    )  # lobby | room | pre_arrival | website | custom
    code = Column(String(64), unique=True, nullable=False, index=True)
    url_generated = Column(String(512))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="qr_sources")

    __table_args__ = (
        Index("ix_qr_sources_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<QRSource id={self.id} code={self.code!r}>"


# ---------------------------------------------------------------------------
# Post (Restaurants, Tours, Tourist Guide)
# ---------------------------------------------------------------------------
class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    section = Column(
        String(30), nullable=False
    )  # restaurant | tour | guide
    title = Column(String(255), nullable=False)
    subtitle = Column(String(255))
    image_url = Column(String(512))
    content_html = Column(Text)
    button_text = Column(String(100))
    button_url = Column(String(512))
    icon = Column(String(50))
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"title": ..., "subtitle": ..., "content_html": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="posts")

    __table_args__ = (
        Index("ix_posts_hotel_id", "hotel_id"),
        Index("ix_posts_section", "section"),
    )

    def __repr__(self) -> str:
        return f"<Post id={self.id} section={self.section!r} title={self.title[:40]!r}>"


# ---------------------------------------------------------------------------
# Popup
# ---------------------------------------------------------------------------
class Popup(Base):
    __tablename__ = "popups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text)
    image_url = Column(String(512))
    button_text = Column(String(100))
    button_url = Column(String(512))
    trigger_type = Column(String(20), default="on_load")  # on_load | after_seconds | manual
    trigger_seconds = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"title": ..., "message": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="popups")

    __table_args__ = (
        Index("ix_popups_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<Popup id={self.id} title={self.title[:40]!r}>"


# ---------------------------------------------------------------------------
# Section (agrupador de Post por slug, con nombre/icono configurables)
# ---------------------------------------------------------------------------
class Section(Base):
    __tablename__ = "sections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    slug = Column(String(50), nullable=False)
    name = Column(String(100), nullable=False)
    icon = Column(String(30))
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"name": ...}}
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="sections")

    __table_args__ = (
        Index("ix_sections_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<Section id={self.id} slug={self.slug!r}>"


# ---------------------------------------------------------------------------
# GalleryImage
# ---------------------------------------------------------------------------
class GalleryImage(Base):
    __tablename__ = "gallery_images"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    image_url = Column(String(500), nullable=False)
    caption = Column(String(200), nullable=True)
    i18n = Column(Text, nullable=True)  # JSON: {"en": {"caption": ...}}
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="gallery_images")

    __table_args__ = (
        Index("ix_gallery_images_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<GalleryImage id={self.id} hotel_id={self.hotel_id}>"


# ---------------------------------------------------------------------------
# PushSubscription (Web Push autoalojado)
# ---------------------------------------------------------------------------
class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    endpoint = Column(Text, unique=True, nullable=False)
    p256dh = Column(String(255), nullable=False)
    auth = Column(String(255), nullable=False)
    guest_lead_id = Column(Integer, ForeignKey("guest_leads.id"), nullable=True)
    lang = Column(String(5), default="es")
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="push_subscriptions")

    __table_args__ = (
        Index("ix_push_subscriptions_hotel_id", "hotel_id"),
    )

    def __repr__(self) -> str:
        return f"<PushSubscription id={self.id} hotel_id={self.hotel_id}>"


# ---------------------------------------------------------------------------
# ScheduledNotification (Web Push autoalojado)
# ---------------------------------------------------------------------------
class ScheduledNotification(Base):
    __tablename__ = "scheduled_notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id"), nullable=False)
    title = Column(String(120), nullable=False)
    body = Column(String(300), nullable=False)
    url = Column(String(500), nullable=True)
    scheduled_at = Column(DateTime, nullable=True)  # null = enviar ahora
    status = Column(String(20), default="scheduled")  # scheduled|sending|sent|cancelled|failed
    sent_at = Column(DateTime, nullable=True)
    sent_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    hotel = relationship("Hotel", back_populates="notifications")

    __table_args__ = (
        Index("ix_scheduled_notifications_hotel_id", "hotel_id"),
        Index("ix_scheduled_notifications_status_scheduled_at", "status", "scheduled_at"),
    )

    def __repr__(self) -> str:
        return f"<ScheduledNotification id={self.id} status={self.status!r}>"
