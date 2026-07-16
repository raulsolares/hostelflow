# Arquitectura — HostelFlow

Documento de referencia de la arquitectura actual (estado MVP). Las limitaciones señaladas aquí tienen su remediación planificada en [`BACKLOG.md`](BACKLOG.md).

## Visión general

Monolito FastAPI que sirve tanto la API JSON como los dos frontends (HTML autónomos). Multi-tenant por hotel: cada hotel tiene un `slug` público y todos sus datos cuelgan de `hotel_id`.

```
                    ┌─────────────────────────────────────────────┐
                    │              FastAPI (main.py)              │
                    │                                             │
  Huésped ──QR──▶   │  GET /g/{slug} ──▶ templates/guest.html     │
  (móvil, PWA)      │  GET /api/guest/{slug}      (público)       │
                    │  POST /api/guest/{slug}/onboarding          │
                    │  POST /api/guest/events                     │
                    │  GET /api/qr/{code} ──302──▶ /g/{slug}?src  │
                    │                                             │
  Admin hotel ──▶   │  GET /admin ──▶ templates/admin.html        │
  (navegador)       │  POST /api/auth/login ──▶ JWT (HS256)       │
                    │  /api/admin/* (Bearer + require_role)       │
                    │                                             │
                    │  /static (uploads, QR PNGs) · /manifest.json│
                    │  /sw.js (service worker)                    │
                    └──────────────────┬──────────────────────────┘
                                       │ SQLAlchemy 2.0
                                       ▼
                              SQLite (hostelflow.db)
```

- **Sin frontend framework ni build**: `admin.html` y `guest.html` son SPAs vanilla JS autocontenidas que consumen la API con `fetch`.
- **Sin capa de servicios**: las rutas acceden al ORM directamente.
- **Sin migraciones**: `Base.metadata.create_all(checkfirst=True)` en el evento startup (`main.py:488-491`), seguido de `seed_data()`.

## Modelo de datos

10 tablas. `hotels` es la raíz del tenant; toda tabla hija lleva `hotel_id` (FK indexada). Definiciones en `models.py`.

```
hotels 1──* users            (admins del hotel; hotel_id nullable para super_admin)
       1──* guest_leads      (huéspedes capturados en onboarding)
       1──* content_modules  (bloques de info: wifi, horarios, reglas…)
       1──* faq_items
       1──* promos
       1──* posts            (tarjetas: restaurant | tour | guide)
       1──* popups
       1──* qr_sources       (códigos QR con tracking de origen)
       1──* access_logs      (analytics; FK opcional a guest_leads)
```

| Tabla | Campos clave | Notas |
|---|---|---|
| `hotels` | `nombre`, `slug` (único), branding (`primary/secondary/accent_color`, `logo_url`, `cover_url`, `theme`), contacto (`whatsapp`, `email`, `phone`, `address`), `privacy_policy`, `default_language`, `custom_css`, `custom_js`, `is_active` | ⚠️ `nombre` en español (inconsistencia); `custom_js` es un riesgo de seguridad documentado (A2) |
| `users` | `email` (único), `password_hash` (bcrypt), `role`, `hotel_id` (nullable) | Roles: constantes string en `UserRole` (`models.py:27`): `super_admin`, `hotel_admin` |
| `guest_leads` | `name`, `whatsapp`, `email`, `check_in/out_date`, `language`, `consent_contact`, `source_qr`, `first/last_seen_at`, `install_prompt_shown`, `installed_flag`, `notes` | **Contiene PII** — ver sección GDPR de `SECURITY.md` |
| `content_modules` | `module_type` (wifi\|hours\|rules\|location\|services\|dining\|events\|checkout\|custom), `title`, `content_html`, `icon`, `sort_order`, `audience_stage` (pre_arrival\|in_stay\|pre_checkout\|all) | `content_html` se renderiza sin sanitizar en guest (A1) |
| `faq_items` | `question`, `answer`, `sort_order` | |
| `promos` | `title`, `description`, `price_text`, `cta_label`, `cta_link`, `start/end_date` | Fechas no se usan para filtrar vigencia hoy |
| `posts` | `section` (restaurant\|tour\|guide), `title`, `content_html`, `button_text/url`, `icon` | Índice extra por `section` |
| `popups` | `title`, `message`, `trigger_type` (on_load\|after_seconds\|manual), `trigger_seconds` | |
| `qr_sources` | `name`, `source_type` (lobby\|room\|pre_arrival\|website\|custom), `code` (único), `url_generated` | PNG generado en `static/qr/{code}.png` |
| `access_logs` | `event_type`, `page_view`, `source_qr`, `user_agent`, `guest_lead_id` (nullable) | Alimenta `/api/admin/analytics` |

Los valores tipo enum (`module_type`, `audience_stage`, `section`, `trigger_type`, roles) son **strings libres sin constraint** — solo convención documentada en comentarios de `models.py`.

## Flujos clave

### 1. Autenticación admin (JWT)

1. `POST /api/auth/login` (`main.py:498`) valida email/password contra bcrypt.
2. Se emite JWT HS256 con `sub` = user id y expiración de **30 días** (`ACCESS_TOKEN_EXPIRE_DAYS`, `main.py:33`; hallazgo A3).
3. El admin SPA guarda token y usuario en `localStorage` y envía `Authorization: Bearer` en cada request.
4. `get_current_user` (`main.py:93`) decodifica el token y **relee el usuario de BD** (rol y `is_active` siempre frescos; no hay revocación de tokens).
5. `require_role(*roles)` (`main.py:111`) autoriza por rol; todos los `/api/admin/*` lo usan (excepción conocida: upload, hallazgo C4).

**Aislamiento de tenant:** cada handler admin filtra por `_get_hotel_id(user)` (`main.py:603`), que devuelve `user.hotel_id` o hace fallback a `1` (hallazgo A5: el super_admin no puede elegir hotel; opera siempre sobre el hotel 1).

### 2. Recorrido del huésped

1. Escanea un QR → `GET /api/qr/{code}` (`main.py:958`) → redirect 302 a `/g/{slug}?source={code}`.
2. `/g/{slug}` sirve `guest.html`, que llama a `GET /api/guest/{slug}` (`main.py:525`) y recibe **todo el payload** del hotel (hotel + módulos + FAQs + promos + posts + popups activos) en una sola respuesta.
3. Vista de bienvenida → onboarding opcional (`POST /api/guest/{slug}/onboarding`, `main.py:555`) que crea un `GuestLead`.
4. La navegación registra eventos con `POST /api/guest/events` (`main.py:586`) hacia `access_logs` (hallazgo A4: el body incluye `hotel_id` sin validar).
5. El estado del huésped (lead id, idioma) se persiste en `localStorage` con clave por slug.

### 3. Arranque y seed

`startup()` (`main.py:488`): `create_all` + `seed_data()`. El seed (`main.py:362`) es idempotente por conteo de hoteles y crea el tenant demo completo (Hotel Azul, 2 usuarios, 8 módulos, 5 FAQs, 2 promos, 3 QR, 9 posts, 1 popup). Los errores del seed se capturan y solo se imprimen (`main.py:479-481`) — un seed a medias no impide arrancar.

### 4. PWA

- `GET /manifest.json` (`main.py:987`) genera el manifiesto dinámicamente.
- `GET /sw.js` (`main.py:1004`) sirve un service worker con cache básico. ⚠️ Hoy da 500 porque `Response` no está importado (bug P0-2 del backlog), por lo que la PWA no funciona.

## Decisiones y limitaciones actuales

| Decisión / estado | Implicación | Plan |
|---|---|---|
| Monolito de un archivo (`main.py`) | Simple de leer, pero CRUD repetido ×5 recursos y difícil de testear | Refactor a `APIRouter`s + factory CRUD (P2-3) |
| SQLite + `create_all`, sin migraciones | Cambios de esquema no se aplican a BDs existentes; multi-worker arriesgado | Alembic (P2-2); 1 worker o migrar a Postgres (P2-5) |
| `DATABASE_URL` configurable pero `connect_args={"check_same_thread": False}` fijo (`main.py:36`) | Cambiar a Postgres rompe sin tocar código | Hacer `connect_args` condicional al driver (P2-2) |
| JWT stateless de 30 días, sin refresh/revocación | Token robado válido un mes | Expiración corta + refresh (P1-3) |
| Frontend inline sin build | Cero tooling, pero sin componentes ni tests de UI; archivos de ~1000-1600 líneas | Aceptado por ahora; extraer JS/CSS a `static/` es opcional (P3) |
| Serialización manual `*_to_dict` en vez de `response_model` | Sin contrato tipado de respuestas ni validación de salida | Migrar a schemas Pydantic de respuesta (P2-3) |
| Sin tests, sin CI | Regresiones invisibles | pytest + httpx + CI (P2-1, P2-6) |
| CORS `*` con credenciales, sin cabeceras de seguridad ni rate limiting | Superficie de ataque amplia | P0-6, P1-6, P1-7 |
