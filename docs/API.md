# Referencia de API — HostelFlow

Base URL local: `http://localhost:8000`. FastAPI genera documentación interactiva en `/docs` (Swagger) y `/redoc`.

**Autenticación:** los endpoints marcados 🔒 requieren header `Authorization: Bearer <token>` (JWT obtenido en login) y rol `super_admin` o `hotel_admin`.

**Hotel activo (multi-tenant, P5):** los endpoints admin operan sobre un hotel resuelto por `_resolve_hotel_id(user, request)`:
- `super_admin` → header **`X-Hotel-Id: <id>`** (o query `?hotel_id=`) si viene y el hotel existe; si no, el primer hotel activo. El panel admin envía `X-Hotel-Id` en cada request cuando el usuario es super_admin.
- Resto de usuarios → sus hoteles permitidos se resuelven con `_allowed_hotels(db, user)` (tabla `user_hotels`, más `user.hotel_id` legacy si no tiene filas ahí). Si mandan `X-Hotel-Id`/`?hotel_id=` de un hotel **permitido** → lo usa; de uno **no permitido** → **403** `"No tienes acceso a este hotel"` (ya no hay fallback silencioso). Sin header → su hotel principal (`user.hotel_id`) si sigue permitido, si no el primero asignado. Sin ningún hotel asignado → 403.
- **Rol por hotel:** cada asignación en `user_hotels` tiene un rol `admin` o `editor` (`_role_in_hotel`). Un editor puede hacer CRUD de contenido (módulos/posts/secciones/galería/faqs/promos/popups), subir imágenes, ver dashboard/analytics/leads y cambiar su propia contraseña, pero recibe **403** `"No tienes permisos para esta acción"` en: `PUT /api/admin/hotel`, todo `/api/admin/users*`, todo `/api/admin/notifications*` y `POST /api/admin/qr` (el `GET` de QR sí está permitido). Esta restricción se aplica con la dependencia reutilizable `require_manager`.
- **Trial/plan (P5, objetivo 2):** si el hotel resuelto tiene `plan="suspended"`, o `plan="trial"` con `trial_ends_at` vencido, **toda escritura** (POST/PUT/DELETE/PATCH) a través de `_resolve_hotel_id` devuelve **403** `"El período de prueba ha terminado. Contacta a HostelFlow para activar tu plan."`. Las lecturas (GET) nunca se bloquean, para que el panel pueda seguir mostrando el aviso y el hotel.

**Formato de errores:** `{"detail": "<mensaje>"}` con códigos 401 (token inválido/ausente), 403 (rol insuficiente), 404 (recurso no encontrado en el tenant).

> ⚠️ Los endpoints marcados con **[BUG]** o **[SEC]** tienen defectos conocidos documentados en [`SECURITY.md`](SECURITY.md) y [`BACKLOG.md`](BACKLOG.md).

---

## Auth

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/auth/login` | — | Login. Rate limit **5/minuto por IP** (429 al exceder) |
| GET | `/api/auth/me` | 🔒 | Usuario del token actual |
| POST | `/api/signup` | — | **Nuevo (P5).** Registro público: crea hotel en trial 14 días + su hotel_admin. Rate limit **3/minuto por IP** |

### POST /api/auth/login

Body: `{"email": EmailStr, "password": str}` — email con formato inválido → 422.
Respuesta 200: `{"access_token": str, "expires_in": int, "user": {"id", "email", "name", "role", "hotel_id"}, "hotels": [{"id", "nombre", "slug", "role"}]}` — token HS256 con expiración de **8 horas** (configurable con env `ACCESS_TOKEN_EXPIRE_HOURS`); `expires_in` en segundos. No hay refresh token: al recibir 401 por expiración, el cliente debe re-loguear. `hotels` (P5) lista los hoteles del usuario con su rol (`admin`/`editor`); para `super_admin` incluye todos los hoteles con rol `admin`.
Respuesta 401: credenciales incorrectas. Respuesta 429: rate limit excedido.

### GET /api/auth/me

Respuesta 200: `{"id", "email", "name", "role", "hotel_id", "hotels": [{"id", "nombre", "slug", "role"}]}` (P5, mismo formato que en login).

### POST /api/signup

Body: `{"hotel_name": str, "email": EmailStr, "password": str (≥8 chars), "name": str}`.
- Email duplicado → **409**. Password corto → **422**.
- Crea `Hotel` con `plan="trial"`, `trial_ends_at = now() + 14 días`, `theme="boutique"`, slug único autogenerado desde `hotel_name`, y las 3 secciones default (`restaurant`, `tour`, `guide`, igual que el seed).
- Crea `User(role="hotel_admin")` dueño del hotel + fila en `user_hotels` con rol `admin`.
- Respuesta 200: mismo contrato que `POST /api/auth/login` (`access_token`, `expires_in`, `user`, `hotels`) para auto-login inmediato en el frontend.

---

## Público — Huésped

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/guest/{slug}` | — | Payload completo del hotel para la app de huésped |
| POST | `/api/guest/{slug}/onboarding` | — | Registra un `GuestLead`. Rate limit 30/min |
| POST | `/api/guest/{slug}/install-event` | — | Registra evento de instalación PWA. Body `{guest_lead_id?, event}` con `event ∈ {prompt_shown, accepted, dismissed, installed}`; deriva `hotel_id` del slug y actualiza `install_prompt_shown`/`installed_flag`. Rate limit 30/min |
| POST | `/api/guest/{slug}/events` | — | **Nuevo (P1-4).** Registra evento de analytics derivando el hotel del slug. Rate limit 30/min |
| POST | `/api/guest/events` | — | **DEPRECATED** — usar `/api/guest/{slug}/events`. Misma validación, deriva el hotel de `hotel_id` (404 si no existe). Rate limit 30/min |
| GET | `/api/qr/{code}` | — | Redirect 302 a `url_generated` del QR activo |
| GET | `/api/guest/{slug}/push/public-key` | — | Clave pública VAPID (base64url) para `applicationServerKey`. Rate limit 10/min |
| POST | `/api/guest/{slug}/push/subscribe` | — | Registra/actualiza una suscripción Web Push. Rate limit 10/min |
| POST | `/api/guest/{slug}/push/unsubscribe` | — | Borra la suscripción por `endpoint`. Rate limit 10/min |

### GET /api/guest/{slug}

Respuesta 200 (solo registros `is_active`):
```json
{
  "hotel": { "id", "nombre", "slug", "logo_url", "cover_url", "primary_color", "...", "custom_css", "header_style", "header_config", "supported_languages", "plan", "trial_ends_at" },
  "modules": [ { "id", "module_type", "title", "subtitle", "content_html", "image_url", "icon", "sort_order", "audience_stage", "i18n" } ],
  "faqs":    [ { "id", "question", "answer", "sort_order", "i18n" } ],
  "promos":  [ { "id", "title", "description", "image_url", "price_text", "cta_label", "cta_link", "start_date", "end_date", "i18n" } ],
  "posts":   [ { "id", "section", "title", "subtitle", "image_url", "content_html", "button_text", "button_url", "icon", "i18n" } ],
  "popups":  [ { "id", "title", "message", "image_url", "button_text", "button_url", "trigger_type", "trigger_seconds", "i18n" } ],
  "sections": [ { "id", "hotel_id", "slug", "name", "icon", "sort_order", "is_active", "i18n" } ],
  "gallery":  [ { "id", "hotel_id", "image_url", "caption", "sort_order", "is_active", "i18n", "created_at" } ]
}
```
404 si el slug no existe o el hotel está inactivo. `sections` y `gallery` solo incluyen registros `is_active`, ordenados por `sort_order`.

**Trial vencido / hotel suspendido (P5):** si `hotel.plan == "suspended"`, o `plan == "trial"` con `trial_ends_at` ya pasado, la respuesta 200 es en cambio:
```json
{"trial_expired": true, "hotel": {"nombre", "slug", "logo_url", "primary_color"}}
```
sin `modules`/`faqs`/`promos`/`posts`/`popups`/`sections`/`gallery` — el frontend debe detectar `trial_expired` y mostrar un aviso en vez del contenido.

Notas de seguridad (P1-1, P1-2): `custom_js` **ya no se sirve** (decisión de producto — SEC A2); `custom_css` se sirve saneado (sin `expression()`, `javascript:`, `@import`, `url()` con esquema no http/https, `</style`, `<script`); `content_html` de módulos y posts se sanitiza con allowlist (bleach) al guardar **y** al servir. La misma sanitización aplica al `content_html` dentro de `i18n` de módulos y posts.

### i18n de contenido (P4)

Los recursos `modules`, `faqs`, `promos`, `posts` y `popups` (además de `sections` y `gallery`) aceptan un campo opcional `i18n` en sus schemas `*Create`/`*Update`:

```json
{"i18n": {"en": {"title": "WiFi", "subtitle": "High speed", "content_html": "<p>...</p>"}}}
```

- Formato: `{idioma: {campo: valor}}`. Solo se incluyen los campos que tienen traducción; el idioma base del hotel (`Hotel.default_language`) sigue viviendo en las columnas normales (`title`, `content_html`, etc.).
- Idiomas permitidos: `es`, `en`, `fr`, `de`, `pt` — cualquier otra clave → **422** `"Idioma no soportado en i18n: <clave>"`.
- Cada valor de idioma debe ser un objeto (`{campo: valor}`) → 422 si no.
- El `content_html` dentro de `i18n` (módulos y posts) se sanea con la misma allowlist de `sanitize_html()` al guardar. `faqs`/`promos`/`popups` no tienen campos HTML, así que sus valores de `i18n` se persisten tal cual.
- Se guarda como JSON string en la columna `i18n` (Text, nullable) de cada tabla y se parsea al servir (`json.loads` con fallback a `None` si el registro está corrupto).

---

## Admin — Secciones y Galería (P4)

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/admin/sections` | 🔒 | Lista de secciones del hotel activo, ordenadas por `sort_order` |
| POST | `/api/admin/sections` | 🔒 | Crea una sección. Body: `{"name": str, "slug"?: str, "icon"?: str, "sort_order"?: int, "is_active"?: bool, "i18n"?: dict}` |
| PUT | `/api/admin/sections/{id}` | 🔒 | Edición parcial |
| DELETE | `/api/admin/sections/{id}` | 🔒 | Borra la sección. **409** `"La sección tiene publicaciones; muévelas o elimínalas primero"` si hay `Post` en el hotel con `Post.section == section.slug` |
| GET | `/api/admin/gallery` | 🔒 | Lista de imágenes de galería del hotel activo, ordenadas por `sort_order` |
| POST | `/api/admin/gallery` | 🔒 | Crea una imagen. Body: `{"image_url": str, "caption"?: str, "sort_order"?: int, "is_active"?: bool, "i18n"?: dict}`. La subida del archivo en sí reutiliza `POST /api/admin/upload` (el admin sube primero, luego crea el registro con la URL devuelta) |
| PUT | `/api/admin/gallery/{id}` | 🔒 | Edición parcial |
| DELETE | `/api/admin/gallery/{id}` | 🔒 | Borrado físico |

**Slug de sección:** si no viene `slug` en el body, se autogenera a partir de `name` (minúsculas, sin acentos, separado por guiones). Único por hotel: si ya existe, se agrega sufijo `-2`, `-3`, … (igual que el slug de hoteles). `Post.section` sigue siendo un string libre que **referencia** `Section.slug` — no hay FK física (sin migraciones); los posts de secciones ya sembradas (`restaurant`, `tour`, `guide`) siguen funcionando porque el seed crea esas 3 secciones para cada hotel.

Ambos recursos siguen el patrón estándar: `_resolve_hotel_id(user, request)`, 404 español si el id no pertenece al tenant, 401/403 sin auth/rol insuficiente.

Serializadores: `section_to_dict` → `{id, hotel_id, slug, name, icon, sort_order, is_active, i18n}`. `gallery_to_dict` → `{id, hotel_id, image_url, caption, sort_order, is_active, i18n, created_at}`.

---

## Admin — Header configurable y evento de galería (P4)

Campos nuevos en `HotelUpdate` / `hotel_to_dict` (ver `PUT /api/admin/hotel` y `PUT /api/admin/hotels/{id}`):

| Campo | Tipo | Validación |
|---|---|---|
| `header_style` | `str` | Uno de `classic \| centered \| split \| custom` → **422** si no |
| `header_config` | `dict` (se guarda como JSON string) | Solo claves permitidas: `show_name, overlay, bg_color, text_color, align, logo_pos` → **422** `"header_config contiene claves no permitidas: ..."` si hay alguna extra |
| `supported_languages` | `str` (CSV, se guarda tal cual) | Subconjunto no vacío de `es,en,fr,de,pt` → **422** si algún idioma no está soportado |

En las respuestas (`hotel_to_dict`, incluido `GET /api/guest/{slug}` → `hotel`), `header_config` se devuelve **parseado** como objeto (o `null`) y `supported_languages` se devuelve como **lista** de strings (aunque se persiste como CSV en la columna).

**Evento de tracking nuevo:** `gallery_open` se agregó a `ALLOWED_EVENT_TYPES` — válido en `POST /api/guest/{slug}/events` y en el endpoint legacy `POST /api/guest/events`.

### POST /api/guest/{slug}/onboarding

Body: `{"name": str, "whatsapp"?: str, "email"?: EmailStr, "check_in_date"?: str(ISO), "check_out_date"?: str(ISO), "language": str = "es", "consent_contact": bool = false, "source_qr"?: str}`
Respuesta 200: `{"id": int, "name": str, "message": str}`.
Validación estricta (P1-8): email inválido → 422; `whatsapp` debe cumplir `^[+\d][\d\s\-()]{5,25}$` → 422; fechas mal formadas → 422 con detalle.

### POST /api/guest/{slug}/events (nuevo — reemplaza a /api/guest/events)

Body: `{"event_type": str, "page_view"?: str, "guest_lead_id"?: int, "source_qr"?: str}`
- `hotel_id` se deriva del slug; 404 si no existe hotel activo.
- `event_type` validado contra allowlist: `page_view, module_open, faq_open, promo_click, whatsapp_click, install_prompt_shown, install_accepted, install_dismissed, installed, onboarding_complete, post_open, popup_shown, popup_click` — 422 si no.
- `guest_lead_id` que no pertenece al hotel → se guarda como `null`.
- `user_agent` se toma de la cabecera y se trunca a 300 caracteres.
Respuesta 200: `{"ok": true}`. Rate limit 30/min por IP (429).

### POST /api/guest/events (deprecated)

Body: `{"hotel_id": int, "guest_lead_id"?: int, "event_type": str, "page_view"?: str, "source_qr"?: str, "user_agent"?: str}` — se mantiene para clientes cacheados. Aplica la misma validación que el endpoint nuevo (404 si `hotel_id` no existe, 422 si `event_type` inválido, lead de otro hotel → null); el campo `user_agent` del body se ignora (se usa la cabecera).

---

## Web Push (notificaciones autoalojadas, sin proveedor externo)

Implementación con VAPID (claves EC P-256) y `pywebpush`. Sin migraciones: tablas nuevas `push_subscriptions` y `scheduled_notifications` (se crean solas con `create_all`). Un scheduler de fondo (`asyncio` en el proceso de la app) revisa cada 30 s las notificaciones con `status="scheduled"` y `scheduled_at` vencido, las reclama con un UPDATE condicional y las envía en un hilo aparte (`asyncio.to_thread`).

### GET /api/guest/{slug}/push/public-key

Respuesta 200: `{"public_key": str}` — clave pública VAPID en base64url sin padding, lista para pasar como `applicationServerKey` (convertida a `Uint8Array`) en `pushManager.subscribe()`. 404 español si el slug no existe o el hotel está inactivo.

### POST /api/guest/{slug}/push/subscribe

Body: `{"endpoint": str, "keys": {"p256dh": str, "auth": str}, "guest_lead_id"?: int, "lang": str = "es"}`.
- `endpoint` debe ser `https://` y ≤ 1000 caracteres (422 si no).
- Upsert por `endpoint`: si ya existe la suscripción, actualiza hotel/keys/lead/lang; si no, la crea.
- `guest_lead_id` que no pertenece al hotel → se guarda como `null` (igual que en `/events`).
Respuesta 200: `{"ok": true}`. Rate limit 10/min por IP.

### POST /api/guest/{slug}/push/unsubscribe

Body: `{"endpoint": str}`. Borra la suscripción si existe y pertenece al hotel del slug. Respuesta 200: `{"ok": true}` (idempotente, no falla si no existía). Rate limit 10/min.

### Admin — notificaciones (🔒, patrón `_resolve_hotel_id`)

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/admin/notifications` | Lista del hotel activo, ordenada por `created_at` desc |
| POST | `/api/admin/notifications` | Crea/programa una notificación |
| DELETE | `/api/admin/notifications/{id}` | Cancela una notificación en estado `scheduled` |
| GET | `/api/admin/push/stats` | `{"subscribers": int}` del hotel activo |

**POST /api/admin/notifications** — Body: `{"title": str, "body": str, "url"?: str, "scheduled_at"?: str(ISO)}`.
- `title` 1–120 caracteres, `body` 1–300 caracteres (422 si excede).
- `scheduled_at` no puede estar en el pasado (tolerancia 1 minuto) → 400 si lo está.
- `scheduled_at` ausente/`null` → se guarda `scheduled_at=now()` con `status="scheduled"`, así el scheduler la envía en el siguiente ciclo (≤30 s).
Respuesta 200: la notificación creada (ver forma abajo).

**DELETE /api/admin/notifications/{id}** — Solo si `status="scheduled"` → pasa a `"cancelled"`. 400 `"Solo se pueden cancelar notificaciones programadas"` si ya está `sending/sent/cancelled/failed`. 404 si el id no pertenece al hotel activo.

Forma de una notificación (`notification_to_dict`):
```json
{
  "id": int, "hotel_id": int, "title": str, "body": str, "url": str|null,
  "scheduled_at": str|null, "status": "scheduled|sending|sent|cancelled|failed",
  "sent_at": str|null, "sent_count": int, "fail_count": int, "created_at": str
}
```

### Envío y manejo de errores

`send_notification(id)` carga las suscripciones del hotel y llama a `pywebpush.webpush()` por cada una:
- Éxito → `sent_count += 1`.
- `WebPushException` con status 404/410 (endpoint muerto) → se borra la suscripción, no cuenta como fallo.
- Cualquier otro error → `fail_count += 1`.
- Sin suscriptores → `status="sent"` con `sent_count=0` de inmediato.
- Con suscriptores → `status="sent"` si `sent_count>0`, si no `status="failed"`.

### Configuración VAPID

Env vars `VAPID_PRIVATE_KEY`, `VAPID_PUBLIC_KEY`, `VAPID_CLAIMS_SUB` (ver `.env.example`). Si faltan, la app autogenera un par de claves EC P-256 al arrancar y las persiste en `vapid_keys.json` (raíz del repo, ignorado por git) para reutilizarlas entre reinicios en dev.

---

## Admin — Dashboard y perfil de hotel

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/admin/dashboard` | 🔒 | Métricas: `total_leads`, `leads_this_week`, `total_modules/faqs/promos/popups`, `recent_leads` (últimos 5), `visits_by_date`, `leads_by_date`, `push_subscribers`, `top_modules` (P3, ver abajo) |
| GET | `/api/admin/hotel` | 🔒 | Perfil completo del hotel activo |
| PUT | `/api/admin/hotel` | 🔒 | Actualización parcial del hotel activo (campos de `HotelUpdate`, ver abajo) |

Campos de `HotelUpdate` (todos opcionales): `nombre`, contacto (`address`, `phone`, `whatsapp`, `email`), branding (`logo_url`, `cover_url`, `primary_color`, `secondary_color`, `accent_color`, `font_family`, `text_color`, `bg_color`, `theme`), copy de la experiencia (`welcome_headline`, `welcome_subtitle`, `onboarding_enabled`, `onboarding_title`, `onboarding_subtitle`), PWA (`pwa_enabled`, `pwa_short_name`, `install_headline`, `install_subtitle`), `privacy_policy`, `default_language`, `custom_css`, header configurable y traducción (`header_style`, `header_config`, `supported_languages` — ver sección P4 abajo).

**Campos nuevos de `GET /api/admin/dashboard` (P3 — dashboard con themes):**

| Campo | Forma | Descripción |
|---|---|---|
| `visits_by_date` | `[{"date": "YYYY-MM-DD", "count": N}, ...]` | `AccessLog` con `event_type == "page_view"` de los últimos 30 días, agrupados por fecha (`func.date(AccessLog.created_at)`) |
| `leads_by_date` | `[{"date": "YYYY-MM-DD", "count": N}, ...]` | `GuestLead` de los últimos 30 días agrupados por fecha. Misma query que `GET /api/admin/analytics` — extraída al helper compartido `_leads_by_date(db, hid)` |
| `push_subscribers` | `int` | Igual que `GET /api/admin/push/stats` → `subscribers`: total de `PushSubscription` del hotel |
| `top_modules` | `[{"module": str, "views": N}, ...]` | Top 5 `AccessLog.page_view` más vistos. Misma query que `GET /api/admin/analytics` — extraída al helper compartido `_top_modules(db, hid)` |

Todos los campos nuevos se filtran por `_resolve_hotel_id(user, request)`, igual que el resto del endpoint. `GET /api/admin/analytics` no cambia de contrato (sigue devolviendo `events_breakdown` como dict y `top_modules` con las mismas claves `module`/`views`).

**Themes de hotel (P3):** el campo `Hotel.theme` tiene default `"boutique"` (antes `"ocean"`). Los hoteles del seed usan: `casa-del-mar` → `boutique`, `atico-corporativo` → `urban`, `el-refugio` → `zen`, `one-active` → `resort`. Los colores de branding (`primary_color`, `secondary_color`, `accent_color`, `text_color`, `bg_color`) ahora son `nullable` sin default no-nulo — si el hotel no los personaliza, el theme del frontend aporta la paleta. En el seed, solo `casa-del-mar` conserva colores explícitos como demo de que el override del hotel gana al theme.

**P1-2:** `custom_js` fue eliminado del schema y de todas las respuestas (si un cliente viejo lo envía, se ignora; la columna sigue en BD pero nunca sale por la API). `custom_css` se sanea al guardar y al servir.

---

## Admin — Gestión de hoteles y usuarios

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/admin/hotels` | 🔒 super_admin | Lista de hoteles con `id, nombre, slug, is_active, logo_url, primary_color, leads_count` |
| POST | `/api/admin/hotels` | 🔒 super_admin | Crea hotel con branding completo (`HotelUpdate`); autogenera `slug` único; devuelve el hotel (`plan="active"` por defecto) |
| GET | `/api/admin/hotels/{id}` | 🔒 super_admin | Perfil de un hotel por id |
| PUT | `/api/admin/hotels/{id}` | 🔒 super_admin | Edita un hotel por id. Body `HotelSuperUpdate` = `HotelUpdate` + **`plan`** (`trial\|active\|suspended`, 422 si no) + **`trial_ends_at`** (datetime) — P5, para activar/suspender/extender el trial. Estos dos campos **solo** existen en este endpoint, nunca en el PUT self-service |
| DELETE | `/api/admin/hotels/{id}` | 🔒 super_admin | Archiva (soft delete, `is_active=False`); no permite archivar el hotel activo en uso |
| GET | `/api/admin/users?hotel_id=` | 🔒 `require_manager` | **P5.** super_admin ve todos (filtro opcional `?hotel_id=`); admin de hotel ve usuarios con acceso a su hotel activo; editor → 403 |
| POST | `/api/admin/users` | 🔒 `require_manager` | **P5, contrato nuevo.** Body `{email, name, password (≥8), role: "hotel_admin"\|"super_admin", hotels: [{hotel_id, role: "admin"\|"editor"}]}`. Email único (409); hoteles deben existir (404); solo super_admin puede crear otro `super_admin` (403 si no); un hotel_admin actor solo puede asignar su propio hotel activo (403 si intenta otro) y si no manda `hotels` se asigna automáticamente como `admin` de su hotel; `role="hotel_admin"` sin `hotels` → 400. Nunca expone `password_hash` |
| PUT | `/api/admin/users/{id}` | 🔒 `require_manager` | **Nuevo (P5).** Body `{name?, is_active?, hotels?}` — `hotels` reemplaza todas las asignaciones. Un hotel_admin solo toca usuarios con acceso a su hotel activo y nunca a un `super_admin` (404 disfrazado); no puede quitarse a sí mismo el acceso a su hotel activo (400); desactivar (`is_active=false`) o quitar el rol `admin` del último admin de un hotel → 400 `"No puedes dejar el hotel sin un administrador activo"`; nadie puede autodesactivarse (400) |
| POST | `/api/admin/users/{id}/reset-password` | 🔒 `require_manager` | **Nuevo (P5).** Body `{new_password}` (≥8 chars, 400 si no). Mismas reglas de alcance que PUT |
| DELETE | `/api/admin/users/{id}` | 🔒 `require_manager` | **P5, ahora soft-delete** (`is_active=False`, antes no existía). Mismas reglas de alcance/último-admin; no auto-desactivación |
| POST | `/api/admin/change-password` | 🔒 | Cambia la propia contraseña (`{current_password, new_password}`; mínimo 8 chars) |

**`require_manager`** (P5): dependencia reutilizable que exige rol base `super_admin`/`hotel_admin` Y que el rol efectivo en el hotel activo (`_role_in_hotel`) no sea `editor`. Se usa en los endpoints de arriba, en `PUT /api/admin/hotel`, en todo `/api/admin/notifications*` y en `POST /api/admin/qr`.

**Modelo `UserHotel`** (tabla `user_hotels`, sin migraciones — requiere BD nueva): `user_id`, `hotel_id`, `role` (`admin`\|`editor`), `UNIQUE(user_id, hotel_id)`. `User.hotel_id` se mantiene como hotel principal legacy; un usuario sin filas en `user_hotels` sigue funcionando como `admin` de su `hotel_id` (`_allowed_hotels` añade ese fallback).

---

## Admin — CRUD de contenido

Los 5 recursos siguen el mismo patrón (filtrado por hotel del usuario, 404 si el id no pertenece al tenant):

| Recurso | Listar | Crear | Actualizar | Borrar |
|---|---|---|---|---|
| Módulos | `GET /api/admin/modules` | `POST /api/admin/modules` | `PUT /api/admin/modules/{id}` | `DELETE /api/admin/modules/{id}` |
| FAQs | `GET /api/admin/faqs` | `POST /api/admin/faqs` | `PUT /api/admin/faqs/{id}` | `DELETE /api/admin/faqs/{id}` |
| Promos | `GET /api/admin/promos` | `POST /api/admin/promos` | `PUT /api/admin/promos/{id}` | `DELETE /api/admin/promos/{id}` |
| Posts | `GET /api/admin/posts?section=` | `POST /api/admin/posts` | `PUT /api/admin/posts/{id}` | `DELETE /api/admin/posts/{id}` |
| Popups | `GET /api/admin/popups` | `POST /api/admin/popups` | `PUT /api/admin/popups/{id}` | `DELETE /api/admin/popups/{id}` |

Cuerpos: ver schemas `*Create` / `*Update` en `main.py` (~líneas 145-282). Los `Update` son parciales (`exclude_unset`). DELETE devuelve `{"ok": true}` (borrado físico, sin soft-delete).

Notas:
- `GET /api/admin/posts` acepta `?section=restaurant|tour|guide` (o cualquier `slug` de `Section` del hotel).
- `start_date`/`end_date` de promos se validan con pydantic (`datetime`): fecha mal formada → 422 con detalle (P1-8).
- Los campos `content_html` (módulos y posts) se **sanitizan con bleach** (allowlist de tags/atributos/protocolos, CSS de `style` filtrado) al crear/actualizar y también al servir (P1-1 / SEC A1 cerrado).
- Los 5 recursos aceptan `i18n` opcional (ver "i18n de contenido (P4)" arriba).

---

## Admin — Upload, Leads, QR, Analytics

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/admin/upload` | 🔒 | Sube archivo multipart, devuelve `{"url": "/static/uploads/<hex><ext>", "filename"}`. Requiere auth (401 si no), solo imágenes JPEG/PNG/WebP (415 si no), máximo 5 MB (413 si excede) |
| GET | `/api/admin/leads?limit=&offset=` | 🔒 | Leads paginados: `{"leads": [...], "total": int}` (`limit` máx. 200, default 50) |
| GET | `/api/admin/qr` | 🔒 | Lista de QR sources del hotel (editor incluido) |
| POST | `/api/admin/qr` | 🔒 `require_manager` | Crea QR source + genera PNG. Body: `{"name": str, "source_type": str}`. **P5:** editor → 403 |
| GET | `/api/admin/qr/{id}/image` | 🔒 | PNG del QR (lo regenera si no existe en disco) |
| GET | `/api/admin/analytics` | 🔒 | `{"leads_by_date": [30 días], "events_breakdown": {tipo: count}, "top_modules": [top 5 por page_view]}` |

---

## Static y PWA

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` y `/admin` | Sirven `templates/admin.html` |
| GET | `/g/{slug}` | Sirve `templates/guest.html` (el slug lo resuelve el JS del cliente) |
| GET | `/g/{slug}/manifest.webmanifest` | Manifest PWA **por hotel**: `name`, `short_name`, `start_url`/`scope`=`/g/{slug}`, `theme_color`=`primary_color`, `background_color`=`bg_color`, iconos del hotel |
| GET | `/g/{slug}/icon-{192,512}.png` | Icono PNG del hotel generado con PIL (color de marca + inicial) o desde `logo_url` |
| GET | `/manifest.json` | Manifiesto PWA global (compatibilidad) |
| GET | `/sw.js` | Service worker. Cache-first strategy |
| — | `/static/*` | Archivos estáticos (uploads, QRs) |

---

## Cambios de contrato planificados (ver BACKLOG.md)

| Cambio | Estado |
|---|---|
| `POST /api/admin/upload` ahora exige Bearer token y rechaza archivos no-imagen o >5 MB | ✅ Implementado (P0-3) |
| `POST /api/guest/events` → `/api/guest/{slug}/events` sin `hotel_id` en el body (el viejo queda deprecated con la misma validación) | ✅ Implementado (P1-4) |
| Fechas de promos devuelven 422 en formato inválido | ✅ Implementado (P1-8) |
| JWT expira en 8 h (`ACCESS_TOKEN_EXPIRE_HOURS`); login devuelve `expires_in`; el admin SPA re-loguea al recibir 401 | ✅ Implementado (P1-3) |
| `custom_js` eliminado de la API (schema y respuestas) | ✅ Implementado (P1-2) |
| Rate limiting: login 5/min; endpoints públicos de escritura 30/min → 429 `{"detail": "Demasiadas solicitudes…"}` | ✅ Implementado (P1-6) |
| Cabeceras de seguridad en toda respuesta (nosniff, Referrer-Policy, CSP, X-Frame-Options DENY salvo `/g/*` con `frame-ancestors 'self'`, HSTS tras proxy TLS) | ✅ Implementado (P1-7) |
| Permisos multi-hotel por rol (`user_hotels`: admin/editor), `POST /api/admin/users` rediseñado (`hotels: [...]` en vez de `hotel_id` único), nuevos `PUT/POST reset-password/DELETE` de usuarios, registro público `/api/signup` con trial 14 días y enforcement de plan/trial en escrituras | ✅ Implementado (P5) |
