# Backlog — HostelFlow

**Fuente de verdad de tareas pendientes.** Priorizado P0 (bloquea producción) → P3 (mejoras de producto). Cada ítem lleva referencia al código, hallazgo de seguridad asociado (`docs/SECURITY.md`) y criterios de aceptación.

Convención de estado: `[ ]` pendiente · `[~]` en progreso · `[x]` hecho.

---

## P0 — Bugs y seguridad crítica (bloquean producción)

### [x] P0-1 · Corregir 500 al crear QR
`main.py:903` usa `request` que no es parámetro de `create_qr`.
- **Fix:** añadir `request: Request` a la firma de `create_qr` (ya se importa `Request` en `main.py:14`).
- **Aceptación:** `POST /api/admin/qr` crea el registro, genera el PNG con URL absoluta y devuelve 200; el QR abre `/g/{slug}?source=...`.

### [x] P0-2 · Corregir 500 en /sw.js
`main.py:1017` usa `Response` no importado.
- **Fix:** añadir `Response` al import de `fastapi.responses` (`main.py:16`).
- **Aceptación:** `GET /sw.js` devuelve 200 `application/javascript`; la PWA registra el service worker sin error en consola.

### [x] P0-3 · Autenticar y validar el endpoint de upload  · SEC C4
`main.py:861-871` sin auth ni validación.
- **Fix:** `Depends(require_role(...))`; validar `content_type` contra allowlist de imágenes, tamaño máx. (p. ej. 5 MB), derivar extensión del MIME (no de `file.filename`). Añadir `X-Content-Type-Options: nosniff` a `/static`.
- **Aceptación:** anónimo → 401; archivo no-imagen → 415; archivo >límite → 413; imagen válida autenticada → 200 con URL. No es posible subir `.html`/`.svg`.

### [x] P0-4 · Eliminar el fallback inseguro de SECRET_KEY  · SEC C2
`main.py:31`.
- **Fix:** si `HOSTELFLOW_SECRET` falta o es el valor por defecto y `ENV=production`, abortar el arranque; permitir el default solo en dev. Actualizar `.env.example` con instrucción de generación.
- **Aceptación:** arrancar en producción sin secreto fuerte lanza `RuntimeError`; en dev sigue funcionando con aviso.

### [x] P0-5 · Eliminar/rotar credenciales seed  · SEC C3
`main.py:390-404`.
- **Fix:** tomar la contraseña de `SEED_ADMIN_PASSWORD` o generar aleatoria e imprimirla una sola vez; documentar cambio en primer login. Quitar credenciales en claro de toda la documentación (hecho en `DEPLOY.md`).
- **Aceptación:** no existe `admin123` en el código ni docs; una instancia nueva no tiene contraseña de admin adivinable.

### [x] P0-6 · Cerrar CORS  · SEC C1
`main.py:72-78`.
- **Fix:** `allow_origins` desde `ALLOWED_ORIGINS` (lista por env), default a `http://localhost:8000` en dev.
- **Aceptación:** un origen no listado recibe rechazo CORS del navegador; los dominios configurados funcionan.

---

## P1 — Seguridad alta y robustez

### [x] P1-1 · Sanitizar content_html  · SEC A1
Cerrado en backend: `sanitize_html()` (bleach + css_sanitizer) con allowlist de tags/atributos/protocolos, aplicado al **guardar** (create/update de módulos y posts) y al **servir** (`module_to_dict`/`post_to_dict`, defensa en profundidad para datos previos).
- **Verificado:** tests `TestP1_1_SanitizeContentHtml` (script/onerror eliminados, formato legítimo conservado).

### [x] P1-2 · Política sobre custom_js/custom_css  · SEC A2
Decisión de producto: **`custom_js` deja de servirse** — eliminado de `hotel_to_dict`, de `GET /api/guest/{slug}` y del schema `HotelUpdate` (se ignora si llega; la columna sigue en BD por falta de migraciones). `custom_css` se mantiene pero **saneado** al guardar y al servir (`sanitize_custom_css`: sin `expression(`, `javascript:`, `@import`, `url()` con esquema no http/https, `</style`, `<script`). CSP añadida en P1-7.
- **Verificado:** tests `TestP1_2_CustomJsCss`.

### [x] P1-3 · JWT de vida corta  · SEC A3
Access token de **8 horas** (`ACCESS_TOKEN_EXPIRE_HOURS`, configurable por env). Login devuelve `expires_in` (segundos). Sin refresh token: el admin SPA re-loguea limpio al recibir 401 (decisión del contrato).
- **Verificado:** tests `TestP1_3_ShortLivedJWT` (exp ≈ 8h, `expires_in`, token expirado → 401).

### [x] P1-4 · Proteger/validar /api/guest/events  · SEC A4
Nuevo `POST /api/guest/{slug}/events`: hotel derivado del slug (404 si no existe activo), `event_type` contra allowlist (422 si no), `guest_lead_id` de otro hotel → null, `user_agent` truncado a 300. El endpoint viejo `POST /api/guest/events` queda **deprecated** con la misma validación (para clientes cacheados). Rate limiting 30/min (P1-6).
- **Verificado:** tests `TestP1_4_GuestEvents`.

### [x] P1-5 · Corregir aislamiento multi-tenant  · SEC A5
Resuelto en el trabajo premium (ver `PREMIUM_SPEC.md` §1). `_resolve_hotel_id(user, request)`: hotel_admin → 403 si no tiene `hotel_id`; super_admin → `X-Hotel-Id`/`?hotel_id=` validado, sin hardcode `1`.
- **Verificado:** con `X-Hotel-Id:2`, `GET /api/admin/hotel` devuelve el hotel 2; un hotel_admin no puede salir de su hotel.

### [x] P1-6 · Rate limiting en login  · SEC A6
`slowapi` integrado: **5/min** en `POST /api/auth/login`; **30/min** en públicos de escritura (`/api/guest/{slug}/events`, `/api/guest/events`, onboarding, install-event). Handler 429 con mensaje en español.
- **Verificado:** tests `TestP1_6_RateLimit` + prueba en vivo (401×4 → 429).

### [x] P1-7 · Cabeceras de seguridad + CSP  · SEC M1
`SecurityHeadersMiddleware`: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, CSP (permite fonts.googleapis.com/fonts.gstatic.com e `img-src https:`, verificados contra los templates), `X-Frame-Options: DENY` + `frame-ancestors 'none'` en general y `frame-ancestors 'self'` en `/g/*` (preview del admin), HSTS solo con `x-forwarded-proto: https`.
- **Verificado:** tests `TestP1_7_SecurityHeaders`.

### [x] P1-8 · Validación de entrada estricta  · SEC M4
`EmailStr` en `LoginRequest` y `OnboardingRequest` (`pydantic[email]`); `whatsapp` con patrón `^[+\d][\d\s\-()]{5,25}$`; fechas de onboarding y promos como `datetime` pydantic → 422 con detalle en formato inválido (se eliminó el `try/except pass` y el `fromisoformat` sin control).
- **Verificado:** tests `TestP1_8_StrictValidation`.

### [x] P1-9 · Actualizar dependencias con CVE  · SEC B1
`python-jose` → **PyJWT 2.13**, `passlib` eliminado (ya se usaba `bcrypt` directo; pinneado a 5.0.0), `python-multipart` 0.0.32, y `fastapi 0.139` + `starlette 1.3.1` (los CVEs restantes que reportó pip-audit eran de starlette).
- **Verificado:** `pip-audit` → "No known vulnerabilities found"; suite completa verde.

---

## P2 — Calidad e infraestructura

### [~] P2-1 · Suite de tests (pytest + httpx)  · SEC B2
- **Fix:** `pytest`, `httpx`, BD SQLite en memoria/temporal por test; matriz mínima: login OK/KO, `get_current_user`/`require_role`, un CRUD completo por recurso, aislamiento de tenant (un hotel_admin no ve datos de otro hotel), upload rechaza no-imágenes, onboarding crea lead. Eliminar `verify.py`.
- **Aceptación:** `pytest` verde; los tests de authz/tenant fallan si se reintroducen A5/C4.
- **Estado:** `tests/test_p0_security.py` (16 — P0), `tests/test_p1_hardening.py` (32 — P1) y `tests/test_p2_crud_tenant.py` (62 — CRUD completo por recurso con parametrize sobre modules/faqs/promos/posts/popups, aislamiento de tenant incluyendo intento de spoof de `X-Hotel-Id`, paginación/aislamiento de leads, upload no-imagen/SVG/oversize/válido, onboarding→lead, y endpoints premium hoteles/usuarios solo-super_admin). **110 tests verdes en total.** Falta solo eliminar `verify.py` (movido a P2-8) para cerrar del todo.

### [ ] P2-2 · Migraciones con Alembic
- **Fix:** inicializar Alembic, migración inicial desde los modelos, hacer `connect_args` condicional al driver (SQLite vs Postgres). Sustituir `create_all` en producción.
- **Aceptación:** un cambio de columna se aplica con `alembic upgrade` sin perder datos; cambiar `DATABASE_URL` a Postgres no rompe.

### [ ] P2-3 · Refactor del CRUD duplicado  · SEC B4
`main.py:653-852` y serializadores `*_to_dict`.
- **Fix:** factory/router genérico parametrizado por modelo + schemas, con `response_model` de Pydantic. Un solo lugar donde vive el patrón auth+tenant.
- **Aceptación:** comportamiento idéntico al actual; los 5 recursos comparten una implementación; los tests de P2-1 siguen verdes.

### [ ] P2-4 · Logging estructurado  · SEC B5
`main.py:479-481` y `print` sueltos.
- **Fix:** módulo `logging` con niveles; el seed loguea errores (no los traga); sin PII en logs.
- **Aceptación:** los eventos relevantes aparecen en logs con nivel adecuado; un fallo de seed es visible.

### [ ] P2-5 · Hardening del Dockerfile  · SEC M5
- **Fix:** usuario no-root; `--workers 1` mientras la BD sea SQLite (o migrar a Postgres y mantener multi-worker).
- **Aceptación:** el proceso corre como no-root; sin errores de contención de escritura de SQLite bajo carga concurrente básica.

### [ ] P2-6 · CI básica
- **Fix:** workflow (GitHub Actions) que corra lint (`ruff`) + `pytest` + `pip-audit` en cada push/PR.
- **Aceptación:** el pipeline pasa en verde y bloquea merge si fallan tests o hay CVEs altos.

### [ ] P2-7 · Endpoints GDPR de leads  · SEC M3
`models.py:99-117`.
- **Fix:** exportar (JSON/CSV) y borrar leads + `access_logs` asociados; documentar retención; no persistir lead sin consentimiento.
- **Aceptación:** un admin exporta y borra los datos de un huésped; el borrado elimina también sus logs.

### [ ] P2-8 · Limpieza de residuos  · SEC B3
- **Fix:** quitar imports muertos (`io`, `StreamingResponse`, `main.py:6,16`); borrar el directorio vacío `frontend/`; eliminar `verify.py` (reemplazado por P2-1); corregir rutas WSL en cualquier doc restante.
- **Aceptación:** `ruff` sin warnings de imports sin uso; no quedan rutas `/mnt/d/...` en el repo.

---

## P3 — Producto / premium

### [x] P6-0 · Pagos automatizados con Stripe (2026-07-19)
- Un solo plan por suscripción con **cupones nativos de Stripe** (`allow_promotion_codes` en Checkout; los cupones se crean en el dashboard de Stripe). Facturas manuales (fuera del sistema).
- `POST /api/admin/billing/checkout` (crea/reutiliza Customer, Checkout Session de suscripción), `GET /api/admin/billing/portal` (Customer Portal para tarjeta/cancelación), `POST /api/webhooks/stripe` (firma verificada, idempotente): `checkout.session.completed` → active; subscription canceled/unpaid/incomplete_expired → suspended; past_due mantiene active (gracia con reintentos de Stripe).
- **Exención de trial**: `/api/admin/billing/*` queda fuera del bloqueo de escrituras, para que un hotel vencido pueda pagar.
- Config: `STRIPE_SECRET_KEY`/`STRIPE_WEBHOOK_SECRET`/`STRIPE_PRICE_ID` (documentadas en .env.example); sin ellas los endpoints devuelven 503 y la UI degrada con toast.
- Admin: botón "Activar plan" en el banner de trial y card "Facturación" en Configuración; "Gestionar suscripción" vía portal; retorno `?billing=success|cancelled` con toasts; indicador "· Stripe" en Hoteles. Los IDs de Stripe nunca se exponen en el API del guest.
- 191 tests verdes (20 nuevos en `test_p6_billing.py`, Stripe mockeado sin red).
- **Pendiente operativo (manual)**: crear producto+precio en Stripe (modo test), copiar las 3 claves al .env, registrar el endpoint del webhook en el dashboard.

### [x] P5-0 · Permisos multi-hotel + módulo SaaS de prueba (2026-07-16)
- **Permisos por hotel**: tabla `user_hotels` (rol admin/editor por hotel, unique user+hotel); `_resolve_hotel_id` valida `X-Hotel-Id` contra los hoteles asignados (403 si no); rol **editor** = solo contenido (403 en config del hotel, usuarios, notificaciones push y creación de QR); `GET /api/auth/me` devuelve `hotels: [{id, nombre, slug, role}]`. CRUD completo de usuarios (`GET/POST/PUT/DELETE /api/admin/users` + reset-password) con salvaguardas: no tocar super_admins desde hotel_admin, no desactivar al último admin de un hotel, no auto-desactivarse. Página "Usuarios" en el admin con asignación multi-hotel y selector de hotel en topbar para usuarios con 2+ hoteles; el sidebar se filtra por rol efectivo.
- **SaaS trial**: `POST /api/signup` público (rate limit 3/min) crea hotel `plan=trial` (14 días) + admin + secciones default y auto-loguea; formulario "Crear cuenta gratis" en la pantalla de login. Trial vencido/suspendido: escrituras admin → 403 (lecturas ok), guest → `trial_expired` con pantalla amable multiidioma. Super_admin gestiona plan desde Hoteles (Activar/Extender 14 días/Suspender). `PUT /api/admin/hotel` NO expone plan/trial (un hotel no puede auto-extenderse).
- **Sidebar agrupado**: Dashboard/Analytics arriba + grupos CONTENIDO / MARKETING / GESTIÓN con etiquetas eyebrow; "Contenido"→"Publicaciones".
- Seed demo: `editor@casadelmar.com` (editor), `gerente@hostelflow.com` (admin casa-del-mar + editor ático), hotel `hotel-prueba-vencida` (trial expirado). Fix de revisión: datetimes UTC naive del backend parseados como UTC en el admin (`parseUtc`) — el banner decía 15 días en un trial de 14 y `timeAgo` corría desfasado.
- 171 tests verdes (31 nuevos en `test_p5_permissions_saas.py`).

### [x] P4-0 · Contenido: editor rico, secciones dinámicas, galería, i18n de contenido, headers (2026-07-16)
- **Editor de texto enriquecido** propio (contenteditable + toolbar, sin CDNs por CSP) en módulos y posts, con toggle de vista HTML. Fix del formulario de popups que enviaba campos inexistentes (`content_html`/`delay_seconds` → `message`/`trigger_seconds`) — era la causa de "los campos HTML no funcionan"; el backend siempre guardó UTF-8 y etiquetas correctamente.
- **Secciones dinámicas de posts** (modelo `Section`, CRUD multi-tenant, borrado protegido 409 si tiene posts); el seed crea restaurant/tour/guide para compat. Gestor en el admin + select dinámico en posts.
- **Galería** (modelo `GalleryImage`, CRUD): gestor admin con subida múltiple; en el guest strip en home + vista completa + lightbox propio (swipe/teclado/contador).
- **i18n de contenido**: columna JSON `i18n` en módulos/posts/faqs/promos/popups (idiomas es/en/fr/de/pt validados; `content_html` traducido pasa por `sanitize_html`); tabs de idioma en los forms del admin; helper `ct()` en el guest con fallback al idioma base; UI del guest extendida a fr/de/pt; selector de idiomas limitado a `hotel.supported_languages`.
- **Headers configurables**: `header_style` classic/centered/split/custom + `header_config` (knobs: show_name, overlay, bg_color, text_color, align, logo_pos); selector visual en admin donde tocar un knob cambia a "Personalizado" y los presets restauran valores; fallback a color cuando no hay cover.
- **Resort rehecho** ("Mosaico de color"): tiles de color pleno sin cajas/sombras, rotación de 4 colores derivada de la paleta del hotel con contraste por luminancia, tipografía Outfit, fotos sin caja en posts/promos.
- **Urban**: grid 2 col con tiles 120px sin empalmes, tab Explorar→Servicios con icono de cuadrícula. Etiquetas de etapa: `all`=permanente sin badge, formato unificado, labels en 5 idiomas (fix: el admin enviaba `during_stay`, valor inexistente — ahora `in_stay`).
- 137 tests verdes (22 nuevos en `test_p4_sections_gallery_i18n.py`).

### [x] P3-0 · Sistema de themes del guest + dashboard admin real (2026-07-15)
- **4 themes** (`Hotel.theme`: `boutique|urban|resort|zen`) que cambian layout/tipografía/navegación/densidad, con alias de compat para los 8 presets de color viejos (`ocean→resort`, etc.). Cascada: tokens del theme → paleta del preset viejo → overrides de color del hotel → `custom_css`. Urban: bottom-nav 4 tabs (solo en home); Zen: índice de secciones + lista; Resort: cards XL fotográficas. Seeds: un hotel por theme (casa-del-mar demuestra overrides).
- **Dashboard admin con datos reales**: `GET /api/admin/dashboard` ampliado (`visits_by_date`, `leads_by_date`, `push_subscribers`, `top_modules`), gráficos SVG sin librerías, actividad reciente con `recent_leads`. Analytics arreglado (consumía claves que el backend no devuelve). Selector visual de theme + preview iframe en Configuración.
- **UX guest**: push opt-in en el closing del onboarding (persistido en `hf_push_choice_{slug}`), strings al i18n, `role=button`/keyboard en cards, defaults de color del modelo a `None` (el theme aporta la paleta). Tracking corregido: el guest emitía `module_view`/`post_view` que la allowlist rechazaba — ahora `module_open`/`post_open` con el título como `page_view`, y `top_modules` cuenta solo `module_open`.

- [ ] **P3-1 · Más idiomas i18n.** Extender el objeto `i18n` de `guest.html` más allá de es/en; que respete `hotel.default_language`.
- [ ] **P3-2 · Selector de hotel para super_admin.** UI en el admin para cambiar de tenant (depende de P1-5).
- [ ] **P3-3 · Vigencia de promos.** Filtrar por `start_date`/`end_date` en la app de huésped.
- [ ] **P3-4 · Paginación consistente.** Aplicar el patrón limit/offset de leads a los listados que crezcan.
- [ ] **P3-5 · Backups automatizados y cifrados.** Job programado con retención (depende de M3).
- [ ] **P3-6 · Monitoreo/observabilidad.** Health check (`/health`), métricas básicas, alertas de error.
- [ ] **P3-7 · Iconos PWA.** Añadir `static/icon-192.png` y `icon-512.png` referenciados por `/manifest.json`.

---

## Orden de ataque sugerido

1. **P0 completo** (bugs + seguridad crítica) — desbloquea un deploy mínimamente seguro.
2. **P2-1 (tests)** en paralelo con P1 — cada fix de P1 nace con su test de regresión.
3. **P1 completo** — cierra la superficie de ataque alta.
4. **P2-2/P2-3** (Alembic + refactor) — base mantenible antes de crecer.
5. Resto de P2 y P3 según prioridad de producto.
