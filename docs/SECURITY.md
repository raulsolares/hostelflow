# Auditoría de Seguridad — HostelFlow

Estado: **P0 y P1 cerrados** (C1-C4, A1-A6, M1, M2, M4, B1 remediados — ver checklist al final y `BACKLOG.md`). Quedan abiertos M3 (GDPR/retención), M5 (Docker no-root) y los B2-B5 de calidad. Las secciones de hallazgos siguientes se conservan como registro de la auditoría original; el estado vigente es el del checklist.

## Resumen por severidad

| ID | Severidad | Título | Ubicación | Backlog |
|---|---|---|---|---|
| C1 | 🔴 Crítico | CORS abierto con credenciales | `main.py:72-78` | P0-6 |
| C2 | 🔴 Crítico | `SECRET_KEY` con fallback público | `main.py:31` | P0-4 |
| C3 | 🔴 Crítico | Credenciales admin por defecto débiles y publicadas | `main.py:390-404`, `DEPLOY.md` | P0-5 |
| C4 | 🔴 Crítico | Endpoint de upload sin auth ni validación | `main.py:861-871` | P0-3 |
| A1 | 🟠 Alto | XSS almacenado vía `content_html` | `guest.html:1136,1162` | P1-1 |
| A2 | 🟠 Alto | Ejecución de `custom_js`/`custom_css` del hotel | `guest.html:1082-1094` | P1-2 |
| A3 | 🟠 Alto | JWT de 30 días sin revocación | `main.py:33,61-65` | P1-3 |
| A4 | 🟠 Alto | Endpoint de eventos sin auth ni control de tenant | `main.py:586-596` | P1-4 |
| A5 | 🟠 Alto | Aislamiento multi-tenant con fallback a hotel 1 | `main.py:603-607` | P1-5 |
| A6 | 🟠 Alto | Login sin rate limiting | `main.py:498` | P1-6 |
| M1 | 🟡 Medio | Sin cabeceras de seguridad (CSP/HSTS/XFO) | (no existen) | P1-7 |
| M2 | 🟡 Medio | Bugs de runtime (500) en QR y `/sw.js` | `main.py:903,1017` | P0-1, P0-2 |
| M3 | 🟡 Medio | PII de huéspedes sin retención/borrado (GDPR) | `models.py:99-117` | P2-7 |
| M4 | 🟡 Medio | Validación de entrada laxa | `main.py:121-123,207-215,563-572` | P1-8 |
| M5 | 🟡 Medio | Contenedor Docker corre como root | `Dockerfile` | P2-5 |
| B1 | 🔵 Bajo | Dependencias con CVEs conocidos | `requirements.txt` | P1-9 |
| B2 | 🔵 Bajo | Sin tests reales | `verify.py` | P2-1 |
| B3 | 🔵 Bajo | Código muerto / imports sin usar | `main.py:6,16` | P2-8 |
| B4 | 🔵 Bajo | Duplicación masiva en CRUD | `main.py:653-852` | P2-3 |
| B5 | 🔵 Bajo | Logging por `print`, errores de seed silenciados | `main.py:479-481` | P2-4 |

---

## Críticos

### C1 — CORS totalmente abierto con credenciales
`main.py:72-78`: `allow_origins=["*"]` junto con `allow_credentials=True`. Es una combinación insegura (y que la especificación CORS prohíbe: con `*` el navegador ignora las credenciales, pero la intención declarada es peligrosa). Cualquier origen puede llamar a la API.

**Remediación:** restringir a los dominios reales vía variable de entorno.
```python
origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
```

### C2 — SECRET_KEY con fallback público
`main.py:31`: `SECRET_KEY = os.getenv("HOSTELFLOW_SECRET", "hostelflow-dev-secret-2026")`. Si la variable no se define (fácil de olvidar en deploy), se firma con un secreto conocido → **cualquiera puede forjar un JWT válido y suplantar al super_admin**.

**Remediación:** fallar el arranque si falta o es el valor por defecto en producción.
```python
SECRET_KEY = os.getenv("HOSTELFLOW_SECRET")
if not SECRET_KEY or SECRET_KEY == "hostelflow-dev-secret-2026":
    if os.getenv("ENV") == "production":
        raise RuntimeError("HOSTELFLOW_SECRET debe definirse con un valor fuerte en producción")
    SECRET_KEY = "hostelflow-dev-secret-2026"  # solo dev
```

### C3 — Credenciales admin por defecto débiles y documentadas
`main.py:390-404`: el seed crea `super_admin` y `hotel_admin` con contraseña `admin123`, además publicada en la documentación de deploy. Sin forzado de cambio en el primer login. Acceso administrativo trivial en cualquier instancia recién desplegada.

**Remediación:** generar contraseña aleatoria al sembrar e imprimirla una sola vez, o exigir cambio en el primer login; tomar las credenciales del seed de variables de entorno.
```python
seed_pw = os.getenv("SEED_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
# ...crear admin con hash_password(seed_pw)...
print(f"[SEED] super_admin creado. Password inicial: {seed_pw}  (cámbiala tras el primer login)")
```

### C4 — Endpoint de upload sin autenticación ni validación
`main.py:861-871`: `POST /api/admin/upload` **no tiene `Depends(require_role(...))`** (a diferencia del resto de `/api/admin/*`). Cualquier anónimo sube archivos. No valida MIME, tamaño ni extensión, y la extensión la controla el cliente (`file.filename`): se puede subir `.html`/`.svg` con JavaScript que luego se sirve desde el mismo origen en `/static/uploads/...` → **XSS almacenado** + relleno de disco (DoS).

**Remediación:** exigir auth, validar tipo/tamaño y no confiar en la extensión del cliente.
```python
ALLOWED = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
MAX_BYTES = 5 * 1024 * 1024

@app.post("/api/admin/upload")
async def upload_image(file: UploadFile = File(...),
                       user: User = Depends(require_role(UserRole.super_admin, UserRole.hotel_admin))):
    if file.content_type not in ALLOWED:
        raise HTTPException(415, "Tipo de archivo no permitido")
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "Archivo demasiado grande")
    filename = f"{uuid.uuid4().hex[:12]}{ALLOWED[file.content_type]}"
    (UPLOAD_DIR / filename).write_bytes(content)
    return {"url": f"/static/uploads/{filename}", "filename": filename}
```
Complementar con cabecera `X-Content-Type-Options: nosniff` (M1) sobre `/static`.

---

## Altos

### A1 — XSS almacenado vía content_html
`guest.html:1136` (`body.innerHTML = html` con `mod.content_html`) y `guest.html:1162` (`post-detail-content.innerHTML = post.content_html`). El resto de campos sí pasan por `escapeHtml()`, pero estos dos inyectan HTML crudo. Un admin (o un token forjado por C2) inyecta `<script>` que se ejecuta en el navegador de todos los huéspedes.

**Remediación:** sanitizar en el cliente con DOMPurify (`DOMPurify.sanitize(html)`) antes de asignar `innerHTML`, o sanitizar en el backend al guardar (p. ej. `bleach.clean` con allowlist de tags). Preferible sanitizar en el backend para que el dato en BD ya sea seguro.

### A2 — Ejecución de custom_js / custom_css del hotel
`guest.html:1082-1094`: `custom_css` y `custom_js` (editables en el admin, persistidos en `Hotel`) se inyectan y ejecutan tal cual en la app pública. Equivale a XSS almacenado permanente sobre todos los huéspedes; sin CSP no hay contención.

**Remediación:** decidir política de producto. Recomendado: eliminar `custom_js` (o limitarlo a super_admin con doble confirmación y auditoría), mantener `custom_css` pero saneado (sin `expression()`/`url(javascript:)`), y añadir CSP (M1) que prohíba scripts inline no confiables.

### A3 — JWT de larga vida sin revocación
`main.py:33` (`ACCESS_TOKEN_EXPIRE_DAYS = 30`) y `main.py:61-65`. Un token filtrado vale un mes; no hay refresh, `jti`, ni lista de revocación. Positivo: el rol se relee de BD, no del token.

**Remediación:** bajar el access token a 1-8 horas y añadir refresh token; o al menos incluir un `jti` y una tabla de revocación para logout de servidor.

### A4 — Endpoint de eventos sin auth ni control de tenant
`main.py:586-596`: acepta `hotel_id`, `guest_lead_id` y `user_agent` arbitrarios sin autenticación. Permite envenenar/inflar las analíticas de cualquier hotel y llenar `access_logs` (DoS de almacenamiento).

**Remediación:** mover a `/api/guest/{slug}/events`, derivar `hotel_id` del slug (validando que el hotel exista), verificar que `guest_lead_id` pertenece a ese hotel, y aplicar rate limiting.

### A5 — Aislamiento multi-tenant con fallback a hotel 1
`main.py:603-607`: `_get_hotel_id` devuelve `1` para cualquier usuario sin `hotel_id`. Un `hotel_admin` mal configurado (sin hotel asignado) accedería a los datos del hotel 1. El super_admin, además, no puede elegir hotel.

**Remediación:** si `user.hotel_id` es `None` y el rol no es super_admin → `403`. Para super_admin, exigir un selector de hotel explícito (parámetro `hotel_id` validado o cabecera de tenant) en lugar del hardcode.

### A6 — Login sin rate limiting
`main.py:498`: `/api/auth/login` sin throttling; combinado con C3 (`admin123`) es fuerza bruta trivial. Toda la app carece de rate limiting.

**Remediación:** integrar `slowapi` (limiter por IP) al menos en login y en endpoints públicos de escritura.
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
# @limiter.limit("5/minute") sobre login
```

---

## Medios

### M1 — Ausencia de cabeceras de seguridad
No hay CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`. Amplifica C4/A1/A2 y permite clickjacking del panel admin.

**Remediación:** middleware que añada cabeceras a toda respuesta; CSP restrictiva en `guest.html`/`admin.html` (bloquear scripts inline no confiables), `X-Frame-Options: DENY` en `/admin`, `nosniff` global, HSTS tras el proxy TLS.

### M2 — Bugs de runtime (500)
- `main.py:903` — `create_qr` usa `request.base_url` pero `request` no es parámetro → `NameError`, crear QR siempre falla con 500.
- `main.py:1017` — `serve_sw` usa `Response`, ausente de los imports de `fastapi.responses` (`main.py:16`) → `/sw.js` da 500 y rompe la PWA.

No son vulnerabilidades pero degradan la robustez (funcionalidad rota). Fixes en P0-1 y P0-2.

### M3 — PII de huéspedes sin retención ni borrado (GDPR)
`models.py:99-117`: `GuestLead` guarda nombre, email, WhatsApp y fechas de estancia en SQLite en texto plano. No hay endpoint de borrado/exportación (derechos de acceso/supresión), ni política de retención, ni cifrado en reposo. `DEPLOY.md` documenta copiar la `.db` completa como backup (PII sin proteger). Ver sección GDPR abajo.

### M4 — Validación de entrada laxa
`main.py:121-123` (`LoginRequest.email: str`) y `main.py:207-215` (`OnboardingRequest`) usan `str` en vez de `EmailStr`; `whatsapp` sin patrón; fechas parseadas con `try/except pass` silencioso (`main.py:563-572`) o `fromisoformat` sin control (promos). `consent_contact` por defecto `False` pero no se exige consentimiento explícito antes de guardar el lead.

**Remediación:** `EmailStr` (requiere `pydantic[email]`), validadores de teléfono/fecha, y devolver 422 en datos inválidos en lugar de descartarlos.

### M5 — Contenedor Docker como root
`Dockerfile`: sin `USER` no privilegiado; una escritura arbitraria (C4) se ejecuta como root dentro del contenedor.

**Remediación:** crear y usar un usuario no-root; ejecutar uvicorn con 1 worker mientras la BD sea SQLite.

---

## Bajos

- **B1 — Dependencias con CVEs.** `python-jose==3.3.0` (CVE-2024-33663 confusión de algoritmo, CVE-2024-33664 DoS JWE), `python-multipart==0.0.12` (CVE-2024-53981 DoS de parsing, relevante con el endpoint de upload). `passlib==1.7.4` sin mantenimiento activo. Actualizar y revisar con `pip-audit`.
- **B2 — Sin tests reales.** Solo `verify.py` (compila e importa) con rutas WSL rotas. Ver P2-1.
- **B3 — Código muerto.** `import io` y `StreamingResponse` (`main.py:6,16`) sin uso.
- **B4 — CRUD duplicado.** ~200 líneas idénticas en 5 recursos; un fix de seguridad debe replicarse 5 veces. Ver P2-3.
- **B5 — Logging por `print`.** `seed_data` traga excepciones con `print` (`main.py:479-481`); sin logging estructurado.

## Aspectos correctos (contexto)

- **Sin SQL crudo ni f-strings en queries**: todo vía ORM parametrizado → no se detectó SQLi.
- Contraseñas con **bcrypt** (`main.py:48`), nunca en claro.
- La mayoría de campos se escapan con `escapeHtml()` (guest) / `esc()` (admin).
- `.gitignore`/`.dockerignore` excluyen `.env` y `*.db`; no hay secretos de terceros versionados.
- El rol se revalida contra BD en cada request (no se confía en el claim del token).
- No se detectó modo debug de FastAPI activado ni stack traces expuestos al cliente.

---

## PII y cumplimiento (GDPR / privacidad)

`guest_leads` es datos personales. Para operar legalmente en la UE/Latam:

1. **Base legal y consentimiento:** no persistir el lead sin `consent_contact` explícito; registrar timestamp y versión de la política aceptada.
2. **Derecho de acceso/portabilidad:** endpoint admin para exportar los leads de un huésped (JSON/CSV).
3. **Derecho de supresión:** endpoint para borrar un lead y sus `access_logs` asociados.
4. **Retención:** política de borrado automático (p. ej. leads > 24 meses) vía tarea programada.
5. **Cifrado en reposo:** cifrar el volumen de la BD o migrar a un motor gestionado con cifrado; los backups (`.db`) deben cifrarse — hoy `DEPLOY.md` los copia en claro.
6. **Minimización:** revisar si se necesita almacenar `user_agent` completo en `access_logs`.

(Items 2-4 → backlog P2-7.)

---

## Checklist de despliegue seguro (producción)

Antes de exponer a internet, todos los P0 y P1 deben estar cerrados. Mínimo:

- [x] `HOSTELFLOW_SECRET` definido con valor fuerte (≥ 64 chars aleatorios); arranque falla si falta (C2)
- [x] Credenciales seed eliminadas o rotadas; sin `admin123` en ningún entorno accesible (C3)
- [x] `POST /api/admin/upload` autenticado y con validación de tipo/tamaño (C4)
- [x] CORS restringido a los dominios reales (C1)
- [x] Cabeceras de seguridad + CSP activas (M1) — nosniff, Referrer-Policy, CSP con allowlist de Google Fonts, XFO DENY (salvo `/g/*` con `frame-ancestors 'self'` para el preview del admin), HSTS condicionado a `x-forwarded-proto: https`
- [x] Rate limiting en login (5/min) y endpoints públicos de escritura (30/min); 429 en español (A6, A4)
- [x] JWT con expiración corta — 8 h (`ACCESS_TOKEN_EXPIRE_HOURS`), login devuelve `expires_in`; sin refresh token, el admin SPA re-loguea al 401 (A3)
- [x] `content_html` sanitizado con bleach (al guardar y al servir); `custom_js` ya no se sirve por la API; `custom_css` saneado (A1, A2)
- [x] Bugs de runtime corregidos (`create_qr`, `/sw.js`) (M2)
- [ ] HTTPS forzado (proxy con TLS) — HSTS ya listo en el middleware; falta el proxy TLS del deploy
- [ ] Backups de la BD cifrados; política de retención de PII definida (M3)
- [ ] Contenedor como usuario no-root, 1 worker con SQLite (M5)
- [x] Dependencias actualizadas y auditadas con `pip-audit` (B1) — python-jose→PyJWT 2.13, passlib eliminado (bcrypt 5 directo), python-multipart 0.0.32, fastapi 0.139 + starlette 1.3.1; `pip-audit`: "No known vulnerabilities found"
- [x] Validación de entrada estricta: EmailStr, patrón WhatsApp, fechas → 422 (M4)
- [x] Eventos de tracking con tenant derivado del slug + allowlist de `event_type`; endpoint legacy deprecated con la misma validación (A4)
