# CLAUDE.md — Guía operativa para agentes de desarrollo

Proyecto: **HostelFlow Guest Guide** — SaaS multi-tenant de guías digitales de huéspedes para hoteles. FastAPI + SQLAlchemy + SQLite, frontend vanilla JS embebido en templates.

## Fuente de verdad de tareas

**`docs/BACKLOG.md`** contiene el plan de trabajo priorizado (P0–P3) con criterios de aceptación. Antes de implementar cualquier mejora, consúltalo; antes de dar el proyecto por "terminado", cierra los P0 y P1. La auditoría de seguridad completa con evidencia `archivo:línea` está en `docs/SECURITY.md`.

## Comandos

```powershell
# Arrancar en desarrollo (crea BD + seed al primer arranque)
python main.py                    # usa PORT (default 8000)

# Validar sintaxis rápida
python -m py_compile main.py models.py

# Resetear la BD de desarrollo (el seed se re-ejecuta al arrancar)
Remove-Item hostelflow.db
```

No hay suite de tests todavía (backlog P2-1). `verify.py` es un smoke check obsoleto con rutas WSL hardcodeadas (`/mnt/d/hermes/hostelflow/...`) que **no funciona en este entorno Windows** — está marcado para eliminación en el backlog; no lo uses como referencia.

## Mapa del código

- `main.py` — TODO el backend: config (líneas ~29-44), helpers de password/JWT (~46-65), app + CORS (~68-78), dependencias de auth (`get_current_user`, `require_role`, ~93-116), schemas Pydantic (~119-224), serializadores `*_to_dict` (~284-357), `seed_data()` (~362-483), startup (~488), rutas (auth ~498, guest público ~525, admin ~610, upload ~861, QR ~886, analytics ~929, static/PWA ~958-1021).
- `models.py` — 10 modelos SQLAlchemy 2.0. Multi-tenant: toda tabla hija tiene `hotel_id` FK indexada hacia `hotels`.
- `templates/admin.html` — SPA del panel admin (HTML+CSS+JS inline, ~960 líneas). Token JWT en `localStorage` (`hf_token`, `hf_user`); helper `api()` añade el header Bearer.
- `templates/guest.html` — PWA del huésped (~1570 líneas). Carga todo con `GET /api/guest/{slug}`; i18n es/en en el objeto `i18n`; helper `escapeHtml()` para escapar output.

## Gotchas críticos (leer antes de tocar código)

1. **Entorno Windows.** El repo vive en `D:\hermes\hotelflow`. Documentación antigua y `verify.py` contienen rutas WSL (`/mnt/d/hermes/hostelflow/`) que ya no aplican. Usa comandos PowerShell o rutas agnósticas.
2. **No hay migraciones.** El esquema se crea con `Base.metadata.create_all(checkfirst=True)` en startup. **Añadir/renombrar columnas en `models.py` NO altera una BD existente** — en dev, borra `hostelflow.db`; la solución real es Alembic (backlog P2-2).
3. **Bugs de runtime conocidos** (backlog P0, corrígelos si tocas esas zonas):
   - `main.py:903` — `create_qr` referencia `request` que no es parámetro de la función → `NameError` (500) al crear un QR. Fix: inyectar `request: Request` en la firma.
   - `main.py:1017` — `serve_sw` usa `Response`, que no está en los imports de `fastapi.responses` (línea 16) → `/sw.js` da 500 y rompe la PWA. Fix: añadir `Response` al import.
4. **El frontend está inline en `templates/*.html`**, no en `frontend/` (ese directorio está vacío). No hay build: editas el HTML y recargas.
5. **Campo `nombre` en `Hotel`.** El modelo mezcla español (`Hotel.nombre`) e inglés (todo lo demás). El schema `HotelUpdate` y los serializadores dependen de ese nombre — si lo renombras, es un cambio coordinado backend+frontend+BD (y sin migraciones, ver gotcha 2).
6. **SQLite con `check_same_thread=False`** y el Dockerfile arranca uvicorn con `--workers 2`: riesgo de contención de escritura. Con SQLite usa 1 worker (backlog P2-5).
7. **Seed con credenciales públicas débiles** (`admin123`) en `seed_data()`. Es un hallazgo crítico C3 de `docs/SECURITY.md` — no las propagues a más documentación ni las uses fuera de dev.
8. **`_get_hotel_id()` (`main.py:603`) hace fallback a hotel id=1** para usuarios sin `hotel_id`. Todo endpoint admin multi-tenant pasa por ahí; cualquier corrección de aislamiento de tenant empieza en esa función.
9. **El seed solo corre si no hay hoteles** (`if db.query(Hotel).count() > 0: return`) y sus errores se tragan con `print` — si el seed falla, la app arranca igual con BD a medias.

## Convenciones del código existente

- Backend monolítico en un solo archivo con secciones separadas por comentarios banner (`# ── Sección ──…`). Mantén ese estilo mientras no se haga el refactor a routers (backlog P2-3).
- Mensajes de error de la API en español (`"Credenciales incorrectas"`, `"Hotel no encontrado"`); identificadores en inglés.
- Endpoints admin protegidos con `Depends(require_role(UserRole.super_admin, UserRole.hotel_admin))` y filtrado por `_get_hotel_id(user)`. **Todo endpoint admin nuevo debe seguir ambos patrones** (el endpoint de upload actual no lo hace — es el hallazgo crítico C4).
- Serialización manual con funciones `*_to_dict` (no `response_model` de Pydantic).
- Patrón CRUD repetido 5 veces (modules/faqs/promos/posts/popups): si arreglas algo en uno, revisa los otros cuatro. El refactor a factory genérica es backlog P2-3.
- En frontend, todo dato dinámico interpolado en HTML debe pasar por `escapeHtml()` (guest) / `esc()` (admin). Excepción actual: `content_html` se inyecta sin sanitizar — hallazgo A1, no repitas el patrón.

## Al terminar cualquier cambio

1. `python -m py_compile main.py models.py`
2. Arranca la app y ejercita el flujo afectado a mano (login admin → CRUD → verlo en `/g/casa-del-mar`; los 4 slugs del seed son `casa-del-mar`, `atico-corporativo`, `el-refugio`, `one-active`, uno por theme).
3. Si tocaste seguridad/auth, revisa que el hallazgo correspondiente de `docs/SECURITY.md` quede cerrado y márcalo en `docs/BACKLOG.md`.
4. Actualiza `docs/API.md` si añadiste/cambiaste endpoints.
