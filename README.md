# HostelFlow — Guía Digital de Huéspedes

HostelFlow es una plataforma SaaS multi-tenant que da a cada hotel una **guía digital de huéspedes** instalable como PWA, accesible mediante códigos QR, junto con un **panel de administración** para gestionar todo el contenido y capturar leads de huéspedes.

> ⚠️ **Estado del proyecto: MVP funcional, NO listo para producción.**
> Existen hallazgos de seguridad críticos documentados en [`docs/SECURITY.md`](docs/SECURITY.md) y un plan de trabajo priorizado en [`docs/BACKLOG.md`](docs/BACKLOG.md). No despliegues con tráfico real hasta cerrar los ítems **P0**.

---

## Features

| Área | Funcionalidad |
|---|---|
| 📱 App de huésped (PWA) | Guía por hotel en `/g/{slug}`: módulos de información (WiFi, horarios, reglas, ubicación…), promos, posts (restaurantes/tours/guía turística), FAQ, popups configurables, botón de contacto WhatsApp |
| 🌐 Multi-idioma | Interfaz de huésped en español e inglés (objeto `i18n` en `guest.html`) |
| 🧑‍💼 Panel admin | SPA en `/admin`: dashboard con métricas, CRUD de módulos/posts/FAQs/promos/popups, personalización de marca (colores, logo, CSS/JS custom), gestión de leads |
| 📷 Códigos QR | Generación de QR por punto de contacto (lobby, habitación, pre-llegada…) con tracking de origen (`?source=`) |
| 📊 Analytics | Registro de eventos de huésped (`access_logs`): vistas de página, vistas de módulo, leads por fecha |
| 🎯 Captura de leads | Onboarding opcional del huésped (nombre, WhatsApp, email, fechas de estancia, consentimiento de contacto) |
| 🏨 Multi-tenant | Todos los datos aislados por `hotel_id`; roles `super_admin` y `hotel_admin` |

## Stack

- **Backend:** Python 3.11 · FastAPI 0.115 · SQLAlchemy 2.0 · SQLite (por defecto)
- **Auth:** JWT (python-jose, HS256) · bcrypt vía passlib
- **Frontend:** HTML + CSS + JavaScript vanilla, embebido en `templates/admin.html` y `templates/guest.html` (sin build system)
- **Extras:** qrcode (generación de QR), PWA (manifest + service worker servidos por el backend)

## Estructura del repositorio

```
hotelflow/
├── main.py              # App FastAPI completa: config, auth, rutas, seed (~1030 líneas)
├── models.py            # Modelos SQLAlchemy (10 tablas)
├── requirements.txt     # Dependencias pineadas
├── Dockerfile           # Imagen python:3.11-slim + uvicorn
├── .env.example         # Plantilla de variables de entorno
├── templates/
│   ├── admin.html       # Panel de administración (SPA autónoma)
│   └── guest.html       # App de huésped (PWA autónoma)
├── static/
│   ├── qr/              # PNGs de QR generados (no versionados)
│   └── uploads/         # Imágenes subidas desde el admin (no versionadas)
├── docs/                # Documentación técnica (ver abajo)
├── DEPLOY.md            # Guía de despliegue (EasyPanel / VPS)
└── CLAUDE.md            # Guía operativa para agentes de desarrollo
```

Nota: el frontend vive **inline** dentro de los dos HTML de `templates/`. El directorio `frontend/` está vacío (residuo de scaffolding, pendiente de eliminar — ver backlog).

## Quickstart local

Requiere Python 3.11+.

```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Al primer arranque se crea `hostelflow.db` (SQLite) y se siembra un hotel demo ("Hotel Azul") con contenido de ejemplo y dos usuarios administradores.

### URLs clave

| URL | Qué es |
|---|---|
| `http://localhost:8000/admin` | Panel de administración |
| `http://localhost:8000/g/hotel-azul` | App de huésped del hotel demo |
| `http://localhost:8000/docs` | Documentación interactiva de la API (Swagger, generada por FastAPI) |

### Credenciales de desarrollo

El seed crea usuarios demo cuyas credenciales están en `seed_data()` (`main.py`). Son **exclusivamente para desarrollo local**: son públicas, débiles y su eliminación/rotación es un ítem P0 del backlog. **Nunca** las uses en un despliegue accesible desde internet.

## Variables de entorno

Copia `.env.example` a `.env` y ajusta:

| Variable | Default | Descripción |
|---|---|---|
| `HOSTELFLOW_SECRET` | ⚠️ fallback inseguro hardcodeado | Clave de firma JWT. **Obligatoria en producción** (genera una: `python -c "import secrets; print(secrets.token_urlsafe(64))"`) |
| `DATABASE_URL` | `sqlite:///./hostelflow.db` | Cadena de conexión SQLAlchemy. Nota: el `connect_args` actual es específico de SQLite; usar PostgreSQL requiere ajustar `main.py` |
| `PORT` | `8000` | Puerto del servidor |

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Arquitectura, modelo de datos, flujos clave, decisiones y limitaciones |
| [`docs/API.md`](docs/API.md) | Referencia completa de endpoints |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Auditoría de seguridad: hallazgos por severidad con remediación |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Backlog priorizado (P0–P3) con criterios de aceptación — **fuente de verdad de tareas pendientes** |
| [`DEPLOY.md`](DEPLOY.md) | Despliegue en VPS con EasyPanel + checklist de producción |
| [`CLAUDE.md`](CLAUDE.md) | Convenciones y gotchas para agentes de desarrollo |

## Cómo verificar cambios

No existe aún una suite de tests (es el ítem P2-1 del backlog). Mientras tanto:

1. Arranca la app (`python main.py`) y comprueba que el startup siembra/carga sin errores.
2. Ejercita el flujo completo: login en `/admin` → CRUD de un módulo → verlo reflejado en `/g/hotel-azul`.
3. `python -m py_compile main.py models.py` para validar sintaxis.

## Licencia

Proyecto privado. Todos los derechos reservados.
