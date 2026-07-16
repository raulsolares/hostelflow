# HostelFlow — Spec de Producto Premium

Documento de ingeniería + producto que define el salto de "MVP competente" a "SaaS premium digno de un equipo de alto desempeño". Es la **fuente de verdad del contrato** para la ejecución en paralelo. Complementa `docs/BACKLOG.md` (deuda técnica) enfocándose en **valor de producto**.

## Visión

Un hotel entra al panel, **crea su propia app** de huésped, la viste con su marca (colores, logo, portada, tipografía, textos), genera sus **códigos QR**, y el huésped que escanea vive una **experiencia de onboarding premium** (no un popup) y puede **instalar la app** en su teléfono — con la marca del hotel — para usarla durante toda su estancia. Todo debe funcionar de punta a punta y verse de calidad suprema.

## Diagnóstico (estado actual, jul-2026)

Los P0 de seguridad ya están implementados. Lo que impide el nivel premium:

| # | Gap | Severidad | Área |
|---|---|---|---|
| G1 | Super_admin clavado al hotel `id=1` (`_get_hotel_id`, main.py:630); un hotel creado es inadministrable | 🔴 Bloqueante | Backend |
| G2 | Sin gestión de usuarios: un hotel nuevo no puede tener su `hotel_admin` | 🔴 Bloqueante | Backend |
| G3 | Manifest PWA global y hardcodeado (main.py:1081); el icono instalado es genérico, no del hotel | 🟠 Alto | Backend/PWA |
| G4 | Modelo `Hotel` sin campos de branding/onboarding/PWA ricos (solo 3 colores + `theme` string) | 🟠 Alto | Backend |
| G5 | Onboarding del huésped = formulario plano de 1 pantalla (guest.html:725) | 🟠 Alto | Guest |
| G6 | Instalación PWA: no detecta standalone, sin iOS, banner no persiste (guest.html:1481-1500) | 🟠 Alto | Guest |
| G7 | Theming parcial: `--primary-rgb` roto, ~6 vars, colores hardcodeados que ignoran la marca | 🟠 Alto | Guest |
| G8 | Admin sin selector de hotel activo ni preview en vivo (admin.html:760-798) | 🟠 Alto | Admin |
| G9 | Bugs que rompen páginas: `leadsLength` (admin.html:709), `case 'hotels'` duplicado (389/392), `Math.random()` demo (906-933), email demo hardcodeado (182) | 🟡 Medio | Admin |
| G10 | Sin endpoint para persistir eventos de instalación (`install_prompt_shown`/`installed_flag` nunca se escriben) | 🟡 Medio | Backend |

---

## CONTRATO — Backend (fuente de verdad)

El agente de backend implementa esto; los de guest/admin programan **contra este contrato**.

### 1. Contexto de hotel activo (resuelve G1)

`_get_hotel_id(user, request)` pasa a resolver el hotel así:
1. Si `hotel_admin`: siempre `user.hotel_id` (ignora cualquier override; 403 si es `None`).
2. Si `super_admin`: lee el header **`X-Hotel-Id`** (o query `?hotel_id=`) si viene y el hotel existe; si no viene, usa el primer hotel activo por id. Nunca hardcodear `1`.
3. Helper `_resolve_hotel_id(user, request)` centralizado; todos los endpoints admin lo usan.

El admin SPA enviará `X-Hotel-Id` en cada request cuando el usuario sea super_admin (ver contrato admin).

### 2. Gestión de hoteles (resuelve G1)

| Método | Ruta | Rol | Cuerpo / notas |
|---|---|---|---|
| GET | `/api/admin/hotels` | super_admin | Lista (ya existe) — añadir `logo_url`, `primary_color`, conteo de leads |
| POST | `/api/admin/hotels` | super_admin | `HotelUpdate` completo (usar branding recibido, no solo nombre) + opcional crear su `hotel_admin` |
| GET | `/api/admin/hotels/{id}` | super_admin | Perfil por id |
| PUT | `/api/admin/hotels/{id}` | super_admin | Editar por id |
| DELETE | `/api/admin/hotels/{id}` | super_admin | Archivar (`is_active=False`) — soft delete; nunca el hotel propio en uso |

### 3. Gestión de usuarios mínima (resuelve G2)

| Método | Ruta | Rol | Cuerpo |
|---|---|---|---|
| POST | `/api/admin/users` | super_admin | `{email, name, password, role, hotel_id}` — crea `hotel_admin` para un hotel |
| POST | `/api/admin/change-password` | cualquier user | `{current_password, new_password}` |

Validar email único; hashear con bcrypt; no exponer `password_hash`.

### 4. Campos nuevos en `Hotel` (resuelve G4, G7) — models.py

Añadir columnas (nullable, con defaults sensatos). Como no hay Alembic, en **dev se recrea la BD** (borrar `hostelflow.db`; el seed repuebla). El seed debe rellenar estos campos para el hotel demo.

```
# Branding extendido
font_family        String(120)  default "Inter"
text_color         String(7)    default "#1A1A2E"
bg_color           String(7)    default "#FFFFFF"
# Textos de la experiencia (por hotel, reemplazan strings hardcodeados)
welcome_headline   String(160)              # ej. "Bienvenido a Hotel Azul"
welcome_subtitle   String(300)              # ej. "Tu estancia, a un toque de distancia"
onboarding_enabled Boolean      default True
onboarding_title   String(160)  default "Cuéntanos de ti"
onboarding_subtitle String(300)
# Instalación PWA (por hotel)
pwa_enabled        Boolean      default True
pwa_short_name     String(60)               # cae a nombre si null
install_headline   String(160)  default "Instala la app del hotel"
install_subtitle   String(300)  default "Tenla a mano durante toda tu estancia"
```

`hotel_to_dict` (main.py) debe incluir todos estos campos en la respuesta de `GET /api/guest/{slug}` y `GET /api/admin/hotel`.

### 5. Manifest PWA por hotel (resuelve G3)

| Método | Ruta | Notas |
|---|---|---|
| GET | `/g/{slug}/manifest.webmanifest` | Manifest dinámico: `name`=hotel.nombre, `short_name`=pwa_short_name, `start_url`=`/g/{slug}`, `theme_color`=primary_color, `background_color`=bg_color, iconos del hotel (usar `logo_url` si es cuadrado/PNG; si no, un endpoint que genere PNG 192/512 desde el logo o un color sólido con inicial). |

`guest.html` referenciará `<link rel="manifest" href="/g/{slug}/manifest.webmanifest">` inyectado por el backend al servir la plantilla, o vía JS. Mantener `/manifest.json` global por compatibilidad.

### 6. Evento de instalación (resuelve G10)

| Método | Ruta | Cuerpo |
|---|---|---|
| POST | `/api/guest/{slug}/install-event` | `{guest_lead_id?, event: "prompt_shown"|"accepted"|"dismissed"|"installed"}` — actualiza flags en `GuestLead` y/o inserta `AccessLog`. Deriva `hotel_id` del slug. |

### 7. Endurecimiento de contrato (aprovechando el paso)

- `POST /api/guest/events` → mantener, pero derivar `hotel_id` del hotel del `source_qr`/slug cuando sea posible; no romper el front actual.
- Validar `source_type` de QR contra el set permitido.

---

## SPEC — Experiencia de onboarding premium (Guest, resuelve G5)

Reemplazar el formulario plano por un **flujo guiado de pantallas** con transiciones, progreso y copy de valor. No es un popup. Todos los textos salen de los campos del hotel (con fallback a i18n).

Pantallas (dentro de `guest.html`, como vistas conmutadas):

1. **Welcome (hero de marca).** Portada del hotel + overlay derivado del `primary_color` (NO navy hardcodeado). Logo, `welcome_headline`, `welcome_subtitle`. CTA "Comenzar". Botón "Instalar app" visible si aplica (ver PWA). Animaciones de entrada escalonadas.
2. **Valor / "Qué encontrarás".** Carrusel corto (2-3 tarjetas) generado de los módulos/servicios reales del hotel: WiFi, horarios, guía local, etc. Con iconos y microcopy. Indicadores de paso (dots/progress).
3. **Captura (opcional, premium).** Si `onboarding_enabled`: `onboarding_title`/`subtitle`, campos con micro-copy de por qué se piden ("para enviarte tu confirmación por WhatsApp"), consentimiento explícito claro. **Express path**: "Explorar sin registrarme" siempre disponible. Validación inline.
4. **Cierre + instalación.** Confirmación cálida ("¡Listo, {nombre}!") y, si la app no está instalada, la invitación premium a instalarla (ver PWA). Botón "Entrar a la app".

Requisitos de calidad: transiciones suaves entre pasos, barra/dots de progreso, skeleton loaders en carga de datos (no solo spinner), estados vacíos con estilo, todo traducido vía `t()` con detección de idioma inicial del navegador. Respetar `prefers-reduced-motion`.

---

## SPEC — Instalación PWA premium (Guest, resuelve G6)

1. **Detección de estado instalado:** si `window.matchMedia('(display-mode: standalone)').matches` o `navigator.standalone` → NO mostrar ninguna invitación a instalar; el usuario ya está en la app instalada.
2. **Android/Chromium:** capturar `beforeinstallprompt`, guardar el evento, mostrar CTA "Instalar app" en welcome y en el cierre; al aceptar, llamar `prompt()` y registrar el resultado en `/api/guest/{slug}/install-event`.
3. **iOS/Safari (sin beforeinstallprompt):** detectar iOS; mostrar una **hoja inferior (bottom sheet) con instrucciones visuales**: icono Compartir → "Añadir a pantalla de inicio", con ilustración/iconos, no un toast.
4. **Persistencia del descarte:** guardar en `localStorage` (`hf_pwa_dismissed_{slug}`) con **expiración** (p. ej. 24 h). El banner reaparece pasado ese tiempo — insistente pero no molesto, alineado con "mientras esté en el hotel".
5. **`appinstalled`:** escuchar el evento, ocultar toda invitación, registrar `installed` y mostrar confirmación.
6. **Manifest por hotel:** usar `/g/{slug}/manifest.webmanifest` para que el icono/nombre instalado sea del hotel (depende del backend G3).

Copy desde `install_headline`/`install_subtitle` del hotel, traducibles.

---

## SPEC — Theming / personalización total (Guest + Admin, resuelve G7, G8)

**Guest:**
- Al cargar el hotel, setear **todas** las CSS variables desde su marca: `--primary`, `--primary-light` (derivada), `--primary-rgb` (¡calcularla!), `--accent`, `--secondary`, `--text`, `--text-light`, `--bg`, `--bg-secondary`, `--border`, y `font-family`.
- Eliminar colores hardcodeados que deben seguir la marca: overlay del welcome (guest.html:123), badges de etapa (363-365, 642-644), gradientes de fallback (1157, 1301, 1331). Los colores "semánticos" fijos legítimos (WhatsApp #25D366) pueden quedarse.
- Fuente única de presets de tema compartida conceptualmente con el admin (evitar dos definiciones divergentes).

**Admin (resuelve G8):**
- **Selector de hotel activo** para super_admin en el topbar/sidebar: dropdown que lista los hoteles y fija el `X-Hotel-Id` usado por todas las llamadas admin. El "⚙️" de cada hotel debe fijar ese hotel como activo y navegar a su config (no al hotel actual).
- **Preview en vivo:** iframe con `/g/{slug}` (marco de teléfono) que refleja los cambios de branding/copy; refrescar al guardar.
- **Editor de branding completo:** colores (ya), + tipografía, `text_color`, `bg_color`, y **editores de copy**: `welcome_headline/subtitle`, `onboarding_title/subtitle`, `install_headline/subtitle`. Subida de logo/cover con el widget de upload (no solo URL).
- Wizard de alta de hotel: nombre + branding + (opcional) crear su admin, en el modal de creación.

---

## Correcciones de calidad (Admin, resuelve G9)

- `admin.html:709` — `leadsLength` → `leads.length` (la página Huéspedes hoy siempre falla).
- `admin.html:389/392` — eliminar el `case 'hotels'` duplicado en `loadPage`.
- `admin.html:906-933` — quitar los datos `Math.random()` de demo; mostrar estado vacío/real. Gráfica con una librería ligera o barras limpias reales.
- `admin.html:182` — quitar el email demo hardcodeado del login.
- `guest.html:428-435/1351` — unificar la flecha del FAQ a un SVG animado.
- Normalizar `nombre` vs `name` en guest.html.

---

## Alcance por agente (ejecución)

Partición por **archivo** para evitar colisiones. El backend va primero (define el contrato real y funcional); guest y admin corren **en paralelo** contra este contrato.

- **Agente BACKEND** — dueño de `main.py`, `models.py`, `requirements.txt`, seed, manifest/sw. Implementa contrato §1-§7. Recrea `hostelflow.db` en dev. Entrega la app arrancando sin errores y con el hotel demo enriquecido.
- **Agente GUEST** — dueño de `templates/guest.html`. Implementa onboarding premium, PWA install premium, theming total. Consume los campos nuevos del hotel del contrato §4/§5/§6.
- **Agente ADMIN** — dueño de `templates/admin.html`. Implementa selector de hotel (`X-Hotel-Id`), preview en vivo, editores de branding/copy, wizard de alta, y corrige los bugs G9.

## Definición de "hecho" (verificación end-to-end)

1. `python -m py_compile main.py models.py` sin errores; la app arranca (`python main.py`) y siembra sin excepciones.
2. Como super_admin: crear un hotel nuevo con su marca → seleccionarlo → editar su config/módulos/QR → todo apunta al hotel correcto (no al 1).
3. Abrir `/g/{nuevo-slug}`: la app se ve con la marca del hotel (colores, logo, textos), no con navy por defecto.
4. Onboarding: fluye por los pasos premium, con express path funcional; crea el lead.
5. PWA: en un navegador de escritorio no instalado, aparece la invitación; ya instalada (simulando standalone) NO aparece; el manifest de `/g/{slug}` trae nombre/colores del hotel.
6. Admin: páginas Huéspedes y Analytics cargan sin errores; sin datos aleatorios ni email demo.
7. Revisión de calidad visual de ambas apps antes de entregar.

---

## Estado de implementación (jul-2026) — ✅ ENTREGADO

Ejecutado con agentes en paralelo (backend → guest + admin) e integrado. Verificado end-to-end en navegador (Playwright) y con la suite de tests.

| Área | Estado | Evidencia de verificación |
|---|---|---|
| Backend §1-§7 (tenant activo, CRUD hoteles, usuarios, manifest por hotel, install-event, campos de marca) | ✅ | `X-Hotel-Id:2` → `GET /api/admin/hotel` devuelve hotel 2 (no el 1); sin header → hotel 1. `python -m py_compile` OK; app arranca y siembra sin errores |
| G5 Onboarding premium multi-paso + express path | ✅ | Carga limpia entra a `onboarding-flow` con headline/subtitle del hotel, dots de progreso, paso de valor y "Explorar sin registrarme" |
| G6 Instalación PWA (standalone/iOS/persistencia/appinstalled) | ✅ | Detección `display-mode: standalone`, `isIOS`, `appinstalled`, POST a `install-event`, `<link manifest>` por hotel inyectado |
| G7 Theming total | ✅ | Hotel Azul `--primary-rgb`="30,58,95"; Hotel Verde `--primary-rgb`="11,122,59" (derivados del hex real); gradientes de marca, sin navy hardcodeado |
| G8 Admin: selector de hotel + preview en vivo + editores de marca/copy + wizard | ✅ | Selector con 2 hoteles; Configuración con preview en marco de teléfono (`iframe /g/{slug}`); editores de copy y upload de logo/cover |
| G9 Bugs (Huéspedes, `case` duplicado, datos random, email demo) | ✅ | Huéspedes y Analytics cargan sin error; Analytics muestra estado vacío real |
| Integración: popup NO sobre el onboarding | ✅ | El popup `on_load` se difiere: ausente en `onboarding-flow`, presente en `home` (cumple "NO un popup" como primera experiencia) |
| Suite de tests de seguridad P0 | ✅ | `pytest tests/` → 16 passed |

Pendiente (fuera del alcance premium inmediato, ver `BACKLOG.md`): sanitización de `content_html`/`custom_js` (P1-1/P1-2), JWT de vida corta (P1-3), rate limiting (P1-6), CSP (P1-7), Alembic (P2-2).
