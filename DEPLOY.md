# 🚀 HostelFlow — Deploy en EasyPanel (Contabo VPS)

> ⚠️ **Antes de exponer a internet:** cierra los ítems **P0 y P1** de [`docs/BACKLOG.md`](docs/BACKLOG.md) y repasa el [checklist de despliegue seguro](docs/SECURITY.md#checklist-de-despliegue-seguro-producción). El MVP tiene hallazgos de seguridad críticos abiertos.

## Requisitos
- VPS con EasyPanel instalado
- Docker habilitado en EasyPanel
- Puerto 8000 abierto (o el que uses)
- Un dominio para servir sobre HTTPS

## Paso 1: Subir el código al VPS

Opción A — Git (recomendado):
```bash
cd /opt
git clone https://github.com/tu-usuario/hostelflow.git
```

Opción B — copiar desde tu máquina local (ajusta la ruta de origen a la de tu equipo):
```bash
scp -r ./hotelflow/ root@TU_IP:/opt/hostelflow/
```

## Paso 2: Crear el contenedor en EasyPanel

1. EasyPanel → **Docker** → **New Container**
2. Nombre: `hostelflow`
3. Imagen: `custom` → **Build from Dockerfile**
4. Ruta: `/opt/hostelflow`
5. Puerto: `8000`
6. Variables de entorno (**obligatorias**):
   ```
   HOSTELFLOW_SECRET=<clave-fuerte-generada>
   ALLOWED_ORIGINS=https://hostelflow.tudominio.com
   PORT=8000
   ```
   Genera un secreto fuerte:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   ```
7. **Deploy**

> Nota: mientras la base de datos sea SQLite, ejecuta un solo worker de uvicorn para evitar contención de escritura (ver backlog P2-5). El Dockerfile actual usa 2 workers.

## Paso 3: Configurar dominio

En EasyPanel → **Proxy** → **Add Proxy**:
- Dominio: `hostelflow.tudominio.com`
- Container: `hostelflow`
- Port: `8000`

## Paso 4: SSL (HTTPS)

EasyPanel usa Let's Encrypt automáticamente al agregar un dominio. **HTTPS es obligatorio**: la app maneja tokens JWT y PII de huéspedes.

## Credenciales de administración

El seed crea un usuario administrador en el primer arranque. **No existe una contraseña por defecto documentada**: configúrala tú.

- Define `SEED_ADMIN_PASSWORD` como variable de entorno **antes del primer arranque**, o
- Deja que el seed genere una aleatoria y **léela una sola vez en los logs del contenedor** (`docker logs hostelflow`).

Cambia la contraseña tras el primer login. Nunca reutilices credenciales de desarrollo en un entorno accesible desde internet.

> Estado actual: la rotación de credenciales seed es el ítem **P0-5** del backlog. Hasta implementarlo, revisa `seed_data()` en `main.py` y asegúrate de que ninguna instancia pública conserve credenciales adivinables.

## Backup de la base de datos

`hostelflow.db` contiene **datos personales de huéspedes (PII)**. Los backups deben **cifrarse** y su acceso restringirse.

```bash
# En el VPS: genera una copia
docker exec hostelflow cp /app/hostelflow.db /app/hostelflow.db.bak
docker cp hostelflow:/app/hostelflow.db ./hostelflow-backup.db

# Cífrala antes de moverla fuera del servidor (ejemplo con gpg)
gpg --symmetric --cipher-algo AES256 ./hostelflow-backup.db
rm ./hostelflow-backup.db   # elimina la copia en claro
```

Define una política de retención de PII (backlog P2-7 / sección GDPR de `docs/SECURITY.md`).

## Actualizar

```bash
cd /opt/hostelflow
git pull
# En EasyPanel: redeploy el contenedor
```

> Recordatorio: no hay migraciones automáticas. Un cambio de esquema en `models.py` **no** se aplica a una BD existente (backlog P2-2). Planifica la migración antes de actualizar en producción.

## Checklist de producción

Consulta el [checklist completo en `docs/SECURITY.md`](docs/SECURITY.md#checklist-de-despliegue-seguro-producción). Mínimos imprescindibles:

- [ ] `HOSTELFLOW_SECRET` fuerte definido (arranque debe fallar si falta)
- [ ] `ALLOWED_ORIGINS` restringido a tu dominio
- [ ] Sin credenciales `admin123` en ninguna parte
- [ ] Endpoint `/api/admin/upload` autenticado y validado
- [ ] HTTPS forzado
- [ ] Backups cifrados + política de retención de PII
- [ ] Bugs de runtime corregidos (crear QR, `/sw.js`)
