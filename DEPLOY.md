# 🚀 HostelFlow - Deploy en EasyPanel (Contabo VPS)

## Requisitos
- VPS con EasyPanel instalado
- Docker habilitado en EasyPanel
- Puerto 8000 abierto (o el que uses)

## Paso 1: Subir el código al VPS

```bash
# Desde tu máquina local
scp -r /mnt/d/hermes/hostelflow/ root@TU_IP:/opt/hostelflow/
```

O usa Git si tienes el repo en GitHub:
```bash
cd /opt
git clone https://github.com/tu-usuario/hostelflow.git
```

## Paso 2: Crear el contenedor en EasyPanel

1. Ve a EasyPanel → **Docker** → **New Container**
2. Nombre: `hostelflow`
3. Imagen: `custom` → **Build from Dockerfile**
4. Ruta: `/opt/hostelflow`
5. Puerto: `8000`
6. Variables de entorno:
   ```
   HOSTELFLOW_SECRET=tu-clave-secreta-aqui
   PORT=8000
   ```
7. **Deploy**

## Paso 3: Configurar dominio (opcional)

En EasyPanel → **Proxy** → **Add Proxy**:
- Dominio: `hostelflow.tudominio.com`
- Container: `hostelflow`
- Port: `8000`

## Paso 4: SSL (HTTPS)

EasyPanel usa Let's Encrypt automáticamente al agregar un dominio.

## Credenciales por defecto

- **Admin General:** `admin@hostelflow.com` / `admin123`
- **Admin Hotel:** `admin@hotel-azul.com` / `admin123`

⚠️ **CAMBIA LAS CONTRASEÑAS** en producción.

## Backup de la base de datos

```bash
# En el VPS
docker exec hostelflow cp /app/hostelflow.db /app/hostelflow.db.bak
docker cp hostelflow:/app/hostelflow.db ./hostelflow-backup.db
```

## Actualizar

```bash
cd /opt/hostelflow
git pull
# En EasyPanel: redeploy el contenedor
```
