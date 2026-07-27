# IDATA Sentinel — imagen única para los servicios `web` y `worker` (plan §11.2, §11.4).
#
# Cada servicio de Railway usa esta misma imagen y cambia solo su start command:
#   web     -> idata-sentinel serve --host 0.0.0.0 --port $PORT
#   worker  -> idata-sentinel monitor run --forever
#
# Las librerías nativas de WeasyPrint (Pango/Cairo/GDK-Pixbuf) son la razón por la
# que el proyecto no va a un runtime serverless: sin ellas no hay PDF.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install --no-install-recommends -y \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Las dependencias se instalan antes que el código para que un cambio de fuente
# no invalide esta capa. `--no-install-project` es imprescindible aquí: sin él,
# uv intentaría instalar el paquete cuando `idata_sentinel/` todavía no existe y
# el editable install quedaría apuntando al vacío.
COPY pyproject.toml uv.lock README.md ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev --no-install-project

# Ahora sí el código, y con él la instalación del propio paquete.
COPY idata_sentinel ./idata_sentinel
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

# Nunca correr como root: el contenedor hace peticiones a Internet.
# /data es el punto de montaje del volumen persistente. Sin él, la base vive
# dentro de la imagen y cada redeploy borraría la línea base de todos los
# clientes, dejando al monitoreo sin referencia contra la cual comparar.
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data \
    && chown -R sentinel:sentinel /app /data
USER sentinel

ENV IDATA_SENTINEL_DB=/data/sentinel.db
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/salud', timeout=4).status == 200 else 1)"

# Despliegue de un solo servicio: el monitoreo corre dentro del proceso web,
# porque un volumen persistente se monta en un único servicio y web y worker
# separados no podrían compartir la base SQLite.
#
# `serve` se niega a escuchar en 0.0.0.0 sin token, así que IDATA_SENTINEL_TOKEN
# es obligatorio en el despliegue.
CMD ["sh", "-c", "idata-sentinel serve --host 0.0.0.0 --port ${PORT:-8000} --con-monitoreo"]
