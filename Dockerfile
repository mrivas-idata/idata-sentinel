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
# no invalide la capa de dependencias.
COPY pyproject.toml uv.lock README.md ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev

COPY idata_sentinel ./idata_sentinel
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

# Nunca correr como root: el contenedor hace peticiones a Internet.
RUN useradd --create-home --uid 10001 sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/salud', timeout=4).status == 200 else 1)"

# Por defecto arranca el servicio web. `serve` se niega a escuchar en 0.0.0.0 sin
# token, así que IDATA_SENTINEL_TOKEN es obligatorio en el despliegue.
CMD ["sh", "-c", "idata-sentinel serve --host 0.0.0.0 --port ${PORT:-8000}"]
