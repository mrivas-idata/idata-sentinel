# IDATA Sentinel

Plataforma de diagnóstico de seguridad web de **IDATA Chile**. Evalúa la postura de
seguridad de un sitio y produce un reporte ejecutivo con marca IDATA, tanto para
clientes con contrato como para prospección con información pública.

## Qué hace

| Módulo | Alias | Qué resuelve |
|---|---|---|
| Identificación de vulnerabilidades | `vuln` | Cabeceras, TLS, cookies, fingerprint de stack y de componentes WordPress (plugins/temas) + CVE informativa, archivos de seguridad, exposición de información |
| Inventario de activos | `assets` | Subdominios por Certificate Transparency, DNS, seguridad de correo, takeover, CDN/WAF, superficie de ataque |
| Datos Personales (Ley 21.719) | `privacy` | Formularios con datos personales, consentimiento, rastreadores, transferencias internacionales, semáforo por principio |
| Monitoreo continuo | `monitor` | Línea base, diff entre escaneos, alertas por webhook, tendencia del score |

`idata-sentinel help <alias>` explica cada módulo en detalle: qué revisa, qué
hallazgos produce y bajo qué límites legales opera.

## Los dos modos

| Modo | Alcance | Autorización |
|---|---|---|
| **Prospección (pasivo)** | Solo información que el servidor ya publica | No requerida |
| **Auditoría (activo no destructivo)** | Añade las rutas y activos que declara el cliente | **Obligatoria y registrada** |

El modo auditoría amplía la superficie que el propio cliente declaró y suma
**checks de configuración activos no destructivos** (métodos HTTP vía `OPTIONS`,
política CORS, exigencia de autenticación en endpoints declarados, cadenas de
redirección) más la comparación contra un **baseline de hardening acordado**.
Todo es de solo lectura: solo emite `GET`/`HEAD`/`OPTIONS`, nunca muta estado.
Cada técnica activa exige habilitarse **por nombre** (`--active-check <id>`) más
la doble confirmación `--i-understand-active`: sin eso, `--mode audit` solo
expande superficie. En ningún modo se hace fuerza bruta, prueba de credenciales,
inyección, fuzzing de rutas, denegación de servicio ni explotación de CVE.

## Marco legal

En Chile aplica la **Ley 21.459** de delitos informáticos: escanear activamente un
sistema ajeno sin autorización es delito. El modo pasivo es legal porque solo lee
información publicada.

- El modo auditoría exige dominio en alcance, responsable que autoriza, cargo y
  número de contrato. Todo queda en `audit_log.json`, append-only.
- Sin autorización completa y dentro de alcance, el escaneo **degrada a pasivo**; nunca
  corre activo por omisión.
- Modo pasivo: ≥2 s entre requests al mismo host, User-Agent identificable
  (`IDATA-Sentinel/1.0 (+https://idatachile.com)`) y respeto de `robots.txt`.
- Ante un posible *subdomain takeover* se reporta el riesgo pero **nunca** se reclama el
  recurso huérfano.
- Si el objetivo responde con una página de verificación anti-bot, el escaneo lo
  detecta y **declara no evaluable** todo lo que dependa del contenido, en vez de
  describir esa página como si fuera el sitio. El desafío no se resuelve ni se
  evade: hacerlo sería evasión, prohibida en ambos modos.

## Instalación

```bash
uv sync
```

Para generar PDF hace falta WeasyPrint con sus librerías nativas (Pango, Cairo,
GDK-Pixbuf). El `Dockerfile` ya las incluye; en local puede que no estén y el resto
de la herramienta funciona igual.

## Uso

```bash
# Prospección pasiva
idata-sentinel scan https://prospecto.cl --modules vuln,assets

# Diagnóstico completo con PDF y registro para monitoreo
idata-sentinel scan https://cliente.cl --record --pdf informe.pdf

# Auditoría autorizada
idata-sentinel scan https://cliente.cl --mode audit \
    --i-have-authorization --authorized-by "Ana Pérez, CISO" --contract "OC-2026-118" \
    --allowed-domain cliente.cl --asset intranet.cliente.cl

# Monitoreo continuo
idata-sentinel monitor add https://cliente.cl --schedule weekly --webhook https://hooks.../x
idata-sentinel monitor status https://cliente.cl
idata-sentinel monitor run

# App web
idata-sentinel serve
```

`--json salida.json` exporta el contrato estable para integrar con CRM o dashboards.

### Documentos para el cliente

Cualquier Markdown se convierte en un PDF con identidad IDATA, reutilizando el
mismo motor que el reporte:

```bash
idata-sentinel doc docs/guia_cliente.md --pdf guia-cliente.pdf \
    --tipo "Guía del servicio" --version "1.0"
```

- Los bloques entre `<!-- interno:inicio -->` y `<!-- interno:fin -->` **se
  eliminan** de la versión entregable. `--con-notas-internas` genera la copia
  interna, que además lleva un aviso visible de no entregarla.
- Los `[[dobles corchetes]]` marcan datos por completar. El comando los lista
  antes de generar el archivo, para que nadie entregue un documento con huecos.
- Fondo claro y una sección por página: es un documento para leer, anotar e
  imprimir, no una pieza de presentación como el reporte.

[docs/guia_cliente.md](docs/guia_cliente.md) es la guía que se entrega al cliente
al contratar el servicio: 10 pasos, formulario de autorización, checklist de
preparación, glosario y el detalle de las peticiones que verá su SOC.

### Cifrado en reposo

Los hallazgos describen las debilidades del cliente: si la base se filtra, el
atacante recibe el mapa ya hecho. Para cifrarlos:

```bash
idata-sentinel keygen                       # genera la clave
export IDATA_SENTINEL_ENCRYPTION_KEY=...    # guárdala en el gestor de secretos
```

Se cifran `findings` y `artifacts`; el objetivo, la fecha y el score quedan en claro
porque son las columnas por las que se consulta el histórico. Activarlo no rompe una
base existente: cada fila registra en qué modo se escribió. **Sin la clave, los
escaneos ya cifrados son irrecuperables.**

### App web

`idata-sentinel serve` levanta el panel en `http://127.0.0.1:8000`: cartera de
objetivos, resultados de cada diagnóstico, superficie de ataque, semáforo 21.719 y
la ayuda por módulo.

**Exponerla fuera de `localhost` exige un token.** Sin `IDATA_SENTINEL_TOKEN` el
comando se niega a arrancar en una interfaz pública: un escáner abierto a Internet
es una herramienta que cualquiera puede usar contra activos de terceros.

## Arquitectura

```
core/        gate de autorización, cliente HTTP, rate limiter, resolver DNS, engine
checks/      verificaciones atómicas reutilizables entre módulos
modules/     los cuatro módulos de negocio
scoring/     motor de riesgo: severidad × probabilidad -> score 0-100 + nota A-F
reporting/   contexto del reporte, geometría de gráficos, plantilla, exportación PDF
storage/     escaneos, línea base, monitores y política de retención
interfaces/  CLI (typer) y app web (FastAPI)
docs/        catálogo de ayuda por módulo
```

Cada check produce el mismo contrato (`id`, `module`, `category`, `severity`,
`likelihood`, `status`, `title`, `finding`, `business_impact`, `recommendation`,
`evidence`, `references`), verificado por tests. Ningún check lanza excepciones: un
fallo de red produce un resultado "no evaluable" que **no** penaliza el score, para
no confundir "no pude medirlo" con "está mal".

## Tests

```bash
uv run pytest                                        # offline, determinista
uv run pytest --cov=idata_sentinel --cov-fail-under=90
uv run pytest -m integration                         # requiere WeasyPrint nativo
```

La suite no toca la red: HTTP con `respx`, DNS con un resolver en memoria y
certificados generados al vuelo.

### Activar la integración continua

El workflow está listo en [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml) pero
**no** en `.github/workflows/`: publicar ahí exige un token con scope `workflow`.
Para activarlo, con un token que lo tenga:

```bash
mkdir -p .github/workflows
git mv ci/github-actions-ci.yml .github/workflows/ci.yml
git commit -m "Activar CI" && git push
```

Corre los tests offline con umbral de cobertura del 90%, los de integración que
generan el PDF real, y construye la imagen Docker.

## Despliegue

Railway, con contenedores persistentes. No es serverless por tres razones: el rate
limit deliberado alarga los escaneos, el monitoreo necesita un proceso permanente,
y WeasyPrint requiere librerías nativas del sistema.

### Etapa 1 — Un servicio con SQLite en volumen

Es el despliegue vigente. **Un volumen persistente se monta en un único servicio**,
así que el monitoreo corre dentro del propio proceso web (`--con-monitoreo`) en vez
de en un worker aparte.

1. Crear el proyecto en Railway apuntando a este repositorio. `railway.json` ya
   define el build, el start command y el healthcheck.
2. Añadir un **volumen** montado en `/data`.
3. Configurar las variables de entorno:

| Variable | Obligatoria | Para qué |
|---|---|---|
| `IDATA_SENTINEL_TOKEN` | Sí | Sin ella la app se niega a escuchar fuera de `localhost` |
| `IDATA_SENTINEL_ENCRYPTION_KEY` | Sí | Cifra los hallazgos en reposo. Generar con `idata-sentinel keygen` |
| `IDATA_SENTINEL_DB` | No | Ya viene en `/data/sentinel.db` desde el Dockerfile |
| `PORT` | No | La inyecta Railway |

**Una réplica, no más.** SQLite en un volumen no admite varios escritores
simultáneos; escalar horizontalmente corrompería la base.

**Guarda la clave de cifrado fuera de Railway.** Si se pierde, los escaneos ya
cifrados son irrecuperables.

### Etapa 2 — Supabase, cuando haga falta

Postgres gestionado, Auth y Storage entran cuando se necesite acceso de los
clientes o varios servicios en paralelo. El esquema es plano a propósito (JSON en
columnas de texto) para migrar sin reescribir consultas.

### Verificar la imagen localmente

```bash
docker build -t idata-sentinel .
docker volume create sentinel-data
docker run -d --name sentinel -p 8000:8000 \
    -e IDATA_SENTINEL_TOKEN=cambiar \
    -v sentinel-data:/data idata-sentinel
curl localhost:8000/api/salud
```

## Documentos de referencia

- [plan_implementacion_idata_sentinel.md](plan_implementacion_idata_sentinel.md) — plan maestro
- [plan_implementacion_escaneo_vulnerabilidades.md](plan_implementacion_escaneo_vulnerabilidades.md) — detalle del Módulo 1

## Mantenimiento de los datos curados

Estos YAML se mantienen a mano y son los que hay que ampliar según lo que se observe
en escaneos reales:

| Archivo | Contenido |
|---|---|
| `data/fingerprints.yaml` | Firmas de tecnología |
| `data/cve_hints.yaml` | Producto + rango de versión -> CVE informativas |
| `data/cloud_signatures.yaml` | CDN, WAF y proveedores cloud |
| `data/takeover_signatures.yaml` | Servicios SaaS y su página de recurso no reclamado |
| `data/trackers.yaml` | Rastreadores de terceros y quién los controla |
| `data/ley_21719.yaml` | Mapeo de hallazgos a principios de la ley |
| `data/module_help.yaml` | Ayuda por módulo (CLI, web y reporte) |
