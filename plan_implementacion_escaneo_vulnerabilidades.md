# Plan de Implementación — Escaneo de Vulnerabilidades (IDATA Sentinel)

> **Módulo 1 — `vuln_identification`** · Fase 1 del roadmap general (posterior a la Fase 0 legal ya implementada).
> Este documento traduce el alcance funcional aprobado a un plan de ingeniería accionable. **No** modifica el marco legal, el contrato de check ni el motor de riesgo: los toma como restricciones fijas. Los módulos de activos, datos personales y monitoreo quedan fuera de alcance y solo se referencian cuando aportan contexto.
>
> Documento complementario a [plan_implementacion_idata_sentinel.md](plan_implementacion_idata_sentinel.md) §3. Generado con el modelo Fable 5.

---

## 0. Principios rectores (heredados, no negociables)

Todo lo que sigue debe respetar estas reglas del plan maestro:

- **Diagnóstico, nunca explotación.** El módulo solo *observa* respuestas y metadatos. Prohibido: fuerza bruta, prueba de credenciales, explotación de CVEs, inyecciones, DoS, fuzzing agresivo de rutas. Cuando se detecta una versión con CVEs conocidas, se reporta de forma **informativa**; jamás se verifica activamente si es explotable.
- **Dos modos:** `passive` (prospección, sin autorización, solo información pública) y `audit` (auditoría activa no destructiva, requiere autorización registrada). El gate legal (`core/authorization.py`) ya decide si un objetivo puede correr en modo `audit`; este módulo **consume** esa decisión, no la reimplementa.
- **Higiene de red en modo pasivo:** rate limit ≥ 2 s entre requests (vía `core/rate_limiter.py`), User-Agent honesto `IDATA-Sentinel/1.0 (+https://idatachile.com)`, respetar `robots.txt`. Todo el I/O pasa por `core/http_client.py` (httpx async ya configurado con timeouts, UA y retries).
- **Contrato de check inmutable:** cada check produce exactamente el dict definido en el plan maestro (`id`, `module`, `category`, `severity`, `likelihood`, `status`, `title`, `finding`, `business_impact`, `recommendation`, `evidence`, `references`).
- **Motor de riesgo inmutable:** severidad base (critical=25, high=15, medium=8, low=3, info=0) × probabilidad (high×1.0, medium×0.7, low×0.4). Los checks solo *alimentan* `severity` y `likelihood`; no calculan score.

---

## 1. Estructura de archivos

### 1.1 Panorama

```
idata_sentinel/
├── core/
│   ├── engine.py            # (existe) orquestador global — se le registra el módulo
│   ├── check_base.py        # (a implementar aquí) contrato + clase base + helpers de resultado
│   ├── authorization.py     # (existe) gate legal — se consulta, no se toca
│   ├── rate_limiter.py      # (existe)
│   └── http_client.py       # (existe) httpx async
├── modules/
│   └── vuln_identification/
│       ├── __init__.py
│       ├── module.py        # runner del módulo: selecciona checks por modo, ejecuta, agrega
│       ├── context.py       # ScanContext: target normalizado, modo, respuestas cacheadas, config
│       └── registry.py      # registro/descubrimiento de checks del módulo
├── checks/
│   ├── __init__.py
│   ├── http_headers.py      # HttpHeadersCheck(s)
│   ├── tls_ssl.py           # TlsSslCheck(s)
│   ├── tech_fingerprint.py  # TechFingerprintCheck + capa CVE informativa
│   ├── security_files.py    # SecurityFilesCheck (security.txt, robots.txt, dir listing)
│   ├── cookies.py           # CookiesCheck
│   └── exposure.py          # ExposureCheck
├── scoring/
│   ├── risk_engine.py       # (existe) se conecta al final
│   └── weights.yaml         # (existe)
└── data/
    └── cve_hints.yaml       # base local, offline, versión→CVEs informativas (curada a mano)
```

### 1.2 `core/check_base.py` — contrato estándar

Define el andamiaje que **todos** los checks reutilizan. No inventa campos; formaliza el dict del plan maestro.

```python
# Tipos y enums
Severity  = Literal["info", "low", "medium", "high", "critical"]
Likelihood = Literal["low", "medium", "high"]
Status    = Literal["pass", "fail", "warning", "info"]
Mode      = Literal["passive", "audit"]

@dataclass
class CheckResult:
    id: str; module: str; category: str
    severity: Severity; likelihood: Likelihood; status: Status
    title: str; finding: str; business_impact: str
    recommendation: str; evidence: str; references: list[str]
    def to_dict(self) -> dict: ...   # serialización 1:1 al contrato

class BaseCheck(ABC):
    id: str                          # p.ej. "http_headers"
    category: str                    # p.ej. "HTTP Headers"
    module = "vuln_identification"   # constante para todos los checks del módulo
    modes: set[Mode] = {"passive", "audit"}  # en qué modos aplica

    @abstractmethod
    async def run(self, ctx: "ScanContext") -> list[CheckResult]: ...

    # helpers compartidos para construir resultados sin repetir el contrato:
    def _result(self, *, sub_id, severity, likelihood, status, title,
                finding, business_impact, recommendation, evidence, references) -> CheckResult: ...
    def _error_result(self, *, sub_id, reason, evidence) -> CheckResult:
        # produce status="info" (o "warning") cuando el check no pudo evaluar. Ver §4.
```

**Un archivo de check puede emitir varios resultados** (p.ej. `http_headers.py` emite `hsts_missing`, `csp_missing`, etc.). Por eso `run()` devuelve `list[CheckResult]`: un `BaseCheck` = una familia de verificaciones sobre la misma superficie (un solo request reutilizado), y cada hallazgo atómico es un `CheckResult` con su propio `id`.

### 1.3 `modules/vuln_identification/context.py` — `ScanContext`

Objeto que se pasa a cada check para que **no repitan requests** (clave para respetar rate limit):

```python
@dataclass
class ScanContext:
    target: str                 # URL base normalizada (https://host)
    host: str
    mode: Mode                  # "passive" | "audit"
    http: HttpClient            # core/http_client.py
    rate_limiter: RateLimiter
    authorized: bool            # resultado del gate (solo True habilita modo audit)
    audit_paths: list[str]      # rutas provistas por el cliente (solo audit)
    audit_endpoints: list[str]  # endpoints conocidos del cliente (solo audit)
    hardening_baseline: dict    # baseline acordado (solo audit)
    robots: RobotsPolicy        # robots.txt parseado (para respetar disallow en pasivo)
    _cache: dict                # respuestas ya obtenidas (GET /, HEAD, etc.)

    async def get(self, path="/", method="GET") -> Response | None:
        # respeta rate_limiter, cachea por (method, path), devuelve None ante fallo de red
```

### 1.4 `modules/vuln_identification/registry.py` — registro de checks

Patrón de **registro explícito** (evita descubrimiento mágico y facilita el testing):

```python
from checks.http_headers import HttpHeadersCheck
from checks.tls_ssl import TlsSslCheck
from checks.cookies import CookiesCheck
from checks.tech_fingerprint import TechFingerprintCheck
from checks.security_files import SecurityFilesCheck
from checks.exposure import ExposureCheck

ALL_CHECKS: list[type[BaseCheck]] = [
    HttpHeadersCheck, TlsSslCheck, CookiesCheck,
    TechFingerprintCheck, SecurityFilesCheck, ExposureCheck,
]

def checks_for_mode(mode: Mode) -> list[BaseCheck]:
    return [C() for C in ALL_CHECKS if mode in C.modes]
```

### 1.5 `modules/vuln_identification/module.py` — runner del módulo

```python
class VulnIdentificationModule:
    name = "vuln_identification"

    async def run(self, ctx: ScanContext) -> list[dict]:
        checks = checks_for_mode(ctx.mode)
        results: list[CheckResult] = []
        # ejecución concurrente pero serializada por el rate_limiter (§4.5):
        gathered = await asyncio.gather(
            *(self._safe_run(c, ctx) for c in checks),
            return_exceptions=False,   # _safe_run nunca propaga excepciones
        )
        for r in gathered:
            results.extend(r)
        return [r.to_dict() for r in results]

    async def _safe_run(self, check, ctx) -> list[CheckResult]:
        try:
            return await check.run(ctx)
        except Exception as e:               # red de seguridad: un check jamás tumba el módulo
            log.exception("check %s crashed", check.id)
            return [check._error_result(sub_id=f"{check.id}_error",
                     reason=f"Error interno: {type(e).__name__}", evidence=str(e))]
```

### 1.6 Conexión con `engine.py` (existente)

`engine.py` orquesta módulos globalmente. La integración es mínima y no invasiva:

1. **Registro del módulo:** `engine.register_module(VulnIdentificationModule())`.
2. **Construcción del contexto:** el engine ya resuelve el gate de autorización (`authorization.py`) y construye `ScanContext` con `mode`, `authorized`, `robots`, etc. Si `mode="audit"` pero `authorized=False`, el engine degrada a `passive` (o aborta según política del engine) **antes** de invocar el módulo — el módulo confía en `ctx.mode`.
3. **Salida:** el módulo devuelve `list[dict]` (contrato). El engine agrega los resultados de todos los módulos y se los entrega a `scoring/risk_engine.py`. **El módulo no llama al risk_engine directamente.**

---

## 2. Lógica de detección por check

Notación: cada bloque indica **qué se inspecciona**, **librería**, **condiciones pass/fail/warning**, y **severity/likelihood con su justificación**. Los `id` siguen el estilo del contrato (`snake_case` del hallazgo).

### 2.1 `checks/http_headers.py` — HTTP Security Headers

**Superficie:** un `GET /` a la raíz (respuesta cacheada en `ctx`). Se inspecciona `response.headers` (case-insensitive).

Para cada cabecera se emite un `CheckResult` independiente. Regla general: **ausencia de cabecera defensiva = `fail` (o `warning` según impacto); cabecera que filtra versión = `warning`**.

| id | Condición fail | Condición pass | severity | likelihood | Justificación |
|---|---|---|---|---|---|
| `hsts_missing` | No existe `Strict-Transport-Security` sobre HTTPS | Existe con `max-age>=31536000` | medium | high | Degradación a HTTP / robo de sesión; explotable en redes hostiles comunes |
| `hsts_weak` (warning) | Existe pero `max-age<31536000` o sin `includeSubDomains` | — | low | medium | Configuración parcial |
| `csp_missing` | No existe `Content-Security-Policy` | Existe con directivas | medium | medium | Mitiga XSS/inyección de contenido; su ausencia no es explotable por sí sola |
| `csp_unsafe` (warning) | Contiene `unsafe-inline`/`unsafe-eval` o `default-src *` | política restrictiva | low | medium | Política presente pero laxa |
| `xfo_missing` | Faltan **ambos** `X-Frame-Options` y `frame-ancestors` en CSP | cualquiera presente | medium | medium | Clickjacking |
| `xcto_missing` | Falta `X-Content-Type-Options: nosniff` | presente | low | medium | MIME sniffing |
| `referrer_policy_missing` | Falta `Referrer-Policy` | presente | low | low | Fuga de URL/params por Referer |
| `permissions_policy_missing` | Falta `Permissions-Policy` | presente | info | low | Buena práctica; bajo impacto directo |
| `server_version_disclosure` (warning) | `Server` incluye versión (regex `\d+\.\d+`) | ausente o genérico | low | medium | Facilita reconocimiento; alimenta §2.4 |
| `powered_by_disclosure` (warning) | Existe `X-Powered-By`/`X-AspNet-Version`/`X-Generator` con versión | ausente | low | medium | Igual que arriba |

**Pseudocódigo:**

```python
async def run(self, ctx):
    resp = await ctx.get("/")
    if resp is None:
        return [self._error_result(sub_id="http_headers_unreachable", ...)]  # §4
    h = CaseInsensitiveHeaders(resp.headers)
    out = []
    # HSTS solo tiene sentido evaluarlo si el esquema efectivo es https
    if resp.url.scheme == "https":
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(self._result(sub_id="hsts_missing", severity="medium",
                       likelihood="high", status="fail", ...evidence=dump(h)))
        elif max_age(hsts) < 31536000 or "includesubdomains" not in hsts.lower():
            out.append(... "hsts_weak", severity="low", status="warning" ...)
    # CSP, XFO, XCTO, Referrer, Permissions -> mismo patrón
    # Disclosure de versiones -> warning, guardar valor en ctx para fingerprint
    return out
```

**Modo pasivo vs auditoría:**
- *Pasivo:* solo `GET /`.
- *Auditoría:* además itera sobre `ctx.audit_paths` (rutas que el cliente pidió revisar) haciendo un `GET` por ruta y repitiendo la evaluación de cabeceras; los `id` se sufijan con un hash/slug de ruta (p.ej. `hsts_missing@/admin`). Si hay `hardening_baseline`, se compara la cabecera observada contra la exigida en el baseline y se emite `header_baseline_mismatch` (severity heredada del baseline, likelihood `medium`).

### 2.2 `checks/tls_ssl.py` — TLS/SSL

**Superficie:** handshake TLS al puerto 443 usando el módulo estándar `ssl` + `socket` (para negociar y leer protocolo/cipher) y `cryptography.x509` (para parsear el certificado). **No** se prueban vulnerabilidades activas; solo se observa lo que el servidor negocia y presenta.

**Recolección (una sola conexión de inspección, fuera del rate limiter HTTP pero contabilizada):**

```python
ctx_ssl = ssl.create_default_context()
with socket.create_connection((host, 443), timeout=T) as sock:
    with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
        proto  = ssock.version()             # "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"
        cipher = ssock.cipher()              # (name, tls_version, bits)
        der    = ssock.getpeercert(binary_form=True)
cert = x509.load_der_x509_certificate(der)   # cryptography
```

Para detectar **soporte** de TLS 1.0/1.1 sin explotar nada: intentar un handshake acotado a cada versión mínima/máxima (`ctx_ssl.minimum_version = ssl.TLSVersion.TLSv1`), y registrar si el servidor lo acepta. Es negociación estándar, no un ataque.

| id | Condición | severity | likelihood | Justificación |
|---|---|---|---|---|
| `tls_legacy_protocol` | Servidor negocia/acepta TLS 1.0 o 1.1 → `fail` | high | medium | Protocolos obsoletos, criptografía débil conocida |
| `tls_weak_cipher` | Cipher negociado en lista débil (RC4, 3DES, EXPORT, `NULL`, `bits<128`) → `fail` | high | medium | Confidencialidad comprometida |
| `cert_expired` | `not_valid_after < now` → `fail` | critical | high | Sitio inutilizable/insegurizado; usuarios entrenados a ignorar avisos |
| `cert_expiring_soon` | `0 < (not_valid_after - now) < 30d` → `warning` | medium | high | Riesgo operacional inminente |
| `cert_chain_untrusted` | Verificación de cadena falla / self-signed / CA desconocida → `fail` | high | high | MITM plausible; confianza rota |
| `cert_hostname_mismatch` | CN/SAN no cubre `host` → `fail` | high | high | Certificado no válido para el dominio |
| `no_https_redirect` | `GET http://host` no redirige (30x) a `https` → `fail` | medium | high | Tráfico en claro por defecto |
| `tls_ok` | TLS 1.2/1.3, cipher fuerte, cert válido, redirección presente → `pass` (info consolidado) | info | low | Evidencia de buen estado |

**Notas de implementación:**
- La validez de cadena/hostname se obtiene principalmente de que `create_default_context()` **falle** el handshake verificado; se hace un segundo intento con verificación desactivada **solo para leer el certificado y explicar el motivo** (nunca para "aceptar" tráfico). Esto es inspección, no bypass operativo.
- `no_https_redirect` reutiliza `ctx.get` con esquema `http://` y `follow_redirects=False`; se evalúa la cadena de `Location`.

**Modo pasivo vs auditoría:** el conjunto TLS es idéntico en ambos modos (todo es observacional). En auditoría, si el baseline define versión mínima o suite exigida, se añade `tls_baseline_mismatch`.

### 2.3 `checks/cookies.py` — Flags de cookies

**Superficie:** cabeceras `Set-Cookie` de la respuesta a `GET /` (y de las rutas de auditoría si aplica). Parseo robusto con `http.cookies.SimpleCookie` **complementado** por parseo manual, porque `SimpleCookie` no expone `SameSite` de forma fiable en todas las versiones — se recomienda parsear el string crudo de cada `Set-Cookie`.

Por cada cookie emitida se evalúan tres flags:

| id (por cookie, sufijo con nombre) | Condición fail | severity | likelihood | Justificación |
|---|---|---|---|---|
| `cookie_insecure` | Falta `Secure` en sitio HTTPS | medium | high | Cookie viaja en claro si hay downgrade |
| `cookie_no_httponly` | Falta `HttpOnly` (relevante en cookies de sesión) | medium | medium | Robo vía XSS |
| `cookie_weak_samesite` | Falta `SameSite` o `SameSite=None` sin `Secure` | low | medium | CSRF / envío cross-site |

**Regla pass:** cookie con `Secure` + `HttpOnly` + `SameSite` en `Lax`/`Strict` → contribuye a `cookies_ok` (`info`, `pass`).

**Pseudocódigo:**

```python
for raw in resp.headers.get_list("set-cookie"):
    c = parse_setcookie(raw)          # nombre, atributos normalizados a lower
    if scheme=="https" and "secure" not in c.flags:
        out.append(fail("cookie_insecure", name=c.name, sev="medium", lk="high"))
    if "httponly" not in c.flags:
        out.append(fail("cookie_no_httponly", name=c.name, sev="medium", lk="medium"))
    if "samesite" not in c.attrs or (c.attrs.get("samesite")=="none" and "secure" not in c.flags):
        out.append(fail("cookie_weak_samesite", name=c.name, sev="low", lk="medium"))
```

**Modo pasivo vs auditoría:** idéntico; en auditoría se recolectan cookies también de `audit_paths`/`audit_endpoints` (más cookies de sesión visibles tras login-flows *provistos por el cliente*, nunca adivinados).

### 2.4 `checks/tech_fingerprint.py` — Fingerprint + CVEs informativas

**Superficie:** respuesta a `GET /` (headers + HTML) y señales ya recogidas por otros checks (`Server`, `X-Powered-By`, meta `generator`, rutas típicas de CMS, patrones en HTML/JS). Librería: `python-Wappalyzer` si está disponible; si no, lógica propia basada en firmas (regex sobre headers/HTML, cookies típicas como `wordpress_*`, `PHPSESSID`, `ci_session`, etc.).

**Detección de tecnología y versión (pasivo, no intrusivo):**

```python
tech = wappalyzer.analyze_with_versions(url=..., html=resp.text, headers=h)
# fallback propio: firmas en data/fingerprints.yaml
```

| id | Condición | severity | likelihood | Justificación |
|---|---|---|---|---|
| `tech_version_disclosure` | Se identifica producto **con versión** expuesta (CMS/framework/servidor) → `warning` | low | medium | Facilita reconocimiento dirigido |
| `tech_detected` | Producto identificado sin versión → `info` | info | low | Inventario, sin hallazgo |
| `component_version_disclosure` | Plugin/tema de WordPress **con versión** expuesta → `warning` | low | medium | Los componentes concentran la mayoría de los CVEs de un WP |

**Componentes de WordPress (`detect_components`).** El fingerprint del CMS por sí
solo no revela lo que importa: las vulnerabilidades de un sitio WordPress viven
en sus plugins y temas, no en el core. `detect_components` los extrae del HTML
**ya descargado** —cero requests extra— parseando los parámetros `?ver=` de las
rutas `/wp-content/plugins|themes/<slug>/...`. Reglas:

- Se exige `major.minor` (al menos un punto): los temas cachean con enteros
  gigantes tipo `?ver=801499924`, que son cache-busters y no versiones. Tratarlos
  como versión inventaría un componente falso.
- Si un componente aparece con varias versiones, se reporta la **más alta** —la
  más probable de estar instalada y la más conservadora para el cruce con CVE.
- El `slug` (p.ej. `revslider`, `contact-form-7`) es la clave con la que la capa
  CVE cruza el componente. Medido sobre un objetivo real, esto pasó de detectar
  "WordPress 6.9.5" a detectar Slider Revolution 6.7.40, Contact Form 7 6.1.6 y
  Uncode Privacy 2.3.0 — los componentes que de verdad cargan CVEs.

**Capa CVE — estrictamente informativa (§0):**

- Fuente: `data/cve_hints.yaml`, base **local, offline, curada a mano** que mapea `producto+rango_de_versión → [CVE-IDs, título, CVSS de referencia]`. `producto` admite tanto el nombre del stack ("WordPress", "Apache") como el **slug** de un plugin/tema ("revslider", "contact-form-7"); la coincidencia no distingue mayúsculas. **No** se consultan servicios online en tiempo de escaneo (evita depender de red y evita cualquier interpretación de "prueba activa"). El mantenimiento de este YAML es un proceso manual del equipo.
- **Estado actual: el archivo es placeholder.** Sus entradas son ejemplos para validar el pipeline, no CVEs reales. La detección de componentes ya alimenta la capa con los slugs y versiones correctos; falta que el equipo de seguridad de IDATA cure la lista con CVEs verificadas y sus rangos reales (NVD / GitHub Advisories) antes de usarla en un entregable. Publicar CVEs fabricados sería un falso positivo con peso legal, peor que no reportar ninguno.
- Si la versión detectada cae en un rango con CVEs listadas:

| id | status | severity | likelihood | Justificación |
|---|---|---|---|---|
| `cve_informational` | `info` (nunca `fail`) | mapeada desde CVSS de referencia (crit≥9.0, high≥7, med≥4, low<4) **pero degradada a máx. `medium`** | **low** (fijo) | No se verificó explotabilidad; el bajo `likelihood` refleja incertidumbre y evita inflar el score |

- El `finding` debe decir explícitamente: *"Versión potencialmente afectada por CVEs conocidas. Hallazgo informativo, no verificado; IDATA Sentinel no comprueba explotabilidad."* El `recommendation` es actualizar/parchear. `references` lista los CVE-IDs.
- **Prohibido:** enviar payloads de prueba, tocar rutas de exploit, o confirmar la versión mediante técnicas intrusivas. La versión se toma solo de lo que el servidor ya reveló.

**Modo pasivo vs auditoría:** idéntico. En auditoría se puede correlacionar con `audit_endpoints` para afinar el fingerprint, pero la capa CVE sigue siendo informativa y `likelihood=low`.

### 2.5 `checks/security_files.py` — Archivos de seguridad

**Superficie:** peticiones **puntuales y conocidas** (no fuzzing): `/.well-known/security.txt`, `/security.txt`, `/robots.txt`, y detección de *directory listing* en rutas ya conocidas (raíz y, en auditoría, rutas del cliente). Cada request respeta rate limit y `robots.txt` en modo pasivo.

| id | Condición | severity | likelihood | Justificación |
|---|---|---|---|---|
| `security_txt_missing` | Ni `/.well-known/security.txt` ni `/security.txt` responden 200 → `info` | info | low | Buena práctica (RFC 9116), no es vulnerabilidad |
| `security_txt_present` | Existe y parsea → `pass`/`info` | info | low | Evidencia positiva |
| `robots_exposes_sensitive` | `robots.txt` contiene `Disallow:` hacia rutas sensibles (regex: `admin`, `backup`, `config`, `private`, `db`, `.git`, `staging`, `test`) → `warning` | low | medium | Fuga de rutas por documentación pública |
| `directory_listing_open` | Respuesta 200 con firma de autoindex (`<title>Index of /`, `Directory listing for`, tabla de Apache/nginx) → `fail` | medium | medium | Exposición de estructura/archivos |

**Reglas críticas anti-fuzzing:**
- Solo se consultan rutas **canónicas conocidas** (`security.txt`, `robots.txt`) o **provistas por el cliente** (auditoría). **Nunca** se generan rutas por diccionario/fuerza bruta.
- Para `directory_listing_open` se inspeccionan únicamente rutas que ya aparecen en `robots.txt` (como *señal declarada*) o en `audit_paths`. La detección es por *firma en el contenido*, sin navegación recursiva.

**`robots.txt` como política (pasivo):** además de este check, `robots.txt` se parsea al construir el `ScanContext` (`RobotsPolicy`) y se **respeta** en modo pasivo: si una ruta está `Disallow` para nuestro UA, no se solicita en pasivo. En auditoría autorizada, las rutas explícitas del cliente prevalecen sobre `robots.txt` (el cliente autorizó su propio activo), pero esto se registra en evidencia.

### 2.6 `checks/exposure.py` — Exposición de información

**Superficie:** contenido de las respuestas ya obtenidas (raíz + rutas de auditoría) y estructura del HTML (parseo con `selectolax`/`BeautifulSoup`). **Sin** provocar errores: no se inyecta nada para forzar stack traces; solo se observa lo que el servidor devuelve espontáneamente.

| id | Condición fail/warning | severity | likelihood | Justificación |
|---|---|---|---|---|
| `verbose_error_exposed` | El body contiene firmas de stack trace/errores verbosos (`Traceback (most recent call last)`, `Warning: `, `Fatal error:`, `at java.`, `System.Exception`, `SQLSTATE`, rutas absolutas del servidor) → `fail` | medium | medium | Fuga de internals; útil para atacantes |
| `metadata_exposed` | Comentarios HTML con datos internos, `X-Debug`/headers de debug, meta `generator` con versión, o `.map`/`.env`/`.git/HEAD` accesibles (solo rutas conocidas) → `warning` | low | low | Fuga de bajo impacto |
| `form_insecure_transport` | `<form>` cuyo `action` resuelve a `http://` (o página servida por HTTP con formulario que envía datos) → `fail` | high | high | Credenciales/datos en claro — impacto directo y probable |

**Pseudocódigo `form_insecure_transport`:**

```python
for form in html.css("form"):
    action = urljoin(resp.url, form.attrs.get("action", ""))
    if urlparse(action).scheme == "http":
        out.append(fail("form_insecure_transport", sev="high", lk="high",
                        evidence=f"<form action='{action}'>"))
```

**Detección de errores verbosos sin provocarlos:** se limita a las respuestas ya recolectadas. Si en auditoría el cliente lista endpoints, se hace `GET` normal a cada uno y se inspecciona el body; **no** se envían parámetros malformados ni payloads para inducir errores.

**Nota de solape con datos personales:** si un formulario o página expone lo que parece PII, **no** se procesa aquí — se marca el hallazgo de transporte inseguro y se deja la clasificación de datos personales al módulo correspondiente (fuera de alcance). Este módulo no almacena ni transcribe contenido sensible en `evidence`; usa redacción/truncado.

### 2.7 Tabla resumen de checks adicionales de modo auditoría

Los checks anteriores ya describen su comportamiento en `audit`. Se consolidan los tres extras del alcance:

- **Cabeceras por ruta:** `http_headers.py` itera `ctx.audit_paths`.
- **Endpoints conocidos del cliente:** `exposure.py`, `cookies.py`, `tech_fingerprint.py` consumen `ctx.audit_endpoints` (provistos, nunca descubiertos).
- **Comparación contra baseline:** cada check compara con `ctx.hardening_baseline` cuando existe y emite `*_baseline_mismatch`. La severidad del mismatch la define el baseline; `likelihood=medium` por defecto.

---

## 3. Manejo de modo pasivo vs auditoría (regla transversal)

Cada check declara `modes` y decide qué activar leyendo `ctx.mode` / `ctx.authorized`. Reglas uniformes:

1. **Selección:** `checks_for_mode()` filtra por `modes`. Todos los checks de este módulo son válidos en `passive`; el modo `audit` **no agrega checks nuevos**, sino **superficie adicional** (rutas/endpoints/baseline del cliente) dentro de los mismos checks.
2. **Guardas dentro del check:**
   ```python
   targets = ["/"]
   if ctx.mode == "audit" and ctx.authorized:
       targets += ctx.audit_paths
   ```
   Si `ctx.mode == "audit"` pero `ctx.authorized` es `False`, el check se comporta como pasivo (defensa en profundidad; el engine ya debió degradar, pero el check no confía ciegamente).
3. **Respeto de robots.txt:** en `passive`, ninguna ruta `Disallow` se solicita. En `audit`, las rutas del cliente prevalecen y se registra el override en `evidence`/audit_log (el logging append-only ya existe en Fase 0; el módulo solo emite el evento, no lo gestiona).
4. **Rate limit:** ambos modos pasan por `rate_limiter` (≥2 s en pasivo). En auditoría se puede usar el mismo límite salvo que el cliente autorice explícitamente uno distinto; por defecto se mantiene conservador.
5. **Prohibiciones (§0) rigen en ambos modos por igual:** el modo auditoría **no** habilita fuzzing, credenciales ni explotación. Solo habilita *más superficie declarada por el cliente* y comparación con baseline.

---

## 4. Manejo de errores específico del módulo

**Principio inquebrantable:** un check nunca lanza excepción hacia arriba ni deja el módulo a medias. Ante cualquier fallo, produce un `CheckResult` con `status` apropiado y evidencia del error.

### 4.1 Matriz de fallos → resultado

| Situación | Detección | `status` | `severity`/`likelihood` | id / nota |
|---|---|---|---|---|
| Dominio caído / DNS no resuelve / conexión rechazada | `httpx.ConnectError`, `socket.gaierror` | `info` | info / low | `target_unreachable` — no es hallazgo de seguridad, es "no evaluable" |
| Timeout | `httpx.ReadTimeout`/`ConnectTimeout` | `warning` | info / low | `check_timeout` — se reporta y se sigue con otros checks |
| Certificado inválido/expirado/self-signed | excepción TLS en handshake verificado | **es un hallazgo**, no un error: ver §2.2 (`cert_*` con `fail`) | según §2.2 | Se distingue "no pude conectar" (info) de "conecté y el cert es malo" (fail) |
| Redirección infinita / loop | contador de saltos > N (p.ej. 10) con `follow_redirects=False` gestionado manualmente, o `httpx.TooManyRedirects` | `warning` | low / medium | `redirect_loop_detected` — se reporta como anomalía de configuración |
| Respuesta no-HTML donde se esperaba HTML | `content-type` no textual | check degrada: evalúa solo headers, omite parseo de body sin fallar | — | Los checks basados en HTML devuelven `info` "no aplicable" |
| Cuerpo demasiado grande | límite de tamaño en `http_client` (streaming con corte) | se evalúa lo recibido | — | Evita agotar memoria |
| Excepción inesperada en un check | `try/except` en `module._safe_run` (§1.5) | `info`/`warning` | info / low | `<check_id>_error` — red de seguridad final |

### 4.2 Reglas concretas

- **`ctx.get()` devuelve `None`** ante fallo de red en vez de propagar; cada check maneja `None` explícitamente (early-return con `_error_result`).
- **Nunca `raise` en `run()`**; si algo puede fallar, se envuelve. El `except` amplio de `_safe_run` es la última red, no la primera línea de defensa.
- **Distinción semántica clave:** *"no evaluable"* (`status="info"`, no suma al score de riesgo con severidad 0) vs *"hallazgo de seguridad"* (`fail`/`warning` con severidad real). Un dominio caído **no** debe reportarse como vulnerabilidad.
- **TLS:** timeout de handshake configurable (p.ej. 10 s). Un handshake que falla por *versión no soportada por nosotros* no se confunde con *servidor inseguro*: se registra con precisión en `evidence`.
- **Redirecciones:** el módulo gestiona `follow_redirects` de forma controlada para poder (a) evaluar `no_https_redirect` y (b) cortar loops. Máximo de saltos fijo y explícito.
- **Idempotencia y cache:** un fallo de red en la primera petición se cachea como fallo para no reintentar N veces en el mismo escaneo (evita martillar un host caído; respeta el espíritu del rate limit).

---

## 5. Estrategia de testing

Objetivo: **testear cada check sin tocar sitios reales de producción.** Todo determinista, offline, rápido.

### 5.1 Estructura

```
tests/
├── conftest.py                 # fixtures compartidas (ScanContext fake, mock http, mock TLS)
├── fixtures/
│   ├── headers/                # .json con sets de cabeceras (seguro / inseguro / parcial)
│   ├── html/                   # .html: dir listing, stack trace, form http, meta generator
│   ├── setcookie/              # strings Set-Cookie crudos
│   ├── certs/                  # certs PEM generados (válido, expirado, self-signed, mismatch)
│   └── cve_hints_test.yaml     # base CVE de prueba
├── checks/
│   ├── test_http_headers.py
│   ├── test_tls_ssl.py
│   ├── test_cookies.py
│   ├── test_tech_fingerprint.py
│   ├── test_security_files.py
│   └── test_exposure.py
└── test_module_runner.py       # integración: selección por modo, agregación, no-crash
```

### 5.2 Técnicas por capa

- **HTTP:** usar `httpx.MockTransport` o `respx` para inyectar respuestas (status, headers, body) sin red. `ScanContext.get` se apoya en el `HttpClient`, así que el mock se inyecta a nivel de transporte. Un fixture `make_ctx(mode=..., responses={...})` construye el contexto completo.
- **TLS:** dos enfoques combinables:
  1. **Certificados generados con `cryptography`** en `conftest` (válido, expirado, próximo a vencer, self-signed, hostname mismatch) — se testea toda la lógica de parseo/validez de `tls_ssl.py` pasándole el cert directamente a la función pura de evaluación (separar *recolección de socket* de *evaluación* para poder testear la evaluación sin socket).
  2. **Servidor TLS local efímero** (opcional, marcado `@pytest.mark.integration`) con `ssl` + `socketserver` en `localhost` para cubrir el camino de negociación de protocolo/cipher. No es producción y corre en CI aislado.
- **Parseo HTML/cookies:** funciones puras que reciben strings de fixtures; asserts sobre los `CheckResult` producidos.
- **CVE informativo:** cargar `cve_hints_test.yaml` y verificar que una versión en rango produce `cve_informational` con `status="info"`, `likelihood="low"` y severidad degradada (nunca `fail`).

### 5.3 Casos obligatorios por check

Para cada check, como mínimo: **(a)** caso `pass` (config segura), **(b)** cada `fail`/`warning` que emite, **(c)** modo pasivo vs auditoría (verificar que auditoría añade superficie y pasivo no), **(d)** manejo de error: `ctx.get` devuelve `None` → produce `*_unreachable`/`*_error` sin excepción.

### 5.4 Tests transversales

- **Contrato:** un test parametrizado que corre *todos* los checks contra fixtures y valida que cada `CheckResult.to_dict()` tiene exactamente las claves del contrato y valores en los enums permitidos (`severity`, `likelihood`, `status`).
- **No-crash:** un check que lanza excepción a propósito (fixture con `run` que hace `raise`) debe ser contenido por `_safe_run` y producir un resultado `*_error`.
- **Respeto legal:** test que verifica que en modo pasivo no se solicita ninguna ruta `Disallow` de un `robots.txt` fixture, y que **jamás** se generan rutas no declaradas (assert sobre las URLs solicitadas al mock — la lista debe ser subconjunto de {rutas canónicas} ∪ {rutas del cliente}).
- **Rate limit:** test que verifica que múltiples requests pasan por `rate_limiter` (mock que cuenta llamadas/espera).

### 5.5 CI

`pytest -m "not integration"` por defecto (100% offline, sin red). Los tests `integration` (servidor TLS local) corren en un job separado. Cobertura objetivo del módulo ≥ 85% de líneas y 100% de las ramas de decisión pass/fail/warning.

---

## 6. Desglose en sub-fases de la Fase 1

Orden pensado para entregar valor temprano y aislar riesgo (TLS es lo más frágil, va después de tener el andamiaje).

### Fase 1a — Andamiaje del módulo *(base)*
**Alcance:** `check_base.py` (contrato + `BaseCheck` + `CheckResult` + `_error_result`), `context.py` (`ScanContext`), `registry.py`, `module.py` con `_safe_run`, y un check trivial de humo. Integración de registro en `engine.py`.
**Criterio de salida:**
- El engine puede registrar el módulo y ejecutarlo contra un `ScanContext` mockeado devolviendo `list[dict]` conforme al contrato.
- `_safe_run` contiene excepciones (test no-crash verde).
- CI corre con el check de humo.

### Fase 1b — Checks pasivos "de cabeceras y contenido" *(rápido, sin TLS)*
**Alcance:** `http_headers.py`, `cookies.py`, `security_files.py`, `exposure.py`. Todos con manejo de error de red (`ctx.get() is None`) y sus tests con fixtures HTTP/HTML.
**Criterio de salida:**
- Los cuatro checks producen resultados conformes para casos pass/fail/warning.
- Tests de respeto a `robots.txt` y de no-fuzzing en verde.
- Cobertura ≥ 85% de estos archivos.

### Fase 1c — TLS/SSL *(riesgo técnico aislado)*
**Alcance:** `tls_ssl.py` con separación recolección/evaluación, fixtures de certificados, y (opcional) servidor TLS local para negociación.
**Criterio de salida:**
- Detecta correctamente: TLS legacy, cipher débil, cert expirado/por-vencer/self-signed/mismatch, ausencia de redirección HTTP→HTTPS.
- Distingue "no evaluable" (host caído) de hallazgo real.
- Tests de evaluación 100% offline (con certs generados).

### Fase 1d — Fingerprint + CVEs informativas *(depende de señales de 1b)*
**Alcance:** `tech_fingerprint.py`, integración de `python-Wappalyzer`/lógica propia, `data/cve_hints.yaml` (base curada inicial) y capa CVE informativa.
**Criterio de salida:**
- Identifica al menos los productos objetivo del primer cliente/piloto (WordPress, nginx/Apache, frameworks comunes).
- `cve_informational` siempre `status="info"`, `likelihood="low"`, severidad degradada; nunca ejecuta verificación activa (test lo garantiza).

### Fase 1e — Superficie de auditoría + baseline *(activa solo con autorización)*
**Alcance:** consumo de `ctx.audit_paths`/`audit_endpoints`/`hardening_baseline` en los checks correspondientes; emisión de `*_baseline_mismatch`.
**Criterio de salida:**
- Con `authorized=True`, los checks evalúan las rutas del cliente y comparan con baseline.
- Con `authorized=False` en modo `audit`, se comportan como pasivo (test lo verifica).

### Fase 1f — Conexión a riesgo y CLI *(cierre de Fase 1 del roadmap: pasos 5 y 6)*
**Alcance:** verificar que la salida agregada alimenta `scoring/risk_engine.py` sin cambios al motor; CLI mínima con `typer` que ejecuta el módulo y emite salida a consola + JSON.
**Criterio de salida:**
- `risk_engine` produce score 0-100 + letra A-F a partir de los resultados reales del módulo.
- `idata-sentinel scan <target> --mode passive|audit --json out.json` funciona end-to-end contra un objetivo de prueba local.

---

## 7. Definition of Done (Módulo 1)

El módulo se considera **completo** cuando **todo** lo siguiente es cierto:

**Funcional**
- [ ] Los 6 archivos de `checks/` están implementados y cubren cada ítem del alcance funcional (headers, TLS, cookies, fingerprint+CVE informativa, security files, exposición).
- [ ] Cada check emite resultados que cumplen **exactamente** el contrato de check (claves y enums), verificado por test de contrato.
- [ ] `severity`/`likelihood` asignados según la tabla de §2 y consumidos correctamente por `risk_engine.py` (sin modificar el motor).
- [ ] Modo pasivo y auditoría funcionan según §3; auditoría solo agrega superficie declarada por el cliente y comparación con baseline.

**Legal / de seguridad (bloqueante)**
- [ ] Ningún check hace fuzzing, fuerza bruta, prueba de credenciales, inyección, DoS ni explotación de CVEs — verificado por test que audita las URLs/payloads solicitados.
- [ ] La capa CVE es puramente informativa (`status="info"`, `likelihood="low"`, sin verificación activa).
- [ ] Modo pasivo respeta rate limit ≥2 s, UA honesto y `robots.txt` (tests verdes).
- [ ] Modo auditoría solo corre con `ctx.authorized=True`; sin autorización degrada a pasivo.
- [ ] `evidence` nunca vuelca contenido sensible/PII completo (redacción/truncado aplicado).

**Robustez**
- [ ] Ningún check lanza excepciones hacia arriba; todos los fallos de red/TLS/redirección producen un `CheckResult` con `status` apropiado (§4).
- [ ] "No evaluable" (host caído/timeout) se distingue de "hallazgo real" y no infla el score de riesgo.
- [ ] Loops de redirección se cortan; certificados inválidos se reportan como hallazgo, no como crash.

**Calidad / testing**
- [ ] Suite de tests 100% offline por defecto (`-m "not integration"`), determinista.
- [ ] Cada check tiene tests para pass, cada fail/warning, ambos modos y el camino de error.
- [ ] Cobertura del módulo ≥ 85% líneas y 100% de las ramas de decisión pass/fail/warning.
- [ ] CI en verde (lint + tipos + tests).

**Integración / entrega**
- [ ] Módulo registrado en `engine.py`; salida agregada fluye a `risk_engine.py` → score 0-100 + letra.
- [ ] CLI `typer` ejecuta el escaneo con salida a consola y JSON (pasos 5 y 6 del roadmap).
- [ ] Escaneo end-to-end contra un objetivo de prueba local produce un reporte válido en ambos modos.
- [ ] `data/cve_hints.yaml` y `data/fingerprints.yaml` documentados con su proceso de mantenimiento manual.
