# Plan de Implementación — Auditoría Activa No Destructiva (IDATA Sentinel)

> **Modo `audit` — Fase 2 del roadmap.** Este documento define qué es *de verdad* la auditoría activa de IDATA Sentinel: un **diagnóstico de configuración no destructivo** que corre **solo bajo solicitud explícita del cliente** y **solo con autorización registrada**. No es un pentest, no habilita capacidades ofensivas, y no relaja ninguna de las prohibiciones del modo pasivo.
>
> Complementa a [plan_implementacion_idata_sentinel.md](plan_implementacion_idata_sentinel.md) (§1 marco legal, §3 módulo vuln, §7 scoring) y a [plan_implementacion_escaneo_vulnerabilidades.md](plan_implementacion_escaneo_vulnerabilidades.md) (modo pasivo, contrato de check, testing). Toma esos dos como restricciones fijas: **no** modifica el marco legal, el contrato de check ni el motor de riesgo.
>
> Generado con el modelo Opus 5.
>
> **Estado: IMPLEMENTADO** (Fases 2a–2e). El gate de activación por nombre + doble
> confirmación, la comparación contra baseline, los cuatro checks activos
> (`http_methods`, `cors_config`, `auth_enforcement`, `redirect_audit`), el
> escaneo autenticado con sesión provista y el logging reforzado están en código y
> cubiertos por tests offline. Verificado end-to-end contra un objetivo propio:
> el modo activo solo corre nombrado y confirmado, emite solo GET/HEAD/OPTIONS, y
> no produce falsos positivos cuando el objetivo está bien configurado.

---

## 0. Qué es y qué NO es este modo (encuadre)

El modo `audit` de hoy es, con honestidad, **"los mismos checks pasivos sobre más rutas que declara el cliente"**: los checks recorren `ctx.audit_targets()` cuando `ctx.mode=="audit" and ctx.authorized`. Es correcto pero incompleto. Este plan lo convierte en una **auditoría de configuración** real, sin cruzar nunca la línea de lo destructivo.

**La auditoría activa NO destructiva es:**

- Ampliar la **superficie declarada por el cliente** (rutas, endpoints, activos que el propio dueño aporta).
- Validar **configuración** de forma más profunda: métodos HTTP permitidos, CORS, exigencia de autenticación en endpoints sensibles *declarados*, cabeceras y cookies por ruta, cadenas de redirección.
- Comparar la configuración observada contra un **baseline de hardening acordado** con el cliente y reportar desviaciones.
- Opcionalmente, revisar **rutas autenticadas** con una **sesión provista por el cliente** (nunca adivinada ni forzada).

**La auditoría activa NO es, y sigue estando PROHIBIDA (heredado de §0 del plan pasivo, sin excepción):**

fuerza bruta · prueba/adivinación de credenciales · explotación de CVEs · inyecciones (SQLi/XSS/SSTI/command/…) · DoS o carga agresiva · fuzzing de rutas por diccionario · envío de payloads malformados para inducir errores · cualquier acción que **modifique estado** en el objetivo.

> **Regla mental que distingue diagnóstico de ataque:** una técnica es admisible si *pregunta al servidor cómo está configurado* usando peticiones que un cliente legítimo podría emitir, y **no** si *intenta que el servidor haga algo que no debería*. `OPTIONS /` pregunta; `PUT /shell.php` ataca. Enviar `Origin:` y leer la respuesta pregunta; inyectar `';DROP TABLE` ataca.

---

## 1. Principios heredados no negociables

Todo lo que sigue hereda y **refuerza** —nunca debilita— las reglas del plan maestro y del plan pasivo:

1. **Diagnóstico, nunca explotación.** El modo activo observa configuración; no verifica explotabilidad. Todas las prohibiciones del §0 rigen igual que en pasivo.
2. **No destructivo por construcción.** Solo métodos HTTP **seguros/idempotentes de lectura** (`GET`, `HEAD`, `OPTIONS`). **Nunca** `POST`/`PUT`/`PATCH`/`DELETE` contra el objetivo, ni siquiera con sesión autenticada. Un método que puede cambiar estado no se emite jamás.
3. **Autorización registrada obligatoria.** El gate legal (`core/authorization.py`) ya decide `authorized`. El modo activo lo **consume**; sin `authorized=True` degrada a pasivo. El escaneo activo sin autorización es **delito** bajo la **Ley 21.459** (delitos informáticos): la evidencia de debida diligencia (`audit_log.json`) se **amplía**, no se toca.
4. **Solo bajo solicitud explícita.** Ver §4. El modo activo **nunca** corre por omisión, y **cada check activo** debe habilitarse por nombre. Autorización legal ≠ activación técnica: son dos gates distintos.
5. **Contrato de check inmutable.** Cada check activo produce el mismo `CheckResult` que un check pasivo (`core/check_base.py`), incluidos los campos `confidence` y `verification_status`. Sin campos nuevos.
6. **Motor de riesgo inmutable.** Los checks activos solo alimentan `severity`/`likelihood`/`confidence`; no calculan score.
7. **Higiene de red conservadora.** Rate limit ≥ 2 s por host (por defecto igual que pasivo), UA honesto, respuesta cacheada en `ScanContext`. El modo activo **no** sube el ritmo salvo autorización explícita del cliente en el contrato.
8. **Evidencia sin secretos.** `evidence` nunca vuelca cookies de sesión, tokens ni PII completa: redacción/truncado obligatorios (§6, §8).

---

## 2. Estado real: qué YA existe vs qué hay que construir

| Pieza | Estado | Ubicación | Nota |
|---|---|---|---|
| Gate legal (`AuthorizationGate.authorize`) | ✅ **Existe** | `core/authorization.py` | Exige `confirmed`, `authorized_by`, `contract_reference`, `allowed_domains`; valida scope; log append-only `granted\|denied_incomplete\|denied_out_of_scope`. |
| Degradación audit→passive | ✅ **Existe** | `core/engine.py` `Engine.scan()` | Sin autorización o fuera de scope, `mode="passive"`. Nunca corre activo por omisión. |
| Expansión de superficie declarada | ✅ **Existe (scaffold)** | `ScanContext.audit_targets()`, checks | Solo con `mode=="audit" and authorized`. Hoy = mismos checks pasivos sobre más rutas. |
| Flags CLI de audit | ✅ **Existen** | `interfaces/cli.py` | `--i-have-authorization`, `--authorized-by`, `--contract`, `--allowed-domain`, `--asset`. |
| Contrato con `confidence`/`verification_status` | ✅ **Existe** | `core/check_base.py` | Reutilizable tal cual por los checks activos. |
| **Comparación contra `hardening_baseline`** | ❌ **NO implementada** | `ScanContext.hardening_baseline` se pasa pero **ningún check lo lee** | Planificada (§2.7 plan pasivo). **Este plan la construye** (§5). |
| **Gate "activación explícita por check"** | ❌ **NO existe** | — | Hoy `--mode audit` + autorización basta para expandir superficie. **Este plan añade un segundo gate por check** (§4). |
| **Checks de configuración activos** (métodos, CORS, auth-enforcement, sesión) | ❌ **NO existen** | — | **Este plan los diseña** (§6). |
| **Escaneo con sesión provista por el cliente** | ❌ **NO existe** | — | **Este plan lo diseña** (§7). |

---

## 3. Estructura de archivos (adiciones, sin romper lo existente)

Todo se suma sin tocar el contrato ni el motor. Los archivos existentes se **extienden**; los nuevos se **agregan**.

```
idata_sentinel/
├── core/
│   ├── check_base.py          # (existe) contrato — SIN cambios
│   ├── authorization.py       # (existe) + amplía audit_log con checks activos/sesión (§8)
│   ├── active_gate.py         # (NUEVO) ActiveCapabilityGate: activación por check
│   ├── baseline.py            # (NUEVO) carga/valida hardening_baseline + comparador
│   └── session.py             # (NUEVO) ClientSession: material provisto, redactado
├── modules/vuln_identification/
│   ├── context.py             # (existe) + campos: active_checks, client_session (§4, §7)
│   └── module.py              # (existe) + filtra checks activos por el gate de activación
├── checks/
│   ├── http_headers.py        # (existe) + rama baseline_mismatch (§5)
│   ├── cookies.py             # (existe) + rama baseline + cookies por endpoint autenticado
│   ├── tls_ssl.py             # (existe) + rama tls_baseline_mismatch (§5)
│   ├── http_methods.py        # (NUEVO) OPTIONS / métodos permitidos (§6.1)
│   ├── cors_config.py         # (NUEVO) CORS por endpoint declarado (§6.2)
│   ├── auth_enforcement.py    # (NUEVO) endpoints sensibles exigen auth (§6.3)
│   └── redirect_audit.py      # (NUEVO) cadenas de redirección por endpoint (§6.4)
├── data/
│   └── baseline.schema.yaml   # (NUEVO) esquema documentado del baseline del cliente
└── interfaces/
    └── cli.py                 # (existe) + --active-check, --i-understand-active, --session-file
```

**Contrato de `modes` extendido con un tercer nivel implícito.** Hoy `modes` es `{"passive","audit"}`. Los checks nuevos declaran `modes = frozenset({"audit"})` **y** un atributo nuevo de clase `active: bool = True` que los marca como "capacidad activa que exige habilitación explícita". Los checks existentes siguen con `active = False` (su comportamiento en `audit` es solo expandir superficie, que no es una técnica activa nueva).

```python
class BaseCheck(ABC):
    ...
    active: bool = False   # (NUEVO) True => requiere activación explícita por nombre (§4)
```

Este es el único añadido al contrato base, y es aditivo (default `False`): ningún check existente cambia de comportamiento.

---

## 4. Mecanismo "solo bajo solicitud explícita" (el corazón del encargo)

### 4.1 Por qué un solo gate no basta

El gate legal responde *"¿tiene el cliente derecho a que escaneemos este dominio?"*. Es necesario pero **no** suficiente para disparar técnicas activas. Un operador puede tener autorización legal amplia (`--i-have-authorization` sobre `cliente.cl`) y aun así **no** querer que, en ese escaneo puntual, se dispare la comprobación de métodos HTTP o el escaneo autenticado. Confundir *autorización legal* con *activación técnica* es exactamente el accidente que este plan debe impedir: que un check activo se ejecute "porque el modo era audit".

**Decisión de diseño: dos gates ortogonales, ambos obligatorios.**

```
                 ┌─────────────────────────┐      ┌───────────────────────────┐
  técnica activa │ Gate 1: LEGAL           │      │ Gate 2: ACTIVACIÓN         │
  se ejecuta  ⇔  │ authorized == True      │  AND │ check.id ∈ active_checks   │
                 │ (core/authorization.py) │      │ (core/active_gate.py)      │
                 └─────────────────────────┘      └───────────────────────────┘
                        (ya existe)                        (NUEVO)
```

Si **cualquiera** de los dos falla, el check activo **no corre su técnica activa**: o bien se degrada a su comportamiento pasivo/de superficie (si es un check existente), o bien **no emite ningún hallazgo** (si es un check exclusivamente activo). Ante cualquier duda → pasivo. Nunca al revés.

### 4.2 Habilitación por check, no un interruptor global

**Decisión clave:** el modo activo **no** es un booleano. `--mode audit` habilita, como máximo, la **expansión de superficie** ya existente (rutas declaradas por el cliente sobre los checks pasivos), que no es una técnica ofensiva nueva. Para que corra **cada** check activo, el operador debe **nombrarlo**:

```
idata-sentinel scan https://cliente.cl \
  --mode audit \
  --i-have-authorization --authorized-by "J. Pérez, CISO" --contract "OC-2026-114" \
  --allowed-domain cliente.cl \
  --active-check http_methods --active-check cors_config \
  --i-understand-active
```

- `--active-check <id>` (repetible): habilita **un** check activo por su `id`. Sin ninguno, no corre ninguna técnica activa aunque haya autorización.
- No existe `--active-check all` sin fricción: se acepta la palabra `all`, pero **exige** `--i-understand-active` y **además** lista por consola, antes de ejecutar, qué checks se activarán, para que el operador confirme visualmente el alcance.
- `--i-understand-active`: doble confirmación obligatoria (equivalente al checkbox de UI). Su ausencia con `--active-check` presente **aborta con error**, no degrada en silencio: aquí el operador *pidió* algo activo y hay que decirle explícitamente que le falta la confirmación, no ejecutar a medias.

**Por qué habilitación por nombre y no un flag `--active`:** contiene el *blast radius*. Cada técnica activa tiene un perfil de riesgo distinto (CORS es casi inocuo; el escaneo autenticado toca datos reales del cliente). Obligar a nombrar cada una fuerza una decisión consciente por técnica y deja en el `audit_log` **exactamente** qué se activó. Un `--active` global invita a "encenderlo todo" por comodidad, que es justo lo que queremos evitar.

### 4.3 `core/active_gate.py`

```python
@dataclass(frozen=True)
class ActiveCapabilityGate:
    """Gate 2: decide, por check, si su capacidad activa está habilitada.

    Ortogonal al gate legal. Autorización legal NO implica activación.
    """
    enabled: frozenset[str]          # ids de checks activos que el operador nombró
    acknowledged: bool               # --i-understand-active / checkbox

    def allows(self, check: BaseCheck, *, authorized: bool) -> bool:
        if not check.active:
            return True              # check no-activo: no lo gestiona este gate
        return (
            authorized               # Gate 1
            and self.acknowledged    # doble confirmación
            and check.id in self.enabled  # habilitación por nombre
        )

    @classmethod
    def resolve(cls, requested: Sequence[str], *, acknowledged: bool,
                available: Sequence[str]) -> "ActiveCapabilityGate":
        # 'all' se expande a los disponibles, pero exige acknowledged (validado en CLI).
        if any(r.lower() == "all" for r in requested):
            return cls(frozenset(available), acknowledged)
        # ids desconocidos se descartan con advertencia (no habilitan nada).
        return cls(frozenset(r for r in requested if r in available), acknowledged)
```

### 4.4 Nuevos campos en `ScanContext`

Aditivos, con defaults seguros que replican el comportamiento actual si nadie los setea:

```python
@dataclass
class ScanContext:
    ...
    active_checks: frozenset[str] = frozenset()     # ids habilitados (§4.2)
    active_acknowledged: bool = False               # doble confirmación
    client_session: "ClientSession | None" = None   # sesión provista (§7)

    def active_enabled(self, check: "BaseCheck") -> bool:
        """Único punto de verdad que un check activo consulta antes de actuar."""
        if not getattr(check, "active", False):
            return True
        return (self.mode == "audit" and self.authorized
                and self.active_acknowledged and check.id in self.active_checks)
```

### 4.5 Guarda dentro de cada check activo (defensa en profundidad)

El runner ya filtra por el gate, pero el check **no confía ciegamente**: revalida. Es la misma filosofía que el `if ctx.mode=="audit" and ctx.authorized` de los checks actuales.

```python
class HttpMethodsCheck(BaseCheck):
    id = "http_methods"
    active = True
    modes = frozenset({"audit"})

    async def run(self, ctx):
        if not ctx.active_enabled(self):   # gate revalidado dentro del check
            return []                       # exclusivamente activo => silencio total
        ...
```

### 4.6 Filtrado en el runner (`module.py`)

```python
def checks_for_context(ctx) -> list[BaseCheck]:
    out = []
    for C in ALL_CHECKS:
        c = C()
        if ctx.mode not in c.modes:
            continue
        if c.active and not ctx.active_enabled(c):
            continue                        # no se instancia como activo
        out.append(c)
    return out
```

### 4.7 Tabla de decisión del doble gate

| `mode` | `authorized` | `--active-check X` | `--i-understand-active` | Resultado para el check activo `X` |
|---|---|---|---|---|
| `passive` | — | — | — | No aplica (checks activos declaran solo `audit`) |
| `audit` | `False` | sí | sí | **No corre** — engine ya degradó a `passive` |
| `audit` | `True` | **no** | — | **No corre** — no fue nombrado |
| `audit` | `True` | sí | **no** | **Aborta con error** en CLI — pidió activo sin confirmar |
| `audit` | `True` | sí | sí | ✅ Corre su técnica activa |
| `audit` | `True` | `all` | sí | ✅ Corre, tras listar por consola el alcance |

---

## 5. Comparación contra `hardening_baseline` (el gran pendiente)

### 5.1 Qué problema resuelve

Un hallazgo pasivo dice *"falta HSTS"*. Un hallazgo de baseline dice *"el cliente **acordó** HSTS con `max-age≥63072000` en `/checkout`, y el servidor entrega `max-age=300`"*. El segundo es más accionable porque compara contra un compromiso concreto, no contra una buena práctica genérica. El baseline es **el estándar de configuración que el cliente aceptó** y contra el cual quiere ser medido.

Hoy `ScanContext.hardening_baseline: dict` se pasa pero **ningún check lo lee**. Este es el trabajo.

### 5.2 Formato del baseline (`data/baseline.schema.yaml` documentado)

El cliente entrega un YAML; el engine lo carga en `hardening_baseline`. Estructura: por **ruta** (o `*` global), qué se exige, y con qué **severidad** debe reportarse la desviación.

```yaml
# baseline acordado con el cliente — se versiona junto al contrato
version: 1
defaults:                      # aplican a toda ruta salvo override
  headers:
    strict-transport-security:
      required: true
      must_match: "max-age=(6307[2-9]\\d{3}|[7-9]\\d{7,})"   # >= 2 años
      severity: high
    content-security-policy:
      required: true
      severity: medium
  tls:
    min_version: "TLSv1.2"
    severity: high
  cookies:
    require_secure: true
    require_httponly: true
    severity: medium
paths:
  /checkout:                   # override más estricto para ruta crítica
    headers:
      strict-transport-security: { required: true, severity: critical }
    methods:
      allowed: ["GET", "POST", "OPTIONS"]   # cualquier otro método => mismatch
      severity: high
```

**Decisiones de formato:**

- **Severidad heredada del baseline, no del check.** La criticidad de una desviación depende del negocio del cliente (HSTS débil en `/checkout` es peor que en `/blog`). Por eso la `severity` la fija el baseline, no el código. Si el baseline no la especifica, se hereda la del check pasivo equivalente como default.
- **`must_match` es una regex de validación, no de ataque.** Solo se aplica sobre el valor de cabecera **ya recibido**. No genera tráfico.
- **Override por ruta gana sobre `defaults`.** Fusión superficial por clave.
- **El baseline se versiona con el contrato.** El `version` y su hash entran al `audit_log` como evidencia de contra-qué-se-midió (§8).

### 5.3 `core/baseline.py` — cargador + comparador

Función pura, reutilizable por cualquier check. Separa *cargar/validar* (una vez) de *comparar* (por observación), igual que TLS separa recolección de evaluación → testeable offline.

```python
@dataclass(frozen=True)
class BaselineRule:
    key: str                 # "strict-transport-security"
    required: bool
    must_match: str | None
    severity: Severity

@dataclass(frozen=True)
class HardeningBaseline:
    version: int
    _by_path: dict[str, dict[str, BaselineRule]]   # normalizado

    @classmethod
    def load(cls, raw: dict) -> "HardeningBaseline": ...   # valida esquema, compila regex

    def rules_for(self, path: str, section: str) -> dict[str, BaselineRule]:
        # merge defaults + override de la ruta
        ...

def compare_headers(observed: Mapping[str, str], rules: dict[str, BaselineRule]) -> list[Mismatch]:
    out = []
    for key, rule in rules.items():
        value = observed.get(key)
        if rule.required and value is None:
            out.append(Mismatch(key, expected=rule, got=None, kind="missing"))
        elif value is not None and rule.must_match and not re.search(rule.must_match, value):
            out.append(Mismatch(key, expected=rule, got=value, kind="value"))
    return out
```

### 5.4 Emisión de `*_baseline_mismatch`

Cada check con baseline añade una rama que, **solo si hay baseline para esa ruta/sección**, compara y emite. Ejemplo en `http_headers.py`:

```python
if ctx.hardening_baseline:
    baseline = HardeningBaseline.load(ctx.hardening_baseline)   # cacheado en ctx
    for m in compare_headers(resp.headers, baseline.rules_for(path, "headers")):
        out.append(self._result(
            sub_id=self._suffixed(f"header_baseline_mismatch_{m.key}", path),
            severity=m.expected.severity,          # heredada del baseline
            likelihood="medium",
            status="fail",
            confidence="confirmed",                # dos señales: observado + acordado
            title=f"Configuración fuera del baseline acordado: {m.key}",
            finding=(f"El baseline v{baseline.version} exige {describe(m.expected)} en {path}; "
                     f"el servidor entrega {redact(m.got)!r}."),
            business_impact="Desviación respecto del estándar de hardening comprometido con el cliente.",
            recommendation=f"Ajustar {m.key} en {path} conforme al baseline acordado.",
            evidence=redact(m.got or "(ausente)"), references=("baseline",),
        ))
```

**`confidence="confirmed"`:** un mismatch de baseline no es una heurística ni una deducción de una sola señal; es la coincidencia de dos fuentes independientes (lo observado y lo acordado por escrito). Encaja con la semántica ya definida en `check_base.py` (`confirmed` = dos señales independientes coinciden), y evita que el motor lo trate como incierto.

**Secciones con baseline en la Fase 2:** `headers` (http_headers), `tls` (tls_ssl → `tls_baseline_mismatch`), `cookies` (cookies), `methods` (http_methods, §6.1). El patrón es idéntico; el comparador vive en `baseline.py` una sola vez.

---

## 6. Checks de configuración activos (nuevos)

Todos: `active = True`, `modes = {"audit"}`, revalidan `ctx.active_enabled(self)`, solo métodos de lectura, y **argumentan** por qué son no destructivos.

### 6.1 `checks/http_methods.py` — Métodos HTTP permitidos

**Qué hace:** un `OPTIONS` a cada ruta declarada; lee la cabecera `Allow` (o `Access-Control-Allow-Methods`). Reporta métodos peligrosos **habilitados**: `TRACE`/`TRACK` (XST), `PUT`/`DELETE`/`PATCH` sin control, `CONNECT`.

**Por qué es no destructivo:** `OPTIONS` es, por definición del RFC 9110, un método **seguro** cuyo único propósito es *preguntar* qué se permite. **No** se invocan los métodos peligrosos; solo se lee lo que el servidor **declara**. La diferencia con un ataque: nosotros preguntamos "¿aceptas PUT?"; un ataque **hace** `PUT`. Nunca hacemos el segundo paso.

| id | Condición | severity | likelihood | confidence |
|---|---|---|---|---|
| `http_trace_enabled` | `Allow`/respuesta a `OPTIONS` incluye `TRACE`/`TRACK` | medium | medium | high |
| `http_write_methods_advertised` | Anuncia `PUT`/`DELETE`/`PATCH` en ruta no-API | low | low | high |
| `methods_baseline_mismatch` | Métodos anunciados ⊄ `baseline.methods.allowed` | *(del baseline)* | medium | confirmed |

Nunca se emite un método que no sea `OPTIONS`. Si `OPTIONS` no está soportado (405/501), se declara **no evaluable** (`_error_result`), no un hallazgo.

### 6.2 `checks/cors_config.py` — CORS por endpoint declarado

**Qué hace:** repite el `GET` ya cacheado a cada endpoint declarado añadiendo una cabecera `Origin:` de prueba (p.ej. `https://idata-cors-probe.example`) y lee `Access-Control-Allow-Origin` (ACAO) y `Access-Control-Allow-Credentials` (ACAC). Detecta el patrón peligroso: **ACAO refleja el Origin arbitrario** *y* **ACAC=`true`** → cualquier sitio puede leer respuestas autenticadas.

**Por qué es no destructivo:** enviar una cabecera `Origin` es lo que hace **cualquier navegador** en una petición cross-origin legítima. Es una petición HTTP ordinaria de lectura; no altera estado, no inyecta payload ejecutable, no adivina nada. Observamos cómo el servidor **decide** su política CORS.

| id | Condición | severity | likelihood | confidence |
|---|---|---|---|---|
| `cors_reflects_arbitrary_origin` | ACAO == Origin de prueba **y** ACAC==`true` | high | medium | high |
| `cors_wildcard_origin` | ACAO == `*` en endpoint que sirve datos | medium | medium | high |
| `cors_null_origin_allowed` | ACAO == `null` | medium | medium | high |

**Límite explícito:** una sola petición de sonda por endpoint (Origin fijo de IDATA). **No** se enumeran orígenes ni se prueba una lista: eso sería fuzzing.

### 6.3 `checks/auth_enforcement.py` — Endpoints sensibles exigen autenticación

**Qué hace:** para cada endpoint que **el cliente declaró como sensible/autenticado** (`ctx.audit_endpoints`), hace **una** petición `GET` **sin credenciales** y verifica que el servidor responde `401`/`403` (o redirige a login). Si responde `200` con contenido de aplicación, emite un hallazgo: un recurso que debía estar protegido es accesible sin auth.

**Por qué es no destructivo y no es un ataque:** **no adivinamos ni probamos credenciales** — hacemos exactamente lo contrario: comprobamos que **sin** credenciales el recurso está cerrado. Es la verificación de un control, no su vulneración. Nunca se prueban usuarios/contraseñas, nunca se fuerza nada. Solo actuamos sobre endpoints que **el dueño listó**; jamás los descubrimos por diccionario.

| id | Condición | severity | likelihood | confidence |
|---|---|---|---|---|
| `sensitive_endpoint_no_auth` | Endpoint declarado sensible responde `200` sin credenciales | high | medium | high |
| `sensitive_endpoint_auth_ok` | Responde `401`/`403`/redirect a login | info | low | high |

**Distinción de falso positivo:** un SPA que responde `200` con su `index.html` a rutas desconocidas no es un fallo de auth. Se reutiliza la firma HTML del check de exposición (`_HTML_SIGNATURE`) para exigir que el `200` traiga **contenido de aplicación real** (JSON/datos), no el shell del SPA, antes de reportar.

### 6.4 `checks/redirect_audit.py` — Cadenas de redirección por endpoint

**Qué hace:** sigue de forma **controlada** (máx. N saltos, sin bucles) la cadena de redirección de cada endpoint declarado y reporta: downgrade HTTPS→HTTP en algún salto, y redirecciones a **hosts fuera del scope autorizado**.

**Por qué es no destructivo:** seguir `Location:` es comportamiento normal de cualquier cliente HTTP. **No** se inyectan parámetros de redirección para provocar *open redirect* (eso sería un ataque); solo se observa la cadena que el servidor produce espontáneamente para la ruta tal cual la declaró el cliente.

| id | Condición | severity | likelihood | confidence |
|---|---|---|---|---|
| `redirect_downgrade_https` | Algún salto va de `https` a `http` | high | medium | high |
| `redirect_offscope_host` | La cadena sale a un host fuera de `allowed_domains` | low | low | high |
| `redirect_loop_detected` | > N saltos / ciclo | low | medium | high |

### 6.5 Extensión de `cookies.py` a endpoints autenticados

Con sesión provista (§7), `cookies.py` recolecta también las cookies de sesión visibles tras usar la sesión del cliente en endpoints declarados, evaluando `Secure`/`HttpOnly`/`SameSite` sobre cookies **reales de sesión** (las de mayor impacto). Sin sesión, se comporta como hoy. Las cookies **nunca** se vuelcan a `evidence` (solo nombre y flags; el valor se redacta).

### 6.6 Resumen: por qué cada técnica separa diagnóstico de ataque

| Check | Petición que emite | Lo que un ataque haría (y NO hacemos) |
|---|---|---|
| http_methods | `OPTIONS` (pregunta) | `PUT`/`DELETE` reales (actúa) |
| cors_config | `GET` con `Origin` (navegación normal) | Enumerar orígenes / robar datos cross-site |
| auth_enforcement | `GET` **sin** credenciales (verifica el cierre) | Probar/forzar credenciales |
| redirect_audit | Seguir `Location` (cliente normal) | Inyectar `?next=//evil` (open redirect) |
| cookies (auth) | Reusar sesión **provista** | Robar/predecir/forzar sesión |

---

## 7. Escaneo con sesión provista por el cliente (autenticado)

### 7.1 Modelo de confianza

El cliente, dueño del activo, entrega **su propia** sesión ya autenticada (una cookie de sesión o un `Authorization: Bearer …`) para que IDATA revise cómo se comporta la aplicación **detrás del login** — cabeceras, cookies, CORS y auth-enforcement en zona autenticada. **Nunca** adivinamos, forzamos ni renovamos credenciales: recibimos material válido y lo usamos tal cual, como lo haría el propio usuario.

### 7.2 Entrega segura: `--session-file`, no la línea de comandos

```
idata-sentinel scan https://cliente.cl --mode audit ... \
  --active-check auth_enforcement --i-understand-active \
  --session-file ./sesion-cliente.json
```

```json
{
  "type": "cookie",                 // "cookie" | "bearer"
  "value": "sessionid=abc123; csrftoken=…",
  "scope_hosts": ["cliente.cl"],    // dónde puede enviarse; se intersecta con allowed_domains
  "expires_hint": "2026-07-31T20:00:00Z"
}
```

**Por qué archivo y no flag directo:** un token en la CLI queda en el historial del shell, en `ps`, y en logs de proceso. Un archivo se lee, se mantiene **solo en memoria**, y se puede borrar tras el escaneo. Es la misma lógica por la que el proyecto ya obliga a gestionar la clave de cifrado fuera del repo (`keygen`).

### 7.3 `core/session.py`

```python
@dataclass(frozen=True)
class ClientSession:
    kind: Literal["cookie", "bearer"]
    _material: str                    # nunca se serializa (repr/asdict redactados)
    scope_hosts: frozenset[str]

    def header_for(self, url: str) -> dict[str, str] | None:
        host = urlparse(url).hostname or ""
        if not any(host == h or host.endswith("." + h) for h in self.scope_hosts):
            return None               # fuera de scope: NO se envía la sesión
        return {"Cookie": self._material} if self.kind == "cookie" else {"Authorization": f"Bearer {self._material}"}

    def __repr__(self) -> str:
        return f"ClientSession(kind={self.kind}, scope={sorted(self.scope_hosts)}, material=<redacted>)"
```

`ScanContext.get_outcome()` consulta `client_session.header_for(url)` y adjunta la cabecera **solo** si (a) hay sesión, (b) `active_enabled`, (c) el host está en scope de la sesión **y** en `allowed_domains`. Triple intersección de scope.

### 7.4 Riesgos y límites (explícitos)

| Riesgo | Mitigación |
|---|---|
| La sesión toca datos reales del cliente | **Solo métodos de lectura** (`GET`/`HEAD`/`OPTIONS`). Nunca `POST`/`PUT`/`DELETE` → no se muta estado, no se dispara una acción destructiva por accidente. |
| Fuga de la sesión en `evidence`/logs | `ClientSession` redacta en `repr`/serialización; los checks nunca ponen el valor en `evidence`; el `audit_log` registra "sesión provista: sí/no", no el material. |
| Envío de la sesión a un host equivocado (CSRF de la propia herramienta) | Triple scope: `scope_hosts` ∩ `allowed_domains` ∩ host de la petición. Fuera de eso, la cabecera no se adjunta. |
| Sesión expirada → 302 a login interpretado como hallazgo | Si tras adjuntar sesión el endpoint redirige a login, se marca **no evaluable** (`session_expired`, `unverified`), no un hallazgo de auth. |
| Acción con efectos secundarios vía `GET` (mal diseño del cliente) | Se documenta como límite conocido: IDATA no puede saber si un `GET` del cliente muta estado. El contrato de auditoría advierte usar una cuenta de prueba, no una productiva. |

---

## 8. Refuerzo del gate y del logging (debida diligencia)

El `audit_log.json` ya registra la **decisión de autorización**. La auditoría activa **amplía** la evidencia (nunca la reduce). Se extiende `AuditLogger.record` con campos aditivos:

```python
entry = {
    ...  # timestamp, target, decision, authorized_by, contract_reference, source_ip (ya existen)
    "active_checks_enabled": sorted(active_checks),   # NUEVO: qué técnicas activas se habilitaron
    "active_acknowledged": bool,                       # NUEVO: doble confirmación registrada
    "authenticated_scan": bool,                        # NUEVO: hubo sesión provista (sí/no; NUNCA el material)
    "baseline_version": baseline_version_or_none,      # NUEVO: contra qué baseline se midió
}
```

**Reglas del logging reforzado:**

- Se registra **antes** de ejecutar cualquier técnica activa, no después: la evidencia de intención precede a la acción.
- El material de sesión, tokens y cookies **nunca** entran al log (solo el booleano).
- Sigue siendo **append-only**: la auditoría activa no puede borrar ni reescribir entradas previas.
- Si el operador pide activo sin confirmación (`--active-check` sin `--i-understand-active`), se registra un `denied_active_unacknowledged` y **se aborta**, dejando rastro del intento.

---

## 9. Encaje sin romper el modo pasivo ni el contrato

1. **Modo pasivo intacto.** Los checks nuevos declaran `modes={"audit"}`: `checks_for_context` ni los instancia en pasivo. Cero riesgo de que una técnica activa se filtre a un escaneo sin autorización.
2. **Contrato intacto.** Los checks activos emiten el mismo `CheckResult`; el único añadido al `BaseCheck` es `active: bool = False` (aditivo, no rompe a nadie).
3. **Motor de riesgo intacto.** `severity`/`likelihood`/`confidence` alimentan el score existente. `confidence="confirmed"` de los mismatches de baseline ya está soportado por `check_base.py`.
4. **`ScanContext` retrocompatible.** Los campos nuevos tienen defaults (`frozenset()`, `False`, `None`) que reproducen el comportamiento actual si nadie los setea.
5. **Engine mínimo.** `RunParams` gana `active_checks`, `active_acknowledged`, `client_session`; el módulo los traslada al `ScanContext`. La degradación audit→passive existente se mantiene como primera línea.

---

## 10. Manejo de errores específico del modo activo

Hereda la matriz del plan pasivo (§4) y añade los casos activos. **Principio inquebrantable:** un check activo nunca lanza hacia arriba ni ejecuta una técnica no habilitada.

| Situación | Detección | `status` / `confidence` | id / nota |
|---|---|---|---|
| Check activo sin habilitación | `ctx.active_enabled(self)` es `False` | (no emite nada) | Silencio total; el runner ya no debió instanciarlo — defensa en profundidad |
| `OPTIONS` no soportado (405/501) | status de la respuesta | `info` / `unverified` | `http_methods_not_supported` — no evaluable, no hallazgo |
| Sesión expirada (redirect a login) | `Location` a login tras adjuntar sesión | `info` / `unverified` | `session_expired` — no es fallo de auth |
| Sesión fuera de scope | `header_for` devuelve `None` | (no se adjunta) | Se evalúa sin sesión; se anota en evidencia que fue anónimo |
| Baseline malformado | `HardeningBaseline.load` lanza | `info` / `unverified` | `baseline_invalid` — se omite la comparación, se avisa; **no** se inventan mismatches |
| Endpoint declarado inaccesible | `outcome.ok` es `False` | `info` / `unverified` | `endpoint_unreachable@<path>` |
| Redirect loop | contador > N | `warning` | `redirect_loop_detected` (§6.4) |
| Excepción inesperada | `try/except` en `_safe_run` | `info` / `unverified` | `<check_id>_error` — red de seguridad final |

**Regla semántica clave (heredada):** *"no evaluable"* (`confidence="unverified"`, no penaliza score) vs *"hallazgo real"* (`fail`/`warning`). Un `OPTIONS` no soportado o una sesión expirada **no** son vulnerabilidades: son "no medido".

---

## 11. Estrategia de testing (100% offline por defecto)

Objetivo idéntico al pasivo: **probar cada check activo sin tocar sitios reales**. Determinista, offline, rápido. `pytest -m "not integration"` por defecto.

### 11.1 Cómo simular servidores para checks activos

- **HTTP (métodos/CORS/auth/redirects):** `httpx.MockTransport`/`respx`. Un fixture `make_active_ctx(mode="audit", authorized=True, active_checks={...}, responses={...})` inyecta respuestas por `(method, path)`, incluidas respuestas a `OPTIONS` con `Allow`, a `GET` con `Origin`→ACAO, y respuestas `401`/`200`. Se testea toda la lógica sin red.
- **Métodos HTTP:** el mock devuelve `Allow: GET, POST, OPTIONS, TRACE` → se verifica `http_trace_enabled`. Un mock que responde `405` a `OPTIONS` → `not_supported`/no evaluable.
- **CORS:** el mock refleja el `Origin` recibido en ACAO y setea ACAC=`true` → `cors_reflects_arbitrary_origin`. Se **asserta que se envió exactamente una** sonda por endpoint (anti-fuzzing).
- **Auth-enforcement:** mock `200` con JSON real → `sensitive_endpoint_no_auth`; mock `200` con `index.html` (firma SPA) → **no** se reporta (falso positivo evitado); mock `401` → `auth_ok`.
- **Sesión:** fixture con `ClientSession`; se asserta que la cabecera de sesión se adjunta **solo** a hosts en scope y **nunca** aparece en `evidence` ni en el `repr`.
- **Baseline:** función pura `compare_headers` contra `BaselineRule` de fixture (present/missing/value-mismatch). Se verifica `severity` heredada y `confidence="confirmed"`.
- **Servidor local efímero** (opcional, `@pytest.mark.integration`): `http.server`/`ssl` en `localhost` para el camino real de `OPTIONS`/redirects. Corre en job aislado de CI, jamás contra producción.

### 11.2 Tests de seguridad/legales (bloqueantes)

- **Doble gate:** un check activo con `authorized=True` pero **sin** estar en `active_checks` **no** emite nada (tabla §4.7 parametrizada, todas las filas).
- **Sin acknowledged:** `--active-check X` sin `--i-understand-active` → la CLI aborta (no ejecuta a medias).
- **Solo lectura:** assert de que **ninguna** petición emitida por un check activo usa un método distinto de `GET`/`HEAD`/`OPTIONS` (inspección de las llamadas al mock).
- **Anti-fuzzing:** las URLs solicitadas son subconjunto de `{rutas canónicas} ∪ {rutas/endpoints del cliente}`; jamás rutas generadas.
- **Scope de sesión:** la sesión nunca se envía fuera de `scope_hosts ∩ allowed_domains`.
- **Redacción:** ni el material de sesión ni cookies completas aparecen en `evidence` ni en `audit_log`.
- **Logging previo:** el `audit_log` registra los checks activos **antes** de ejecutarlos; `denied_active_unacknowledged` se registra ante el intento sin confirmación.

### 11.3 CI y cobertura

`pytest -m "not integration"` (100% offline). Cobertura ≥ 85% líneas y **100% de las ramas del doble gate** y de la comparación de baseline (son las críticas por implicación legal).

---

## 12. Desglose en sub-fases de la Fase 2

Orden pensado para entregar el **control** antes que las **capacidades**: primero el gate que impide accidentes, luego lo que ese gate protege.

### Fase 2a — Gate de activación explícita + logging reforzado *(control primero)*
**Alcance:** `core/active_gate.py`; campos nuevos en `ScanContext` y `RunParams`; `BaseCheck.active`; filtrado en `module.py`; CLI (`--active-check`, `--i-understand-active`); `audit_log` ampliado.
**Criterio de salida:**
- La tabla de decisión §4.7 pasa entera en tests.
- Sin `--active-check`, un escaneo `audit` autorizado se comporta **exactamente** como hoy (solo expansión de superficie).
- `--active-check` sin confirmación aborta y deja rastro en el log.

### Fase 2b — Comparación contra baseline *(el gran pendiente, bajo riesgo)*
**Alcance:** `core/baseline.py` (cargador + comparador puro), `data/baseline.schema.yaml`, ramas `*_baseline_mismatch` en `http_headers`, `tls_ssl`, `cookies`.
**Criterio de salida:**
- `hardening_baseline` deja de ser un campo muerto: produce mismatches con severidad heredada y `confidence="confirmed"`.
- Baseline malformado → `baseline_invalid` no evaluable, nunca mismatches inventados.

### Fase 2c — Checks de configuración activos *(capacidades, ya protegidas por 2a)*
**Alcance:** `http_methods.py`, `cors_config.py`, `auth_enforcement.py`, `redirect_audit.py`, con sus tests offline.
**Criterio de salida:**
- Cada check corre **solo** habilitado por nombre; sin habilitar, silencio.
- Solo emiten `GET`/`HEAD`/`OPTIONS` (test lo garantiza).
- Falsos positivos de SPA evitados en auth-enforcement.

### Fase 2d — Escaneo autenticado con sesión provista *(la capacidad más sensible, al final)*
**Alcance:** `core/session.py`, `--session-file`, integración en `ScanContext.get_outcome`, extensión de `cookies.py` a zona autenticada.
**Criterio de salida:**
- La sesión se adjunta solo dentro del triple scope; nunca aparece en evidencia/log.
- Sesión expirada → no evaluable, no hallazgo.
- Solo lectura, verificado por test.

### Fase 2e — Cierre: CLI end-to-end, reporte y DoD
**Alcance:** salida a consola que lista el alcance activo antes de ejecutar; JSON/PDF incluyen los hallazgos activos y de baseline; verificación de que el `risk_engine` los consume sin cambios.
**Criterio de salida:** escaneo activo end-to-end contra un objetivo de prueba local, con doble gate, baseline y (opcional) sesión, produce un reporte válido.

---

## 13. Definition of Done (Fase 2 — Auditoría activa)

El modo activo se considera **completo** cuando **todo** lo siguiente es cierto:

**Control de activación (bloqueante — el corazón del encargo)**
- [ ] El modo activo **nunca** corre por omisión: `--mode audit` sin `--active-check` se comporta igual que hoy (solo expansión de superficie).
- [ ] **Cada** check activo exige habilitación por nombre (`--active-check <id>`) **más** doble confirmación (`--i-understand-active`); ambos gates verificados por la tabla §4.7.
- [ ] Un check activo revalida `ctx.active_enabled(self)` internamente (defensa en profundidad), no confía en el runner.
- [ ] `--active-check` sin confirmación **aborta** (no degrada en silencio) y registra `denied_active_unacknowledged`.

**Legal / de seguridad (bloqueante)**
- [ ] Ningún check activo hace fuzzing, fuerza bruta, prueba de credenciales, inyección, DoS ni explotación — verificado por test que audita métodos y URLs.
- [ ] Solo se emiten métodos de lectura (`GET`/`HEAD`/`OPTIONS`); jamás `POST`/`PUT`/`PATCH`/`DELETE` contra el objetivo.
- [ ] El modo activo solo corre con `authorized=True`; sin autorización, el engine degrada a pasivo.
- [ ] El `audit_log` registra, **antes** de ejecutar, los checks activos habilitados, la confirmación, si hubo sesión (sí/no) y la versión del baseline — append-only, sin material sensible.
- [ ] Material de sesión, tokens y cookies completas **nunca** aparecen en `evidence` ni en el log.

**Funcional**
- [ ] `hardening_baseline` se consume de verdad: `http_headers`, `tls_ssl`, `cookies` (y `http_methods`) emiten `*_baseline_mismatch` con severidad heredada y `confidence="confirmed"`.
- [ ] Los cuatro checks activos (`http_methods`, `cors_config`, `auth_enforcement`, `redirect_audit`) producen resultados conformes al contrato.
- [ ] El escaneo autenticado con sesión provista funciona dentro del triple scope y solo en lectura.

**Robustez**
- [ ] Ningún check activo lanza excepciones hacia arriba; todo fallo produce un `CheckResult` `unverified` apropiado.
- [ ] "No evaluable" (OPTIONS no soportado, sesión expirada, baseline inválido) se distingue de "hallazgo real" y no infla el score.

**Calidad / integración**
- [ ] Suite 100% offline por defecto (`-m "not integration"`), determinista; cobertura ≥ 85% líneas y **100% de las ramas del doble gate y del comparador de baseline**.
- [ ] Contrato de check, motor de riesgo y modo pasivo **sin cambios de comportamiento** (solo añadidos aditivos).
- [ ] Escaneo activo end-to-end contra objetivo de prueba local produce reporte válido con hallazgos activos y de baseline.
- [ ] `data/baseline.schema.yaml` documentado; proceso de acuerdo del baseline con el cliente descrito.
```
