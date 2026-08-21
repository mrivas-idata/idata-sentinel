# Plan de Implementación — Módulo 5: Visibilidad en Buscadores y Motores Generativos (SEO + GEO)

> **Módulo `search_visibility`, alias `seo`.** Evalúa si un sitio puede ser
> encontrado, entendido y citado: por los buscadores clásicos (**SEO**), por los
> motores generativos que hoy responden sin enviar clics (**GEO**), y con qué
> rapidez responde al usuario (**rendimiento**).
>
> Complementa a [plan_implementacion_idata_sentinel.md](plan_implementacion_idata_sentinel.md)
> (§1 marco legal, §2 contrato de check, §7 scoring) y toma sus restricciones como
> fijas: **no** modifica el marco legal, **no** modifica el contrato de check, y
> —punto central de este plan— **no** contamina el motor de riesgo de seguridad.
>
> Generado con el modelo Opus 5.
>
> **Estado: PROPUESTO.** Ninguna parte está implementada.

---

## 0. Qué es y qué NO es este módulo

**GEO = Generative Engine Optimization**: qué tan preparado está el sitio para
que ChatGPT, Claude, Perplexity, Copilot y los AI Overviews de Google lo lean,
lo entiendan y lo **citen**. Es una superficie nueva y medible: en 2026 una
proporción creciente de las consultas termina en una respuesta generada, sin
visita al sitio de origen. Un sitio invisible para esos motores desaparece de
esa conversación aunque posicione bien en la búsqueda tradicional.

El **SEO local o geográfico** (NAP, `LocalBusiness`, cobertura por comuna) no es
"GEO" en este plan: va dentro de SEO, como una dimensión más. Se explicita
porque la sigla se usa para ambas cosas y confundirlas cambiaría el alcance.

**Este módulo SÍ:**

- Mide **indexabilidad**: si los buscadores pueden entrar, rastrear y entender.
- Mide **legibilidad para motores generativos**: si el contenido existe en el
  HTML que un crawler sin JavaScript recibe, y si está estructurado para ser citado.
- Mide **rendimiento observable**: TTFB, peso, compresión, caché, recursos que
  bloquean el render.
- Reutiliza lo que los módulos 1–3 ya descargaron. Cero peticiones duplicadas.

**Este módulo NO:**

- **No hace auditoría de contenido ni de palabras clave.** No opina sobre la
  calidad editorial, no sugiere keywords, no estima volúmenes de búsqueda. Eso
  es trabajo humano y datos de pago.
- **No estima posiciones ni tráfico.** Sentinel no consulta rankings; afirmarlo
  sería inventar.
- **No mide Core Web Vitals reales sin ayuda externa.** Ver §8: sin navegador no
  hay LCP, CLS ni INP, y este plan se niega a fingirlos.
- **No entra en el score de seguridad.** Ver §2.

---

## 1. Principios heredados no negociables

Los mismos del modo pasivo, sin excepción:

1. **Solo información publicada.** GET/HEAD, nunca mutación de estado.
2. **≥2 s entre peticiones al mismo host**, User-Agent identificable.
3. **`robots.txt` se respeta.** Aquí hay una paradoja aparente que se resuelve
   sola: si `robots.txt` bloquea el rastreo, no se rastrea — y esa restricción
   **es en sí misma el hallazgo SEO**, no un obstáculo para producirlo.
4. **Un check nunca lanza excepciones.** Fallo de red produce un resultado no
   evaluable que **no** penaliza.
5. **Nunca se afirma lo que no se midió.** Aplica con especial fuerza al
   rendimiento, donde la tentación de extrapolar es máxima.

---

## 2. La decisión de arquitectura: dos notas, nunca una

Hoy `scoring/risk_engine.calculate()` recibe `result["modules"]` completo y
promedia **todos** los hallazgos de **todos** los módulos en un solo número.
Añadir el módulo SEO sin tocar eso produciría un absurdo inmediato:

> un sitio con un RCE sin parche **mejoraría su nota de seguridad** por tener
> buenos `title` y `meta description`.

Y al revés: un sitio impecablemente asegurado reprobaría por no tener sitemap.
Las dos lecturas son falsas y ambas destruyen la credibilidad del informe.

**Regla: el riesgo de seguridad y la visibilidad son dos ejes independientes, se
calculan por separado y se presentan por separado.**

### 2.1 Implementación

Se marca el dominio de puntuación en el propio módulo, que es quien lo sabe:

```python
class ScanModule(Protocol):
    name: str
    scoring_domain: str = "security"   # nuevo, con default retrocompatible
    async def run(self, params: RunParams) -> "list[dict] | ModuleOutput": ...
```

`search_visibility` declara `scoring_domain = "visibility"`. El engine agrupa los
resultados por dominio y el CLI/webapp calculan una nota por dominio:

```python
risk       = calculate(result["modules_by_domain"]["security"])    # 0-100 + A-F
visibility = calculate(result["modules_by_domain"]["visibility"])  # 0-100 + A-F
```

`calculate()` **no cambia**: el mismo motor, los mismos pesos, aplicado a dos
conjuntos disjuntos. Es el cambio mínimo que evita el error y no toca el código
ya probado del motor de riesgo.

### 2.2 Retrocompatibilidad

Los módulos existentes no declaran nada y heredan `"security"`, así que el score
de todos los escaneos históricos se mantiene idéntico. El contrato JSON gana una
clave (`visibility`) y no pierde ninguna.

---

## 3. Estado real: qué ya existe y hay que reutilizar

La mitad del trabajo está hecha en otros módulos. **Duplicarlo sería el error de
diseño más probable de este plan** — ya ocurrió una vez con la emisión de CVEs,
que quedó copiada en `tech_fingerprint` y `javascript` hasta que se unificó.

| Necesidad del módulo SEO | Ya existe en | Acción |
|---|---|---|
| HTML de la raíz | `RunParams.root_outcome` | Reutilizar, no volver a pedir |
| `robots.txt` parseado | `core/robots.py` | **Extender**: hoy solo evalúa el UA propio |
| Cabeceras de respuesta | `checks/http_headers.py` | Leer del mismo `FetchOutcome` |
| Recursos, scripts, `<link>` | `checks/javascript.py` | **Extraer** el parser a `core/` y compartir |
| Detección de tecnología | `checks/tech_fingerprint.py` | Reutilizar `detect_technologies` |
| Formularios y campos | `checks/privacy_signals.py` | Reutilizar `parse_forms` para NAP |
| Cache de peticiones por ruta | `ScanContext.get_outcome` | Reutilizar tal cual |
| Diff entre escaneos | `modules/monitoring/diff.py` | Gratis si se respeta el contrato |

**Lo que no existe y hay que construir:** rastreo de `sitemap.xml`, parser de
JSON-LD, evaluación de `robots.txt` por user-agent de terceros, y medición de
tiempos en el cliente HTTP.

---

## 4. Estructura de archivos

```
idata_sentinel/
  modules/search_visibility/
    __init__.py
    module.py            # runner; declara scoring_domain = "visibility"
    registry.py          # registro explícito de checks (patrón existente)
    crawl.py             # presupuesto de rastreo y selección de páginas (§5)
  checks/
    seo_indexability.py  # robots, meta robots, canonical, sitemap, redirecciones
    seo_content.py       # title, description, encabezados, alt, hreflang, OG
    seo_local.py         # NAP, LocalBusiness, cobertura geográfica
    structured_data.py   # JSON-LD / microdatos — compartido SEO + GEO
    geo_readiness.py     # crawlers de IA, llms.txt, contenido sin JS, citabilidad
    performance.py       # tiempo de carga observable (§8)
  core/
    html_parse.py        # parser compartido, extraído de javascript.py
    sitemap.py           # descubrimiento y validación de sitemaps
  data/
    ai_crawlers.yaml     # catálogo de UAs de motores generativos
    schema_types.yaml    # tipos Schema.org esperados por giro de negocio
```

---

## 5. Presupuesto de rastreo: el límite que define el módulo

Con ≥2 s entre peticiones, **rastrear 50 páginas son 100 segundos de espera
pura**. Un módulo SEO ingenuo convertiría un escaneo de 3 minutos en uno de 20 y
haría inviable el monitoreo semanal de una cartera.

**Regla: el módulo opera con un presupuesto explícito de páginas, con un default
conservador.**

```
--seo-pages N     # default 8, máximo 50
```

Selección de las N páginas, en este orden:

1. La raíz (ya descargada, coste cero).
2. Hasta 3 URLs del `sitemap.xml`, priorizando las de `lastmod` más reciente.
3. Hasta 3 URLs enlazadas desde la navegación principal de la raíz.
4. Una URL inexistente generada al vuelo, para comprobar el manejo de 404
   (**única petición deliberada a una ruta que no existe**; no es fuzzing: es
   una sola URL, no adivina nada y no busca contenido oculto).

Toda página fuera del presupuesto se declara no rastreada, y el informe dice
cuántas quedaron fuera. **Nunca se presenta un análisis parcial como completo** —
es el mismo principio que ya aplica `asset_discovery_incomplete`.

---

## 6. Checks de SEO

### 6.1 `seo_indexability.py` — ¿pueden entrar y entender?

| Check | Qué detecta | Severidad |
|---|---|---|
| `robots_blocks_indexing` | `Disallow: /` para buscadores generales | critical |
| `meta_robots_noindex` | `noindex` en páginas que deberían indexarse | critical |
| `x_robots_tag_noindex` | Igual, vía cabecera | critical |
| `canonical_missing` | Sin `rel=canonical` | medium |
| `canonical_conflict` | Canonical que apunta fuera del sitio o a otra página | high |
| `sitemap_missing` | Sin `sitemap.xml` ni referencia en `robots.txt` | medium |
| `sitemap_invalid` | XML malformado, URLs 404, o mezcla http/https | medium |
| `www_apex_not_consolidated` | `www` y apex sirven 200 sin canonical entre sí | high |
| `redirect_chain_long` | Cadenas de 3+ saltos | low |
| `soft_404` | Página inexistente devuelve 200 | medium |
| `pagination_unmarked` | Paginación sin señales de continuidad | low |

`robots_blocks_indexing` y `meta_robots_noindex` son **críticos** porque no son
una mejora incremental: son la diferencia entre existir y no existir en el
índice. Es el equivalente, en este eje, a un certificado TLS vencido.

### 6.2 `seo_content.py` — ¿se entiende de qué trata?

- `title_missing` / `title_duplicated` / `title_length_suboptimal`
- `meta_description_missing` / `meta_description_duplicated`
- `h1_missing` / `h1_multiple` / `heading_hierarchy_broken`
- `images_without_alt` — con recuento y proporción, no solo presencia
- `lang_not_declared` — `<html lang>` ausente; relevante en un mercado bilingüe
- `hreflang_invalid` — si hay versiones por idioma
- `open_graph_incomplete` / `twitter_card_incomplete` — cómo se ve al compartirse
- `internal_links_orphan_page` — página sin enlaces entrantes internos
- `thin_content` — menos de N palabras visibles en el HTML servido

Sobre `thin_content`: se mide **conteo de palabras en el HTML servido**, no
calidad. El hallazgo dice exactamente eso y no pretende juzgar el texto.

### 6.3 `seo_local.py` — negocio con presencia física

Directamente aplicable a la cartera actual (estudios jurídicos, spa,
topografía), donde la búsqueda local decide la mayoría de los contactos:

- `local_business_schema_missing` — sin `LocalBusiness`/`ProfessionalService`
- `nap_inconsistent` — nombre, dirección o teléfono distintos entre páginas
- `phone_not_linked` — teléfono sin `tel:` (móvil no puede llamar con un toque)
- `address_not_marked_up` — dirección en texto plano sin `PostalAddress`
- `service_area_undeclared` — sin `areaServed` declarado
- `opening_hours_missing` — sin `openingHours`

### 6.4 `structured_data.py` — compartido SEO + GEO

Parser de **JSON-LD** (prioritario), microdatos y RDFa:

- `structured_data_missing` — ninguna anotación
- `structured_data_invalid` — JSON malformado o `@type` desconocido
- `structured_data_incomplete` — tipo presente sin propiedades requeridas
- `organization_schema_missing` — sin identidad de la organización
- `breadcrumb_missing`
- `faq_schema_absent_with_faq_content` — hay preguntas y respuestas visibles pero
  sin marcado que permita citarlas

`data/schema_types.yaml` mapea giro → tipos esperados, de modo que a un estudio
jurídico se le pida `ProfessionalService` y a una tienda `Product`/`Offer`, en
lugar de exigir lo mismo a todos.

---

## 7. Checks de GEO — `geo_readiness.py`

El corazón nuevo del módulo, y lo que ningún escáner de seguridad chileno
reporta hoy.

### 7.1 Acceso de los crawlers de IA (`ai_crawler_policy`)

`data/ai_crawlers.yaml` cataloga los agentes y a quién sirven:

| User-Agent | Motor | Para qué |
|---|---|---|
| `GPTBot` | OpenAI | Entrenamiento |
| `OAI-SearchBot` | OpenAI | Búsqueda y **citación en ChatGPT** |
| `ChatGPT-User` | OpenAI | Navegación a petición del usuario |
| `ClaudeBot` / `Claude-User` | Anthropic | Entrenamiento / navegación |
| `PerplexityBot` | Perplexity | Indexación y citación |
| `Google-Extended` | Google | Gemini y AI Overviews |
| `Applebot-Extended` | Apple | Apple Intelligence |
| `CCBot` | Common Crawl | Corpus de terceros |
| `Bytespider`, `meta-externalagent` | ByteDance, Meta | Entrenamiento |

**Este check informa, no prescribe.** Bloquear `GPTBot` para no ceder contenido
al entrenamiento es una decisión legítima de negocio; bloquear `OAI-SearchBot` o
`PerplexityBot` es renunciar a aparecer citado. El hallazgo distingue ambos y
deja la decisión al cliente:

- `ai_crawlers_blocked_from_citation` (**high**) — bloqueados los agentes de
  citación: el sitio no puede aparecer como fuente.
- `ai_crawlers_unrestricted` (**info**) — todo abierto, incluido entrenamiento;
  se señala como decisión a tomar conscientemente, no como falla.
- `ai_crawler_policy_absent` (**medium**) — `robots.txt` no menciona ninguno: el
  comportamiento queda al criterio de cada motor.

**Requiere extender `core/robots.py`**: hoy `can_fetch()` evalúa solo el UA
propio. Hace falta `can_fetch(path, user_agent=...)` para consultar por terceros.

### 7.2 `content_requires_javascript` (**high**)

La mayoría de los crawlers de motores generativos **no ejecutan JavaScript**. Si
el contenido se renderiza en cliente, para ellos la página está vacía.

Medición honesta y barata: proporción de texto visible en el HTML servido frente
al volumen de scripts. Un sitio con 300 palabras y 900 KB de JS que declara un
`<div id="root">` vacío es un caso claro. **Se reporta como indicio con
`confidence="medium"`**, no como certeza: la comprobación definitiva exige
renderizar, y eso es §8 capa 3.

Este check es el que conecta GEO con la realidad de la cartera: un sitio en
Next.js con renderizado en servidor está bien; una SPA pura es invisible.

### 7.3 `llms_txt_missing` (**low**)

Convención emergente (`/llms.txt`) para orientar a los modelos sobre qué contiene
el sitio y qué es citable. Adopción todavía parcial: **severidad baja y dicho
con honestidad** — es una apuesta barata, no un estándar consolidado. Prometer
más sería vender humo.

### 7.4 Citabilidad

- `author_not_identified` — sin autoría declarada ni `Person`/`Organization`
- `content_dates_missing` — sin fecha de publicación o actualización; un motor
  generativo prefiere fuentes fechadas
- `claims_without_sources` — afirmaciones sin enlaces salientes de respaldo
- `answer_structure_absent` — sin encabezados en forma de pregunta, listas ni
  tablas: el contenido es más difícil de extraer como respuesta
- `entity_ambiguity` — el nombre de la organización no está ligado a
  identificadores (`sameAs` a perfiles oficiales), lo que dificulta que el motor
  sepa de qué entidad habla

---

## 8. Rendimiento y tiempo de carga

El punto donde más fácil sería mentir, así que se separa en tres capas por lo
que **realmente** puede afirmar cada una.

### 8.1 Capa 1 — Observable sin navegador (por defecto)

Todo esto sale de las respuestas que el escaneo ya hace, más `HEAD` a los
recursos principales dentro del presupuesto:

| Check | Qué mide |
|---|---|
| `ttfb_slow` | Tiempo hasta el primer byte, medido en el cliente |
| `response_uncompressed` | Sin `gzip`/`br` en HTML, CSS o JS |
| `no_http2` | Servido por HTTP/1.1 |
| `cache_headers_missing` | Estáticos sin `Cache-Control` ni `ETag` |
| `html_oversized` | HTML por encima de un umbral configurable |
| `render_blocking_resources` | CSS y JS síncronos en `<head>` |
| `images_unoptimized` | Sin `width`/`height` (causa de reflow), sin `loading=lazy`, formatos legados con peso alto |
| `fonts_blocking` | Fuentes sin `font-display` ni precarga |
| `excessive_third_party_origins` | Número de orígenes externos contactados |
| `redirect_before_content` | La URL final se alcanza tras redirecciones |

**Requiere**: exponer el tiempo transcurrido en `FetchOutcome` (httpx ya lo
provee) y añadir `head()` al cliente HTTP si no está.

**Lo que esta capa NO puede decir, y el informe lo declara:** no hay LCP, CLS ni
INP. Son métricas de renderizado y **no existen sin navegador**. Un informe que
las presente a partir del peso de los recursos está inventando.

### 8.2 Capa 2 — Datos de campo vía CrUX (opt-in)

La **única** forma honesta de reportar Core Web Vitals reales: el Chrome UX
Report, que son mediciones de usuarios reales, consultables por la API de
PageSpeed Insights.

Se rige por la misma disciplina que `cve-sync` y el OSINT de filtraciones —las
dos capacidades que ya tocan servicios externos:

- **Opt-in explícito**, nunca por defecto: `--with-field-data`.
- Requiere `IDATA_PAGESPEED_API_KEY`. Sin clave, el check es no-op.
- **Envía la URL del objetivo a Google.** Se documenta sin eufemismos: es un
  dato del cliente saliendo hacia un tercero, y por eso exige decisión explícita.
- Si el dominio no tiene tráfico suficiente, CrUX no devuelve datos: se reporta
  **"sin datos de campo"**, jamás se sustituye por una estimación.

Hallazgos: `lcp_poor`, `inp_poor`, `cls_poor`, `field_data_unavailable`.

### 8.3 Capa 3 — Laboratorio con navegador (fase posterior)

Renderizado real con Chromium headless: confirma §7.2, permite medir en
laboratorio y capturar la página como la ve un usuario.

**Coste real que hay que reconocer antes de comprometerlo:** entre 300 MB y
1 GB en la imagen Docker, más memoria y tiempo por escaneo. Contradice el
principio de que el escaneo sea liviano y reproducible. **Se propone como
opcional y en fase separada**, nunca como dependencia del módulo base.

---

## 9. El índice de visibilidad

Mismo motor (`scoring/risk_engine.calculate`), aplicado al conjunto disjunto de
hallazgos con `scoring_domain == "visibility"`. Sin motor nuevo, sin pesos
nuevos, sin código nuevo que probar.

La semántica del contrato se mapea así, y se documenta en el módulo:

- `severity` → **impacto en la visibilidad**. `critical` = el sitio no puede ser
  indexado o citado; `high` = pierde presencia sustantiva; `medium`/`low` =
  mejoras incrementales.
- `likelihood` → **certeza del efecto**. `high` para reglas mecánicas (un
  `noindex` siempre desindexa); `medium` para señales correlacionales.
- `confidence` → igual que siempre: qué tan respaldada está la observación.

Categorías para el desglose por área: `Indexabilidad`, `Contenido`, `Datos
estructurados`, `SEO local`, `Motores generativos`, `Rendimiento`.

---

## 10. Encaje con reporting, monitoreo y app web

**Reporte PDF.** Sección nueva tras la de seguridad, con su propia nota y su
propio desglose. La portada muestra **dos indicadores separados y rotulados**:
`Seguridad 37/100 F` y `Visibilidad 68/100 D`. Nunca un promedio: promediarlos
inventaría un número que no significa nada.

**Monitoreo.** Encaja sin trabajo adicional si el contrato se respeta: el diff
existente detectará el día que desaparezca un `canonical`, se rompa el sitemap,
alguien publique un `noindex` en producción o se bloquee un crawler de citación.
Ese último caso —una regresión de SEO detectada el mismo día— es probablemente
el mayor argumento comercial del módulo.

**App web.** Pestaña propia por objetivo y columna de visibilidad en la cartera.

**CLI.** `MODULE_ALIASES["seo"] = "search_visibility"`, entrada en
`DEFAULT_MODULE_ORDER` (valor 50, después de privacidad), y ficha en
`data/module_help.yaml` con el mismo formato que los otros cuatro.

---

## 11. Errores y no evaluables

Se hereda la disciplina existente sin excepciones:

- Objetivo inalcanzable → todos los checks `unverified`, **sin nota de
  visibilidad**. Aplica aquí el mismo defecto ya identificado en el eje de
  seguridad: un objetivo que no responde no puede producir una nota alta.
- `robots.txt` bloquea el rastreo → se evalúa la raíz y se declara el resto no
  rastreado, con el bloqueo como hallazgo.
- Sitemap inaccesible → `sitemap_unreachable` no evaluable, no penaliza.
- CrUX sin datos → `field_data_unavailable`, informativo.
- Intersticial anti-bot → el módulo entero se salta, igual que los demás.

---

## 12. Testing

Sin red, con `respx`, igual que la suite actual. Fixtures HTML mínimos por check.

**Tests bloqueantes, los que protegen las decisiones de este plan:**

1. **Aislamiento de dominios**: un escaneo con hallazgos SEO críticos **no
   altera en un punto** el score de seguridad, y viceversa. Es el test que
   impide que §2 se rompa por accidente en un refactor futuro.
2. **Presupuesto de rastreo**: con `--seo-pages 3` se emiten como máximo 3
   peticiones de página, y las omitidas quedan declaradas.
3. **`robots.txt` se respeta** también en este módulo.
4. **CrUX es opt-in**: sin clave y sin flag, cero peticiones salientes. Test de
   red vacía, no de configuración.
5. **Ningún check inventa métricas de renderizado** en capa 1: se verifica que
   LCP/CLS/INP no aparecen en la salida sin datos de campo.

Cobertura ≥90%, igual que el resto.

---

## 13. Fases

### Fase 5a — Fundaciones *(el aislamiento primero)*

`scoring_domain` en el protocolo, agrupación en el engine, dos notas en CLI,
JSON y reporte. Módulo vacío registrado. **Se hace antes que cualquier check**:
si el aislamiento no está resuelto, el primer check ya contamina el score.

### Fase 5b — Indexabilidad y contenido

`core/sitemap.py`, `core/html_parse.py` extraído de `javascript.py`,
`seo_indexability.py` y `seo_content.py`, presupuesto de rastreo. Es el mínimo
que ya entrega valor a un cliente.

### Fase 5c — Datos estructurados y SEO local

`structured_data.py`, `seo_local.py`, `data/schema_types.yaml`. Lo de mayor
retorno inmediato para la cartera actual de negocios locales.

### Fase 5d — GEO

`data/ai_crawlers.yaml`, extensión de `core/robots.py` por user-agent,
`geo_readiness.py`. El diferenciador comercial del módulo.

### Fase 5e — Rendimiento capa 1

Tiempos en `FetchOutcome`, `head()` en el cliente, `performance.py`.

### Fase 5f — Rendimiento capa 2 (opt-in)

Integración con CrUX, flag, variable de entorno y documentación del envío de la
URL a un tercero.

### Fase 5g — Laboratorio con navegador *(opcional, evaluar antes de comprometer)*

Solo si el coste en imagen y tiempo se justifica frente a la capa 2.

---

## 14. Riesgos del plan

| Riesgo | Mitigación |
|---|---|
| **Contaminar el score de seguridad** | §2 + test bloqueante de aislamiento. Es el riesgo más grave del plan |
| **Duplicar parsers ya existentes** | §3: extraer a `core/` antes de escribir el primer check |
| **Escaneos que se vuelven lentísimos** | §5: presupuesto con default bajo y omisiones declaradas |
| **Prometer métricas que no se miden** | §8: tres capas separadas y declaración explícita de límites |
| **Convertir GEO en humo** | §7: solo señales medibles; `llms.txt` en `low` y dicho como apuesta |
| **Opinar sobre contenido** | §0: fuera de alcance, explícito |
