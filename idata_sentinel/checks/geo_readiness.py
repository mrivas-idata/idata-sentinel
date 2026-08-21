"""Preparación para motores generativos — GEO (plan SEO/GEO §7).

Mide si ChatGPT, Claude, Perplexity y los AI Overviews pueden leer el sitio,
entenderlo y citarlo. Es la superficie que ningún escáner de seguridad reporta
hoy y la que más rápido está cambiando: una proporción creciente de las
consultas termina en una respuesta generada, sin visita al sitio de origen.

Todo lo que hay aquí es observable de forma pasiva. Lo que no se puede medir sin
renderizar se declara como indicio, no como certeza.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import (
    headings,
    json_ld_blocks,
    meta_content,
    schema_types,
    scripts,
    visible_text,
    word_count,
)

_MODULE = "search_visibility"
_CRAWLERS = Path(__file__).resolve().parent.parent / "data" / "ai_crawlers.yaml"

#: Bajo estas palabras, una página servida sin renderizar no tiene qué citar.
_MIN_WORDS_FOR_CONTENT = 120
#: Proporción texto/script a partir de la cual la página parece un contenedor
#: vacío que se rellena en el navegador.
_JS_HEAVY_RATIO = 40


def _catalog() -> list[dict]:
    if not _CRAWLERS.exists():
        return []
    return yaml.safe_load(_CRAWLERS.read_text(encoding="utf-8")) or []


class GeoReadinessCheck(BaseCheck):
    id = "geo_readiness"
    category = "Motores generativos"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        root = crawl.root if crawl else None
        if root is None or not root.html:
            return [self._error_result(
                sub_id="geo_readiness_unreachable",
                reason="No se obtuvo HTML de la portada para evaluar la preparación GEO.",
            )]

        out: list[CheckResult] = []
        out.extend(self._crawler_policy(ctx))
        out.extend(await self._llms_txt(ctx))
        out.extend(self._requires_javascript(root))
        out.extend(self._citability(crawl))
        return out

    # -- acceso de los crawlers de IA ---------------------------------------

    def _crawler_policy(self, ctx) -> list[CheckResult]:
        """Informa, no prescribe.

        Bloquear el entrenamiento es una decisión editorial legítima; bloquear la
        citación es renunciar a aparecer como fuente. Presentarlas como si fueran
        el mismo problema sería empujar al cliente a una decisión que es suya.
        """
        robots = ctx.robots
        agents = _catalog()
        if not agents:
            return []

        blocked_citation, blocked_training, named = [], [], []
        for entry in agents:
            agent = entry["agent"]
            allowed = robots.can_fetch("/", user_agent=agent)
            if robots.names_agent(agent):
                named.append(agent)
            if allowed:
                continue
            (blocked_citation if entry.get("purpose") == "citation" else blocked_training).append(
                f"{agent} ({entry.get('vendor', '')})".strip()
            )

        out: list[CheckResult] = []

        if blocked_citation:
            out.append(self._result(
                sub_id="ai_crawlers_blocked_from_citation",
                severity="high", likelihood="high", status="fail",
                title="El sitio se excluye de ser citado por los motores generativos",
                finding=(
                    "robots.txt bloquea a agentes que alimentan respuestas con enlace a la "
                    f"fuente: {', '.join(blocked_citation)}."
                ),
                business_impact=(
                    "Cuando alguien pregunte por este servicio a un asistente, el sitio no puede "
                    "aparecer entre las fuentes. No es una pérdida de posiciones: es ausencia de "
                    "una superficie completa, y crece cada mes."
                ),
                recommendation=(
                    "Permitir los agentes de citación en robots.txt. Es compatible con seguir "
                    "bloqueando los de entrenamiento, si esa es la decisión del negocio."
                ),
                evidence="; ".join(blocked_citation)[:300], references=("robots.txt",),
            ))

        if blocked_training:
            out.append(self._result(
                sub_id="ai_crawlers_blocked_from_training",
                severity="info", likelihood="low", status="info",
                title="El sitio se excluye del entrenamiento de modelos",
                finding=f"robots.txt bloquea agentes de entrenamiento: {', '.join(blocked_training)}.",
                business_impact=(
                    "Decisión editorial legítima y sin efecto en la visibilidad: estos agentes "
                    "no producen citas. Se informa para dejar constancia de que es deliberado."
                ),
                recommendation="Ninguna acción; confirmar que la exclusión sea intencional.",
                evidence="; ".join(blocked_training)[:300], references=("robots.txt",),
            ))

        if not named:
            out.append(self._result(
                sub_id="ai_crawler_policy_absent",
                severity="medium", likelihood="medium", status="fail",
                title="Sin política declarada para los motores generativos",
                finding=(
                    "robots.txt no menciona ninguno de los agentes de IA conocidos, así que cada "
                    "motor decide por su cuenta qué hacer con el contenido del sitio."
                ),
                business_impact=(
                    "El negocio no ha tomado una decisión que ya le están tomando otros: hoy su "
                    "contenido puede usarse para entrenar modelos, y mañana un cambio de política "
                    "de cualquier motor lo deja fuera de las citas sin aviso."
                ),
                recommendation=(
                    "Declarar explícitamente en robots.txt qué agentes se permiten. Lo habitual "
                    "es permitir los de citación y decidir aparte los de entrenamiento."
                ),
                evidence="Sin User-agent de motores generativos en robots.txt",
                references=("robots.txt",),
            ))

        return out

    # -- llms.txt ------------------------------------------------------------

    async def _llms_txt(self, ctx) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/llms.txt")
        if outcome.ok and outcome.response.status_code == 200:
            return []
        return [self._result(
            sub_id="llms_txt_missing",
            severity="low", likelihood="low", status="warning",
            title="Sin /llms.txt",
            finding="No se encontró /llms.txt en el sitio.",
            business_impact=(
                "Es una convención emergente para indicarle a los modelos qué contiene el sitio "
                "y qué conviene citar. Su adopción todavía es parcial: publicarlo es una apuesta "
                "barata, no un estándar consolidado, y no tenerlo hoy no penaliza."
            ),
            recommendation="Publicar /llms.txt con un índice del contenido citable, si interesa adelantarse.",
            evidence="/llms.txt", references=("llmstxt.org",),
        )]

    # -- contenido que exige JavaScript --------------------------------------

    def _requires_javascript(self, root) -> list[CheckResult]:
        """La mayoría de los crawlers generativos no ejecuta JavaScript.

        Se reporta como **indicio** con `confidence="medium"`: confirmarlo exige
        renderizar la página, y este escaneo no lo hace. Afirmarlo como certeza
        sería exactamente el tipo de sobreafirmación que el producto evita.
        """
        html = root.html
        words = word_count(html)
        script_bytes = sum(len(s.body) for s in scripts(html))
        text_bytes = len(visible_text(html))
        ratio = (script_bytes / text_bytes) if text_bytes else float("inf")

        if words >= _MIN_WORDS_FOR_CONTENT and ratio < _JS_HEAVY_RATIO:
            return []

        return [self._result(
            sub_id="content_requires_javascript",
            severity="high", likelihood="medium", status="fail", confidence="medium",
            title="El contenido parece depender de JavaScript para existir",
            finding=(
                f"El HTML servido trae {words} palabras visibles frente a {script_bytes} bytes de "
                "JavaScript en línea. Es un indicio de que el contenido se construye en el "
                "navegador; confirmarlo exige renderizar la página, que este escaneo no hace."
            ),
            business_impact=(
                "Los crawlers de los motores generativos no ejecutan JavaScript: si el contenido "
                "solo aparece tras renderizar, para ellos la página está vacía y el sitio no "
                "puede ser citado ni resumido, por bueno que sea el contenido."
            ),
            recommendation=(
                "Servir el contenido principal ya renderizado desde el servidor. En los "
                "frameworks actuales es una opción de configuración, no una reescritura."
            ),
            evidence=f"{words} palabras / {script_bytes} bytes de JS en línea",
            references=("Google Search Central — JavaScript SEO",),
        )]

    # -- citabilidad ---------------------------------------------------------

    def _citability(self, crawl: CrawlResult) -> list[CheckResult]:
        out: list[CheckResult] = []
        root = crawl.root
        html = root.html
        blocks, _ = json_ld_blocks(html)
        types = schema_types(blocks)

        if not _author_declared(html, blocks, types):
            out.append(self._result(
                sub_id="author_not_identified",
                severity="medium", likelihood="medium", status="fail",
                title="El contenido no declara quién lo firma",
                finding=(
                    "No se encontró autoría: ni `<meta name=\"author\">`, ni nodos Person u "
                    "`author` en los datos estructurados."
                ),
                business_impact=(
                    "Un motor generativo prefiere citar fuentes atribuibles. Sin autoría "
                    "declarada, el contenido queda como texto sin respaldo frente a "
                    "competidores que sí la publican — y en servicios profesionales, quién "
                    "firma es justamente el argumento de venta."
                ),
                recommendation="Declarar autor y organización responsable en el marcado.",
                evidence="Sin author ni Person", references=("schema.org/author",),
            ))

        if not _dates_declared(html, blocks):
            out.append(self._result(
                sub_id="content_dates_missing",
                severity="low", likelihood="medium", status="warning",
                title="El contenido no está fechado",
                finding="No se declara fecha de publicación ni de actualización.",
                business_impact=(
                    "Los motores generativos priorizan lo reciente y lo verificable. Sin fecha, "
                    "el contenido compite en desventaja frente a fuentes fechadas."
                ),
                recommendation="Publicar datePublished y dateModified en los datos estructurados.",
                evidence="Sin datePublished/dateModified", references=("schema.org/datePublished",),
            ))

        if not _same_as(blocks):
            out.append(self._result(
                sub_id="entity_ambiguity",
                severity="low", likelihood="medium", status="warning",
                title="La organización no está ligada a sus perfiles oficiales",
                finding="Los datos estructurados no declaran `sameAs` con perfiles verificables.",
                business_impact=(
                    "`sameAs` es lo que le permite a un motor confirmar que este sitio y ese "
                    "perfil son la misma entidad. Sin eso, un negocio de nombre parecido puede "
                    "quedarse con la mención."
                ),
                recommendation="Añadir `sameAs` con los perfiles oficiales del negocio.",
                evidence="Sin sameAs", references=("schema.org/sameAs",),
            ))

        if not _answer_structured(crawl):
            out.append(self._result(
                sub_id="answer_structure_absent",
                severity="low", likelihood="low", status="warning",
                title="El contenido no está estructurado como respuestas",
                finding=(
                    "No se encontraron encabezados en forma de pregunta, listas ni tablas en las "
                    "páginas analizadas."
                ),
                business_impact=(
                    "Un motor generativo extrae mejor lo que ya viene en unidades: una pregunta "
                    "con su respuesta, una lista de pasos, una tabla de precios. El texto "
                    "corrido es más difícil de citar."
                ),
                recommendation="Estructurar el contenido clave en preguntas, listas y tablas.",
                evidence="Sin encabezados interrogativos, <ul>/<ol> ni <table>", references=(),
            ))
        return out


def _author_declared(html: str, blocks: list, types: set[str]) -> bool:
    if meta_content(html, name="author"):
        return True
    if any(t.lower() == "person" for t in types):
        return True
    return any(node.get("author") for node in _all_nodes(blocks))


def _dates_declared(html: str, blocks: list) -> bool:
    if meta_content(html, prop="article:published_time"):
        return True
    return any(
        node.get("datePublished") or node.get("dateModified") for node in _all_nodes(blocks)
    )


def _same_as(blocks: list) -> bool:
    return any(node.get("sameAs") for node in _all_nodes(blocks))


def _all_nodes(blocks: list) -> list[dict]:
    out: list[dict] = []

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            out.append(node)
            for value in node.values():
                if isinstance(value, (dict, list)):
                    walk(value)

    walk(blocks)
    return out


def _answer_structured(crawl: CrawlResult) -> bool:
    for page in crawl.html_pages:
        html = page.html
        if "<table" in html.lower() or "<ul" in html.lower() or "<ol" in html.lower():
            return True
        if any(h.text.strip().endswith("?") or h.text.strip().startswith("¿") for h in headings(html)):
            return True
    return False
