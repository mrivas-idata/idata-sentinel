"""Tiempo de carga observable, y sus límites (plan SEO/GEO §8).

Este es el punto donde más fácil sería mentir, así que la separación es
explícita y aparece también en el informe:

- **Capa 1 (siempre)**: lo que se puede medir sin navegador — tiempo de
  respuesta, compresión, caché, peso, recursos que bloquean el render. Todo sale de peticiones que el escaneo ya hace o de `HEAD`.
- **Capa 2 (opt-in)**: Core Web Vitals reales desde el Chrome UX Report. Envía
  la URL del objetivo a un tercero, así que exige decisión explícita.

**LCP, CLS e INP no se pueden calcular sin renderizar.** Derivarlos del peso de
los recursos sería inventarlos, y este módulo no lo hace: sin datos de campo, el
informe dice que no hay datos de campo.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urljoin, urlparse

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import head_html, images, link_tags, scripts

_MODULE = "search_visibility"

#: Umbrales de tiempo hasta el primer byte. El de 1,8 s es el punto en que la
#: propia documentación de Google considera que hay un problema de servidor.
_TTFB_SLOW = 1.8
_TTFB_VERY_SLOW = 3.0
#: Peso de HTML a partir del cual conviene revisar qué se está sirviendo.
_HTML_LARGE_BYTES = 400_000
_MANY_THIRD_PARTY_ORIGINS = 8

_CRUX_ENDPOINT = "https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed"


class PerformanceCheck(BaseCheck):
    id = "performance"
    category = "Rendimiento"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        root = crawl.root if crawl else None
        if root is None or not root.ok:
            return [self._error_result(
                sub_id="performance_unreachable",
                reason="No se pudo obtener la página principal para medir el rendimiento.",
            )]

        out: list[CheckResult] = []
        out.extend(self._ttfb(root))
        out.extend(self._compression(root))
        out.extend(self._html_weight(root))
        out.extend(self._render_blocking(root))
        out.extend(self._images(root))
        out.extend(self._fonts(root))
        out.extend(self._third_parties(root))
        out.extend(await self._field_data(ctx, root))
        return out

    # -- capa 1: observable --------------------------------------------------

    def _ttfb(self, root) -> list[CheckResult]:
        elapsed = root.outcome.elapsed
        if elapsed is None:
            return []
        if elapsed < _TTFB_SLOW:
            return []
        very = elapsed >= _TTFB_VERY_SLOW
        return [self._result(
            sub_id="ttfb_slow",
            severity="medium" if very else "low",
            likelihood="high", status="fail" if very else "warning",
            confidence="medium",  # una sola muestra, desde una sola red
            title="El servidor tarda en responder",
            finding=(
                f"La respuesta de la portada tardó {elapsed:.2f} s en llegar. Es una medición "
                "única desde la red del escáner, no un promedio de usuarios reales."
            ),
            business_impact=(
                "El tiempo hasta el primer byte es el suelo de todo lo demás: nada puede "
                "empezar a dibujarse antes. Un servidor lento arrastra a toda la experiencia y "
                "es de lo poco que el buscador mide directamente."
            ),
            recommendation=(
                "Revisar caché de servidor, consultas a base de datos y plan de hosting. En "
                "WordPress, la caché de página suele bajar esto de forma inmediata."
            ),
            evidence=f"{elapsed:.2f} s", references=("Core Web Vitals — TTFB",),
        )]

    def _compression(self, root) -> list[CheckResult]:
        encoding = (root.outcome.response.headers.get("content-encoding") or "").lower()
        if encoding:
            return []
        size = len(root.outcome.response.content or b"")
        if size < 20_000:
            return []
        return [self._result(
            sub_id="response_uncompressed",
            severity="low", likelihood="high", status="warning",
            title="El HTML se sirve sin comprimir",
            finding=f"La portada ({size // 1024} KB) llega sin Content-Encoding.",
            business_impact=(
                "Comprimir texto reduce la transferencia entre un 60% y un 80%. Sin ello, cada "
                "visita descarga varias veces lo necesario, y en móvil eso es tiempo y datos."
            ),
            recommendation="Activar gzip o brotli para HTML, CSS y JavaScript en el servidor.",
            evidence=f"{size} bytes sin Content-Encoding", references=(),
        )]

    # El protocolo HTTP **no se reporta**: el cliente compartido no negocia
    # HTTP/2 (httpx solo lo hace con el extra `h2` instalado), así que toda
    # respuesta llega como HTTP/1.1 y el check habría marcado a todos los sitios
    # por igual —incluidos los que sí lo soportan—. Era un falso positivo
    # sistemático: describía una limitación nuestra como un defecto del cliente.
    # Para medirlo de verdad habría que habilitar h2 en `core/http_client.py`,
    # lo que cambia el comportamiento de todos los módulos y se decide aparte.

    def _html_weight(self, root) -> list[CheckResult]:
        size = len(root.outcome.response.content or b"")
        if size < _HTML_LARGE_BYTES:
            return []
        return [self._result(
            sub_id="html_oversized",
            severity="low", likelihood="medium", status="warning",
            title="El HTML de la portada es muy pesado",
            finding=f"La portada pesa {size // 1024} KB de HTML.",
            business_impact=(
                "Un HTML muy grande retrasa el primer dibujado incluso con buena conexión, "
                "porque el navegador tiene que parsearlo entero antes de mostrar el contenido."
            ),
            recommendation="Revisar contenido en línea, estilos incrustados y HTML generado de más.",
            evidence=f"{size} bytes", references=(),
        )]

    def _render_blocking(self, root) -> list[CheckResult]:
        head = head_html(root.html)
        blocking_scripts = [s for s in scripts(head) if s.blocking]
        stylesheets = [
            t for t in link_tags(head, rel="stylesheet")
            if not t.get("media", "").lower() in ("print",)
        ]
        total = len(blocking_scripts) + len(stylesheets)
        if total < 4:
            return []
        return [self._result(
            sub_id="render_blocking_resources",
            severity="low", likelihood="high", status="warning",
            title="Hay recursos que bloquean el primer dibujado",
            finding=(
                f"En <head> hay {len(blocking_scripts)} script(s) sin async/defer y "
                f"{len(stylesheets)} hoja(s) de estilo."
            ),
            business_impact=(
                "El navegador no dibuja nada hasta descargar y procesar cada uno de estos "
                "recursos, en orden. Es la causa más frecuente de una página en blanco al abrir."
            ),
            recommendation=(
                "Añadir `defer` a los scripts no críticos y cargar el CSS no esencial aparte."
            ),
            evidence=f"{len(blocking_scripts)} scripts + {len(stylesheets)} hojas de estilo",
            references=(),
        )]

    def _images(self, root) -> list[CheckResult]:
        imgs = images(root.html)
        if not imgs:
            return []
        no_dims = [i for i in imgs if not i.has_dimensions]
        not_lazy = [i for i in imgs if not i.lazy]
        out: list[CheckResult] = []

        if len(no_dims) > 2:
            out.append(self._result(
                sub_id="images_without_dimensions",
                severity="low", likelihood="high", status="warning",
                title="Imágenes sin ancho y alto declarados",
                finding=f"{len(no_dims)} de {len(imgs)} imágenes no declaran width/height.",
                business_impact=(
                    "El navegador no sabe cuánto espacio reservar y el contenido salta cuando "
                    "cada imagen carga. Es la causa directa del desplazamiento de diseño, que "
                    "además de molesto hace que la gente pulse donde no quería."
                ),
                recommendation="Declarar width y height (o aspect-ratio) en cada <img>.",
                evidence="; ".join(i.src[:50] for i in no_dims[:3])[:250],
                references=("Core Web Vitals — CLS",),
            ))

        if len(imgs) > 5 and len(not_lazy) == len(imgs):
            out.append(self._result(
                sub_id="images_not_lazy",
                severity="low", likelihood="medium", status="warning",
                title="Ninguna imagen usa carga diferida",
                finding=f"Las {len(imgs)} imágenes de la portada se cargan de inmediato.",
                business_impact=(
                    "Se descargan también las que están fuera de pantalla, compitiendo por el "
                    "ancho de banda con lo que el usuario sí está viendo."
                ),
                recommendation="Añadir loading=\"lazy\" a las imágenes que no estén en pantalla al abrir.",
                evidence=f"{len(imgs)} imágenes sin loading=lazy", references=(),
            ))
        return out

    def _fonts(self, root) -> list[CheckResult]:
        font_links = [
            t for t in link_tags(root.html)
            if "font" in (t.get("as", "") + t.get("type", "") + t.get("href", "")).lower()
        ]
        if not font_links:
            return []
        preloaded = any("preload" in t.get("rel", "").lower() for t in font_links)
        has_display = "font-display" in root.html.lower()
        if preloaded or has_display:
            return []
        return [self._result(
            sub_id="fonts_blocking",
            severity="low", likelihood="medium", status="warning",
            title="Las fuentes web pueden retrasar el texto",
            finding=(
                f"Se cargan {len(font_links)} recurso(s) de fuentes sin `font-display` ni precarga."
            ),
            business_impact=(
                "Mientras la fuente descarga, el navegador puede dejar el texto invisible. El "
                "usuario ve la maqueta sin palabras durante ese tiempo."
            ),
            recommendation="Usar font-display: swap y precargar la fuente principal.",
            evidence="; ".join(t.get("href", "")[:60] for t in font_links[:3])[:250],
            references=(),
        )]

    def _third_parties(self, root) -> list[CheckResult]:
        base_host = (urlparse(root.url).hostname or "").lower()
        origins = set()
        for tag in scripts(root.html):
            if not tag.src:
                continue
            host = (urlparse(urljoin(root.url, tag.src)).hostname or "").lower()
            if host and host != base_host:
                origins.add(host)
        for tag in link_tags(root.html):
            href = tag.get("href", "")
            if not href.startswith("http"):
                continue
            host = (urlparse(href).hostname or "").lower()
            if host and host != base_host:
                origins.add(host)

        if len(origins) < _MANY_THIRD_PARTY_ORIGINS:
            return []
        return [self._result(
            sub_id="excessive_third_party_origins",
            severity="low", likelihood="medium", status="warning",
            title="La página depende de muchos orígenes externos",
            finding=f"Se contactan {len(origins)} dominios de terceros para dibujar la portada.",
            business_impact=(
                "Cada origen añade resolución DNS y negociación TLS antes de su primer byte, y "
                "cada uno puede caerse o ponerse lento por su cuenta. Además amplía la "
                "superficie de terceros con acceso a la página."
            ),
            recommendation="Reducir dependencias externas o servir localmente las imprescindibles.",
            evidence="; ".join(sorted(origins)[:6])[:300], references=(),
        )]

    # -- capa 2: datos de campo (opt-in) -------------------------------------

    async def _field_data(self, ctx, root) -> list[CheckResult]:
        """Core Web Vitals reales desde CrUX. Nunca por defecto.

        Requiere las dos cosas: que el operador lo pida y que haya clave. Sin
        ambas, el check no emite ni una petición saliente — el objetivo del
        cliente no viaja a un tercero por descuido de configuración.
        """
        if not getattr(ctx, "field_data_enabled", False):
            return []
        api_key = os.environ.get("IDATA_PAGESPEED_API_KEY", "").strip()
        if not api_key:
            return [self._result(
                sub_id="field_data_not_configured",
                severity="info", likelihood="low", status="info", confidence="unverified",
                title="Datos de campo pedidos pero sin clave configurada",
                finding=(
                    "Se pidió --with-field-data pero IDATA_PAGESPEED_API_KEY no está definida, "
                    "así que no se consultó nada."
                ),
                business_impact="No se pudo medir; no representa un hallazgo sobre el sitio.",
                recommendation="Definir IDATA_PAGESPEED_API_KEY para consultar el Chrome UX Report.",
                evidence="IDATA_PAGESPEED_API_KEY ausente", references=(),
            )]

        url = f"{_CRUX_ENDPOINT}?url={root.url}&key={api_key}&strategy=mobile"
        outcome = await ctx.http.get(url)
        if not outcome.ok or outcome.response.status_code != 200:
            return [self._unavailable("La consulta al Chrome UX Report no se pudo completar.")]

        try:
            payload = json.loads(outcome.response.text or "{}")
        except json.JSONDecodeError:
            return [self._unavailable("La respuesta del Chrome UX Report no se pudo interpretar.")]

        metrics = (payload.get("loadingExperience") or {}).get("metrics") or {}
        if not metrics:
            return [self._unavailable(
                "El dominio no acumula suficiente tráfico real para que existan datos de campo."
            )]

        out: list[CheckResult] = []
        for key, sub_id, label in (
            ("LARGEST_CONTENTFUL_PAINT_MS", "lcp_poor", "LCP"),
            ("INTERACTION_TO_NEXT_PAINT", "inp_poor", "INP"),
            ("CUMULATIVE_LAYOUT_SHIFT_SCORE", "cls_poor", "CLS"),
        ):
            metric = metrics.get(key)
            if not metric:
                continue
            category = metric.get("category", "")
            if category not in ("SLOW", "AVERAGE"):
                continue
            out.append(self._result(
                sub_id=sub_id,
                severity="medium" if category == "SLOW" else "low",
                likelihood="high", status="fail" if category == "SLOW" else "warning",
                confidence="confirmed",  # usuarios reales, no una estimación nuestra
                title=f"{label} fuera del umbral recomendado",
                finding=(
                    f"El Chrome UX Report clasifica {label} como {category} para este sitio, "
                    f"con percentil 75 en {metric.get('percentile')}."
                ),
                business_impact=(
                    "Son mediciones de usuarios reales, no de laboratorio: es la experiencia que "
                    "efectivamente tiene la gente, y la que el buscador considera."
                ),
                recommendation=f"Revisar las causas de {label} con PageSpeed Insights sobre la URL.",
                evidence=f"{label}={metric.get('percentile')} ({category})",
                references=("Chrome UX Report",),
            ))
        return out

    def _unavailable(self, reason: str) -> CheckResult:
        """Sin datos de campo se dice que no los hay. Nunca se estiman."""
        return self._result(
            sub_id="field_data_unavailable",
            severity="info", likelihood="low", status="info", confidence="unverified",
            title="Sin datos de campo de usuarios reales",
            finding=(
                f"{reason} LCP, INP y CLS no se reportan: son métricas de renderizado y no "
                "existen sin navegador ni sin tráfico real. Estimarlas a partir del peso de los "
                "recursos sería inventarlas."
            ),
            business_impact="No se pudo medir; no representa un hallazgo sobre el sitio.",
            recommendation="Volver a consultar cuando el sitio acumule tráfico suficiente.",
            evidence=reason[:200], references=("Chrome UX Report",),
        )
