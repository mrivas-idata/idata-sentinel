"""Detección de páginas intersticiales anti-bot (challenge / WAF / captcha).

Cuando un servidor responde con una página de verificación en vez del sitio, lo
que el escáner tiene delante **no es el objetivo**. Si nadie lo detecta, todos
los checks que deducen del contenido o de las cabeceras de la aplicación
producen hallazgos falsos: "no tiene política de privacidad", "falta CSP",
"no hay formularios"… afirmados sobre una página de espera de 6 KB.

Es el mismo problema que ya documenta `http_client.DEFAULT_HEADERS` para las
respuestas 415, pero un escalón más arriba: ahí el servidor rechazaba la
petición, acá la acepta y devuelve 200 con una página que no es la suya.

En prospección esto es especialmente caro: el hallazgo falso se envía a un
prospecto que sabe perfectamente que su sitio sí tiene política de privacidad.

**No se evade el intersticial.** Detectarlo sirve para declarar el escaneo no
evaluable y decírselo al operador, nunca para saltárselo: resolver un challenge
anti-bot sería precisamente la evasión que el plan maestro prohíbe (§1.2).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

#: Marcadores en el cuerpo. Cada uno es una frase que un sitio real no publica
#: por accidente, junto al proveedor que la emite. Se buscan en minúsculas.
#:
#: Los WAF localizan la página de desafío según `Accept-Language`, y el nuestro
#: pide `es-CL` (`http_client.DEFAULT_HEADERS`): contra objetivos chilenos lo
#: habitual es recibirla en español, no en inglés. Una lista solo en inglés deja
#: pasar justo el caso para el que se construye esta herramienta.
_BODY_MARKERS: tuple[tuple[str, str], ...] = (
    # inglés
    ("just a moment", "Cloudflare"),
    ("checking your browser before accessing", "Cloudflare"),
    ("attention required! | cloudflare", "Cloudflare"),
    ("enable javascript and cookies to continue", "Cloudflare"),
    ("cf-browser-verification", "Cloudflare"),
    ("this process is automatic. your browser will redirect", "Cloudflare"),
    ("sucuri website firewall", "Sucuri"),
    ("incapsula incident id", "Imperva"),
    ("_incapsula_resource", "Imperva"),
    ("captcha-delivery.com", "DataDome"),
    ("px-captcha", "PerimeterX"),
    ("please wait while your request is being verified", "genérico"),
    ("one moment, please", "genérico"),
    ("verifying you are human", "genérico"),
    ("verify you are human", "genérico"),
    ("ddos protection by", "genérico"),
    ("your request is being processed", "genérico"),
    # español
    ("espere mientras se verifica su solicitud", "genérico"),
    ("espere mientras verificamos", "genérico"),
    ("comprobando su navegador antes de acceder", "Cloudflare"),
    ("verificando que usted es un ser humano", "Cloudflare"),
    ("verifique que usted es un ser humano", "Cloudflare"),
    ("activa javascript y las cookies para continuar", "Cloudflare"),
    ("estamos verificando su solicitud", "genérico"),
    ("su solicitud está siendo verificada", "genérico"),
    # portugués
    ("aguarde enquanto sua solicitação é verificada", "genérico"),
    ("verificando se você é humano", "Cloudflare"),
    ("ative o javascript e os cookies para continuar", "Cloudflare"),
)

#: Frases demasiado genéricas para buscarlas en el cuerpo —"un momento" aparece
#: en cualquier texto— pero concluyentes cuando son el **título** de una página
#: pequeña: ningún sitio real titula así su portada.
_TITLE_MARKERS: tuple[tuple[str, str], ...] = (
    ("un momento", "genérico"),
    ("one moment", "genérico"),
    ("just a moment", "Cloudflare"),
    ("please wait", "genérico"),
    ("por favor espere", "genérico"),
    ("aguarde um momento", "genérico"),
    ("attention required", "Cloudflare"),
)
# "Access denied" / "Acceso denegado" quedan deliberadamente fuera: un 403 del
# propio origen tampoco es evaluable, pero no es una página de desafío, y
# anunciarlo como tal sería describir mal lo que se observó.

#: Cabeceras que declaran el challenge sin ambigüedad. No necesitan corroboración
#: del cuerpo: el propio proveedor está diciendo que mitigó la petición.
_HEADER_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("cf-mitigated", "challenge", "Cloudflare"),
    ("x-sucuri-block", "", "Sucuri"),
    ("x-datadome", "", "DataDome"),
)

#: Un marcador dentro de una página grande casi siempre es texto editorial (un
#: artículo que *habla* de captchas), no un intersticial. Las páginas de
#: challenge son pequeñas. Por encima de este tamaño se exige una señal extra.
_SMALL_BODY_BYTES = 25_000

#: Códigos con los que un WAF suele servir el challenge.
_CHALLENGE_STATUS = frozenset({403, 429, 503})


@dataclass(frozen=True)
class InterstitialSignal:
    """Evidencia de que la respuesta observada es una página de verificación."""

    provider: str
    marker: str
    status_code: int
    evidence: str

    @property
    def summary(self) -> str:
        return (
            f"El servidor entrega una página de verificación anti-bot "
            f"({self.provider}, HTTP {self.status_code}) en vez del sitio."
        )


def _title_of(body: str) -> str:
    lowered = body.lower()
    start = lowered.find("<title")
    if start == -1:
        return ""
    open_end = lowered.find(">", start)
    end = lowered.find("</title>", open_end)
    if open_end == -1 or end == -1:
        return ""
    return body[open_end + 1 : end].strip()[:120]


def _body_of(response: "httpx.Response") -> str:
    content_type = response.headers.get("content-type", "")
    if content_type and not content_type.lower().startswith(("text/", "application/xhtml")):
        return ""
    try:
        return response.text
    except (UnicodeDecodeError, ValueError):
        return ""


def detect_interstitial(response: "httpx.Response | None") -> InterstitialSignal | None:
    """Devuelve la señal si la respuesta es un intersticial anti-bot, o `None`.

    Deliberadamente conservador: un falso positivo silenciaría checks legítimos y
    dejaría al operador sin diagnóstico, así que se exige una frase explícita de
    challenge, no una heurística de "la página parece corta".
    """
    if response is None:
        return None

    for header, expected, provider in _HEADER_MARKERS:
        value = response.headers.get(header)
        if value is not None and (not expected or expected in value.lower()):
            return InterstitialSignal(
                provider=provider,
                marker=f"{header}: {value}" if expected else header,
                status_code=response.status_code,
                evidence=f"Cabecera {header}={value!r} en HTTP {response.status_code}",
            )

    body = _body_of(response)
    if not body:
        return None

    lowered = body.lower()
    title = _title_of(body)
    lowered_title = title.lower()

    if len(body) <= _SMALL_BODY_BYTES:
        for marker, provider in _TITLE_MARKERS:
            if marker in lowered_title:
                return InterstitialSignal(
                    provider=provider,
                    marker=marker,
                    status_code=response.status_code,
                    evidence=(
                        f"HTTP {response.status_code}, título {title!r} en una página de "
                        f"{len(body)} bytes: es una página de desafío, no el sitio"
                    ),
                )

    for marker, provider in _BODY_MARKERS:
        if marker not in lowered:
            continue
        # Corroboración: página pequeña, código de challenge, o el marcador está
        # en el propio <title>. Sin esto, un artículo sobre WAF se marcaría solo.
        corroborated = (
            len(body) <= _SMALL_BODY_BYTES
            or response.status_code in _CHALLENGE_STATUS
            or marker in title.lower()
        )
        if not corroborated:
            continue
        return InterstitialSignal(
            provider=provider,
            marker=marker,
            status_code=response.status_code,
            evidence=(
                f"HTTP {response.status_code}, título {title!r}, "
                f"marcador {marker!r} en {len(body)} bytes de cuerpo"
            ),
        )

    return None
