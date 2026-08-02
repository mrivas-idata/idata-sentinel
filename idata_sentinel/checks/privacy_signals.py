"""Señales técnicas de privacidad — Módulo 3, Ley 21.719 (plan maestro §5).

Evalúa lo **observable**: cómo se capturan datos personales, si hay aviso de
privacidad enlazado, si se pide consentimiento antes de activar rastreadores y a
qué terceros se transfieren datos. No sustituye la asesoría legal formal (§5).

Regla anti-fuzzing (§2.5): la política de privacidad se busca **en los enlaces que
la propia página publica**, nunca adivinando rutas por diccionario.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin, urlparse

import yaml

from idata_sentinel.core.check_base import BaseCheck, CheckResult

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_FORM_BLOCK = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
_FIELD = re.compile(r"<(?:input|select|textarea)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_ANCHOR = re.compile(r"<a\b(?P<attrs>[^>]*)>(?P<text>.*?)</a>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC = re.compile(r"""<(?:script|iframe|img)\b[^>]*\b(?:src)\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")

#: Categorías de datos personales detectables por el nombre del campo.
#: Las marcadas en `SENSITIVE_CATEGORIES` son "datos sensibles" bajo la Ley
#: 21.719 y exigen consentimiento explícito.
PII_PATTERNS: dict[str, re.Pattern] = {
    "rut": re.compile(r"\b(rut|run|dni|cedula|identidad)\b", re.IGNORECASE),
    "email": re.compile(r"(e-?mail|correo)", re.IGNORECASE),
    "telefono": re.compile(r"(phone|tel|telefono|fono|celular|movil|whatsapp)", re.IGNORECASE),
    "nombre": re.compile(r"(nombre|apellido|first-?name|last-?name|surname|fullname|\bname\b)", re.IGNORECASE),
    "direccion": re.compile(r"(direccion|address|domicilio|comuna|ciudad|region|postal|zip)", re.IGNORECASE),
    "fecha_nacimiento": re.compile(r"(birth|nacimiento|fecha-?nac|edad|\bage\b)", re.IGNORECASE),
    "salud": re.compile(r"(salud|health|isapre|fonasa|prevision|diagnostic|enfermedad|medic|discapacidad)", re.IGNORECASE),
    "biometrico": re.compile(r"(huella|biometric|facial|iris|\badn\b|genetic)", re.IGNORECASE),
    # `politic` a secas matchea "política de privacidad" — el texto más común
    # cerca de cualquier formulario— y disparaba un `high` falso de "recolecta
    # ideología". Se exige contexto de opinión/afiliación política real; "política"
    # como sinónimo de "policy" ya no cuenta.
    "ideologia": re.compile(
        r"(\breligion\b|\bcredo\b|afiliacion[-_ ]?polit|opinion[-_ ]?polit|"
        r"militancia|partido[-_ ]?polit|ideolog|\bsindicat|creencia[-_ ]?relig)",
        re.IGNORECASE,
    ),
    "vida_sexual": re.compile(r"(orientacion-?sexual|sexual-?orientation|identidad-?genero)", re.IGNORECASE),
    "origen_etnico": re.compile(r"(etnia|etnico|raza|racial|pueblo-?originario|nacionalidad)", re.IGNORECASE),
    "socioeconomico": re.compile(r"(renta|ingreso|salario|sueldo|patrimonio|deuda|tarjeta|banco|cuenta-?corriente)", re.IGNORECASE),
}

#: Art. 2 lit. g) Ley 21.719 + el tratamiento especial de la situación socioeconómica.
SENSITIVE_CATEGORIES = frozenset(
    {"salud", "biometrico", "ideologia", "vida_sexual", "origen_etnico", "socioeconomico"}
)

#: Firmas de plataformas de gestión de consentimiento (CMP) y de banners genéricos.
CONSENT_SIGNATURES = (
    "onetrust", "otsdkstub", "cookiebot", "cookieyes", "cookie-law-info",
    "osano", "quantcast", "didomi", "termly", "iubenda", "complianz",
    "cookieconsent", "cookie-consent", "cookie-banner", "cookiebanner",
    "aceptar cookies", "acepto las cookies", "gestionar cookies",
    "politica de cookies", "usamos cookies", "utilizamos cookies",
)

#: Reconoce el enlace a la política de privacidad. Incluye las convenciones
#: chilenas habituales ("Políticas y Condiciones", "Aviso Legal"): muchos sitios
#: pequeños ponen el tratamiento de datos ahí y no en una página rotulada
#: "Privacidad". No incluye "términos y condiciones" a secas —que legalmente no es
#: una política de privacidad— para no dar por cubierto lo que no lo está.
_PRIVACY_LINK_PATTERN = re.compile(
    r"(privacidad|privacy|proteccion[-_ ]?de[-_ ]?datos|data[-_ ]?protection|"
    r"tratamiento[-_ ]?de[-_ ]?datos|politica[-_ ]?de[-_ ]?datos|"
    r"politicas?[-_ ]?y[-_ ]?condiciones|aviso[-_ ]?legal|aviso[-_ ]?de[-_ ]?privacidad)",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def _load_trackers() -> list[dict]:
    return yaml.safe_load((_DATA_DIR / "trackers.yaml").read_text(encoding="utf-8")) or []


def normalize(text: str) -> str:
    """Quita tildes para que los patrones ASCII reconozcan 'Dirección',
    'Política de cookies' o 'teléfono' tal como aparecen en un sitio chileno."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _attrs_of(raw: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _ATTR.finditer(raw):
        key = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        attrs[key] = value
    return attrs


@dataclass(frozen=True)
class FormField:
    name: str
    type: str
    haystack: str

    @property
    def is_password(self) -> bool:
        return self.type == "password"


@dataclass(frozen=True)
class Form:
    action: str
    absolute_action: str
    method: str
    fields: tuple[FormField, ...] = ()
    snippet: str = ""
    pii_categories: frozenset[str] = field(default_factory=frozenset)

    @property
    def collects_pii(self) -> bool:
        return bool(self.pii_categories)

    @property
    def sensitive_categories(self) -> frozenset[str]:
        return frozenset(self.pii_categories & SENSITIVE_CATEGORIES)

    @property
    def is_insecure(self) -> bool:
        return urlparse(self.absolute_action).scheme == "http"

    @property
    def has_password(self) -> bool:
        return any(f.is_password for f in self.fields)


def detect_pii_categories(fields: tuple[FormField, ...]) -> frozenset[str]:
    found = set()
    for field_ in fields:
        haystack = normalize(field_.haystack)
        for category, pattern in PII_PATTERNS.items():
            if pattern.search(haystack):
                found.add(category)
    return frozenset(found)


def parse_forms(html: str, base_url: str) -> list[Form]:
    forms: list[Form] = []
    for block in _FORM_BLOCK.finditer(html):
        attrs = _attrs_of(block.group("attrs"))
        body = block.group("body")

        fields: list[FormField] = []
        for raw_field in _FIELD.finditer(body):
            field_attrs = _attrs_of(raw_field.group("attrs"))
            haystack = " ".join(
                field_attrs.get(key, "")
                for key in ("name", "id", "placeholder", "autocomplete", "aria-label", "type")
            )
            fields.append(FormField(
                name=field_attrs.get("name", ""),
                type=field_attrs.get("type", "text").lower(),
                haystack=haystack,
            ))

        # El texto visible del formulario (labels) también delata qué se pide.
        label_text = _TAG.sub(" ", body)
        fields.append(FormField(name="", type="label", haystack=label_text[:2000]))

        action = attrs.get("action", "")
        forms.append(Form(
            action=action,
            absolute_action=urljoin(base_url, action) if action else base_url,
            method=attrs.get("method", "get").lower(),
            fields=tuple(fields),
            snippet=block.group(0)[:300],
            pii_categories=detect_pii_categories(tuple(fields)),
        ))
    return forms


def detect_consent_banner(html: str) -> str | None:
    lowered = normalize(html.lower())
    for signature in CONSENT_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def find_privacy_policy_links(html: str, base_url: str) -> list[str]:
    """Solo enlaces que la página ya publica — nunca rutas adivinadas (§2.5)."""
    links: list[str] = []
    for match in _ANCHOR.finditer(html):
        attrs = _attrs_of(match.group("attrs"))
        href = attrs.get("href", "")
        text = _TAG.sub(" ", match.group("text"))
        if not href or href.startswith(("javascript:", "mailto:", "#")):
            continue
        if _PRIVACY_LINK_PATTERN.search(normalize(href)) or _PRIVACY_LINK_PATTERN.search(normalize(text)):
            absolute = urljoin(base_url, href)
            if absolute not in links:
                links.append(absolute)
    return links


@dataclass(frozen=True)
class TrackerHit:
    name: str
    kind: str
    abroad: bool
    controller: str
    evidence: str


def detect_trackers(html: str) -> list[TrackerHit]:
    sources = [m.group(1) for m in _SCRIPT_SRC.finditer(html)]
    haystack = html.lower()

    hits: list[TrackerHit] = []
    for tracker in _load_trackers():
        for pattern in tracker.get("patterns", []):
            lowered = pattern.lower()
            evidence = next((s for s in sources if lowered in s.lower()), None)
            if evidence is None and lowered in haystack:
                evidence = pattern
            if evidence:
                hits.append(TrackerHit(
                    name=tracker["name"],
                    kind=tracker.get("kind", "analytics"),
                    abroad=bool(tracker.get("abroad")),
                    controller=tracker.get("controller", "desconocido"),
                    evidence=evidence[:200],
                ))
                break
    return hits


def third_party_cookies(set_cookies: tuple[str, ...], host: str) -> list[str]:
    """Cookies cuyo atributo Domain apunta fuera del dominio del sitio."""
    out: list[str] = []
    registrable = ".".join(host.lower().split(".")[-2:])
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        domain = ""
        for part in raw.split(";")[1:]:
            key, _, value = part.partition("=")
            if key.strip().lower() == "domain":
                domain = value.strip().lstrip(".").lower()
        if domain and not domain.endswith(registrable):
            out.append(f"{name} (Domain={domain})")
    return out


# ---------------------------------------------------------------------------
# Checks (contrato estándar del plan maestro §2)
# ---------------------------------------------------------------------------

_LEGAL_NOTE = (
    "Evaluación de señales técnicas observables; no constituye una calificación "
    "legal formal de cumplimiento de la Ley 21.719."
)


class PrivacyFormsCheck(BaseCheck):
    """Formularios que capturan datos personales: transporte, aviso de privacidad
    y presencia de categorías sensibles."""

    id = "privacy_forms"
    category = "Datos Personales"
    module = "data_privacy"

    async def run(self, ctx) -> list[CheckResult]:
        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            outcome = await ctx.get_outcome(path)
            if not outcome.ok:
                continue
            resp = outcome.response
            body = resp.text
            base = str(resp.url)
            has_policy_link = bool(find_privacy_policy_links(body, base))

            for index, form in enumerate(parse_forms(body, base)):
                if not form.collects_pii:
                    continue
                out.extend(self._evaluate_form(form, path, index, has_policy_link))
        return out

    def _evaluate_form(
        self, form: Form, path: str, index: int, has_policy_link: bool
    ) -> list[CheckResult]:
        out: list[CheckResult] = []
        categories = ", ".join(sorted(form.pii_categories))
        where = f"{path}#form{index}"

        if form.is_insecure:
            out.append(self._result(
                sub_id=f"pii_form_insecure_transport@{where}",
                severity="critical", likelihood="high", status="fail",
                title=f"Formulario con datos personales enviado sin cifrar en {path}",
                finding=(
                    f"El formulario envía a {form.absolute_action} por HTTP y captura: {categories}."
                ),
                business_impact=(
                    "Los datos personales viajan en texto claro y pueden ser interceptados. "
                    "Es un incumplimiento directo del deber de seguridad de la Ley 21.719 y "
                    "expone a la empresa a sanción de la Agencia de Protección de Datos."
                ),
                recommendation="Servir el formulario y su destino exclusivamente sobre HTTPS.",
                evidence=form.snippet, references=("Ley 21.719 art. 14 quinquies", "CWE-319"),
            ))

        if not has_policy_link:
            out.append(self._result(
                sub_id=f"pii_form_without_privacy_notice@{where}",
                severity="medium", likelihood="high", status="fail",
                title=f"Captura de datos personales sin aviso de privacidad enlazado en {path}",
                finding=(
                    f"La página captura {categories} pero no publica un enlace a la política "
                    f"de privacidad o tratamiento de datos."
                ),
                business_impact=(
                    "La ley exige informar al titular sobre finalidad, plazo y destinatarios "
                    "antes de recoger sus datos. Sin aviso no hay consentimiento informado válido."
                ),
                recommendation=(
                    "Publicar la política de privacidad y enlazarla de forma visible junto al formulario."
                ),
                evidence=form.snippet, references=("Ley 21.719 — deber de información",),
            ))

        sensitive = form.sensitive_categories
        if sensitive:
            out.append(self._result(
                sub_id=f"sensitive_data_collected@{where}",
                severity="high", likelihood="medium", status="warning",
                title=f"Formulario solicita datos sensibles en {path}",
                finding=(
                    f"Se detectaron campos de categorías especialmente protegidas: "
                    f"{', '.join(sorted(sensitive))}. {_LEGAL_NOTE}"
                ),
                business_impact=(
                    "Los datos sensibles exigen consentimiento explícito y medidas de seguridad "
                    "reforzadas; su tratamiento indebido concentra las multas más altas de la ley."
                ),
                recommendation=(
                    "Verificar la base de licitud, obtener consentimiento explícito y separado, "
                    "y minimizar los campos a lo estrictamente necesario."
                ),
                evidence=form.snippet, references=("Ley 21.719 art. 2 lit. g)",),
            ))
        return out


class ConsentTrackingCheck(BaseCheck):
    """Rastreadores de terceros y consentimiento previo."""

    id = "consent_tracking"
    category = "Datos Personales"
    module = "data_privacy"

    async def run(self, ctx) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/")
        if not outcome.ok:
            return [self._error_result(
                sub_id="consent_tracking_unreachable",
                reason="No se pudo obtener la página principal para evaluar el consentimiento.",
                evidence=str(outcome.error.value if outcome.error else ""),
            )]

        resp = outcome.response
        body = resp.text
        trackers = detect_trackers(body)
        banner = detect_consent_banner(body)
        cookies = third_party_cookies(tuple(resp.headers.get_list("set-cookie")), ctx.host)

        out: list[CheckResult] = []
        if trackers and banner is None:
            names = ", ".join(sorted({t.name for t in trackers}))
            out.append(self._result(
                sub_id="trackers_without_consent",
                severity="high", likelihood="high", status="fail",
                title="Rastreadores activos sin mecanismo de consentimiento",
                finding=(
                    f"La página carga {len(trackers)} servicio(s) de terceros ({names}) y no se "
                    f"detectó banner ni plataforma de gestión de consentimiento."
                ),
                business_impact=(
                    "Se tratan datos de los visitantes sin base de licitud desde el primer "
                    "instante de la visita: es la infracción más fácil de constatar por la "
                    "Agencia y la más visible para cualquier denunciante."
                ),
                recommendation=(
                    "Implementar una CMP que bloquee los rastreadores hasta obtener consentimiento "
                    "y registre la prueba de ese consentimiento."
                ),
                evidence="; ".join(f"{t.name}: {t.evidence}" for t in trackers)[:500],
                references=("Ley 21.719 — licitud del tratamiento",),
            ))
        elif trackers and banner:
            out.append(self._result(
                sub_id="consent_banner_present",
                severity="info", likelihood="low", status="info",
                title="Mecanismo de consentimiento detectado",
                finding=f"Se detectó una señal de consentimiento ('{banner}') junto a {len(trackers)} rastreador(es).",
                business_impact="Señal positiva; queda por validar que el bloqueo sea efectivo antes del consentimiento.",
                recommendation=(
                    "Verificar manualmente que ningún rastreador se ejecute antes de que el usuario acepte."
                ),
                evidence=f"firma: {banner}", references=("Ley 21.719",),
            ))

        abroad = sorted({t.controller for t in trackers if t.abroad})
        if abroad:
            out.append(self._result(
                sub_id="international_data_transfer",
                severity="medium", likelihood="high", status="warning",
                title="Transferencia de datos a responsables fuera de Chile",
                finding=f"Los datos de navegación se comparten con: {', '.join(abroad)}. {_LEGAL_NOTE}",
                business_impact=(
                    "Las transferencias internacionales requieren una garantía adecuada declarada. "
                    "Sin ella, cada visita al sitio genera una transferencia no amparada."
                ),
                recommendation=(
                    "Declarar las transferencias en la política de privacidad y adoptar cláusulas "
                    "contractuales u otro mecanismo de garantía adecuada."
                ),
                evidence=", ".join(abroad)[:500],
                references=("Ley 21.719 — transferencias internacionales",),
            ))

        replay = sorted({t.name for t in trackers if t.kind == "session_replay"})
        if replay:
            out.append(self._result(
                sub_id="session_replay_active",
                severity="high", likelihood="medium", status="fail",
                title="Grabación de sesión del usuario activa",
                finding=f"Se detectaron herramientas de session replay: {', '.join(replay)}.",
                business_impact=(
                    "Estas herramientas pueden capturar lo que el usuario escribe en formularios, "
                    "incluidos datos sensibles, y enviarlo a un tercero en el extranjero."
                ),
                recommendation=(
                    "Enmascarar todos los campos de entrada en la configuración de la herramienta y "
                    "condicionar su carga al consentimiento del usuario."
                ),
                evidence=", ".join(replay), references=("Ley 21.719 — minimización",),
            ))

        if cookies:
            out.append(self._result(
                sub_id="third_party_cookies_on_landing",
                severity="medium", likelihood="medium", status="warning",
                title="Cookies de terceros instaladas en la primera visita",
                finding=f"Se observaron cookies de otro dominio: {', '.join(cookies)}.",
                business_impact="Se instala seguimiento antes de cualquier interacción del titular.",
                recommendation="Condicionar la instalación de cookies no esenciales al consentimiento previo.",
                evidence=", ".join(cookies)[:300], references=("Ley 21.719",),
            ))

        return out


class PrivacyPolicyCheck(BaseCheck):
    """Existencia y accesibilidad de la política de privacidad."""

    id = "privacy_policy"
    category = "Datos Personales"
    module = "data_privacy"

    async def run(self, ctx) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/")
        if not outcome.ok:
            return [self._error_result(
                sub_id="privacy_policy_unreachable_target",
                reason="No se pudo obtener la página principal para buscar la política de privacidad.",
                evidence=str(outcome.error.value if outcome.error else ""),
            )]

        resp = outcome.response
        links = find_privacy_policy_links(resp.text, str(resp.url))
        if not links:
            return [self._result(
                sub_id="privacy_policy_missing",
                severity="high", likelihood="high", status="fail",
                title="Sin política de privacidad enlazada en el sitio",
                finding="No se encontró ningún enlace a política de privacidad o tratamiento de datos.",
                business_impact=(
                    "Informar al titular es una obligación básica de la Ley 21.719. Su ausencia es "
                    "verificable por cualquiera desde el navegador y es la primera brecha que "
                    "detectaría un fiscalizador."
                ),
                recommendation=(
                    "Publicar la política de privacidad y enlazarla desde el pie de página de todo el sitio."
                ),
                evidence="", references=("Ley 21.719 — deber de información",),
            )]

        target = links[0]
        policy = await ctx.get_outcome(target)
        if not policy.ok or policy.response.status_code >= 400:
            status = policy.response.status_code if policy.ok else "sin respuesta"
            return [self._result(
                sub_id="privacy_policy_unreachable",
                severity="medium", likelihood="high", status="fail",
                title="La política de privacidad enlazada no es accesible",
                finding=f"El enlace {target} devolvió: {status}.",
                business_impact="El aviso existe formalmente pero el titular no puede leerlo: equivale a no informarlo.",
                recommendation="Reparar el enlace y verificar que la política sea pública y accesible.",
                evidence=target, references=("Ley 21.719 — deber de información",),
            )]

        return [self._result(
            sub_id="privacy_policy_present",
            severity="info", likelihood="low", status="pass",
            title="Política de privacidad publicada y accesible",
            finding=f"Se encontró y verificó el enlace: {target}",
            business_impact="Señal positiva de cumplimiento del deber de información.",
            recommendation=(
                "Revisar que el contenido declare finalidad, plazo de conservación, destinatarios "
                "y la forma de ejercer los derechos ARCO+ (revisión legal, fuera del alcance técnico)."
            ),
            evidence=target, references=("Ley 21.719",),
        )]
