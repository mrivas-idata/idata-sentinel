"""Cabeceras de seguridad modernas — complemento de `http_headers.py`.

`http_headers.py` cubre el juego clásico (HSTS, CSP, XFO, XCTO…). Este check
añade lo que define hoy una configuración sólida y que un escaneo de 2020 no
miraba:

- **Aislamiento de origen** (COOP/COEP/CORP): la defensa contra XS-Leaks y
  tabnabbing que reemplazó a las mitigaciones ad-hoc.
- **CORS**: la combinación comodín + credenciales, y el origen `null`.
- **Calidad real de la CSP**: una política puede existir y ser trivialmente
  evadible. Sin `base-uri`, una inyección de `<base>` desvía los scripts
  relativos y anula los nonces; sin `object-src 'none'` queda la vía de los
  plugins. Son los dos huecos que más veces convierten una CSP en decorativa.
- **CSP solo en Report-Only**: se reporta, no se bloquea nada.
- **X-XSS-Protection**: hoy es contraproducente; el valor correcto es `0`.

Todo se lee de la respuesta ya obtenida: no se envía ni un solo payload.
"""
from __future__ import annotations

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.scan_context import ScanContext

HSTS_PRELOAD_MIN_AGE = 31536000


def parse_csp(value: str) -> dict[str, list[str]]:
    """'default-src self; script-src nonce-x' -> {'default-src': ["'self'"], …}."""
    policy: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.strip().split()
        if parts:
            policy[parts[0].lower()] = parts[1:]
    return policy


def has_strict_source(sources: list[str]) -> bool:
    """Un nonce, un hash o 'strict-dynamic' es lo que hace efectiva a una CSP."""
    return any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
        for s in sources
    )


class ModernHeadersCheck(BaseCheck):
    id = "modern_headers"
    category = "HTTP Headers"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            outcome = await ctx.get_outcome(path)
            if not outcome.ok:
                continue
            out.extend(self._evaluate(outcome.response, path))
        return out

    def _suffixed(self, base: str, path: str) -> str:
        return base if path == "/" else f"{base}@{path}"

    def _evaluate(self, resp, path: str) -> list[CheckResult]:
        headers = resp.headers
        out: list[CheckResult] = []
        out.extend(self._isolation(headers, path))
        out.extend(self._cors(headers, path))
        out.extend(self._csp_quality(headers, path))
        out.extend(self._legacy(headers, path))
        return out

    # -- aislamiento de origen ---------------------------------------------

    def _isolation(self, headers, path: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        coop = headers.get("cross-origin-opener-policy", "").lower()

        if not coop:
            out.append(self._result(
                sub_id=self._suffixed("coop_missing", path),
                severity="medium", likelihood="medium", status="fail",
                title="Falta Cross-Origin-Opener-Policy",
                finding=f"El servidor no envía COOP en {path}.",
                business_impact=(
                    "Una página abierta desde el sitio conserva una referencia al documento "
                    "original: permite ataques de tabnabbing y fugas entre orígenes (XS-Leaks) "
                    "que pueden derivar en secuestro de sesión."
                ),
                recommendation="Configurar Cross-Origin-Opener-Policy: same-origin.",
                evidence="", references=("OWASP XS-Leaks", "CWE-1022"),
            ))
        elif coop.startswith("unsafe-none"):
            out.append(self._result(
                sub_id=self._suffixed("coop_unsafe_none", path),
                severity="low", likelihood="medium", status="warning",
                title="COOP declarado en unsafe-none",
                finding=f"Cross-Origin-Opener-Policy: {coop}",
                business_impact="Equivale a no tener aislamiento: la protección está desactivada explícitamente.",
                recommendation="Cambiar a 'same-origin' o 'same-origin-allow-popups'.",
                evidence=coop, references=("OWASP XS-Leaks",),
            ))

        if not headers.get("cross-origin-resource-policy"):
            out.append(self._result(
                sub_id=self._suffixed("corp_missing", path),
                severity="low", likelihood="low", status="warning",
                title="Falta Cross-Origin-Resource-Policy",
                finding=f"El servidor no envía CORP en {path}.",
                business_impact=(
                    "Otros sitios pueden incrustar los recursos del dominio, habilitando "
                    "ataques de canal lateral que infieren su contenido."
                ),
                recommendation="Configurar Cross-Origin-Resource-Policy: same-origin (o same-site).",
                evidence="", references=("OWASP XS-Leaks",),
            ))
        return out

    # -- CORS ---------------------------------------------------------------

    def _cors(self, headers, path: str) -> list[CheckResult]:
        origin = headers.get("access-control-allow-origin", "").strip()
        credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        if not origin:
            return []

        if origin == "*" and credentials:
            return [self._result(
                sub_id=self._suffixed("cors_wildcard_with_credentials", path),
                severity="high", likelihood="high", status="fail",
                title="CORS permite cualquier origen con credenciales",
                finding=(
                    "Access-Control-Allow-Origin: * junto a Access-Control-Allow-Credentials: true. "
                    "Es una configuración inválida que delata la intención de aceptar cualquier origen "
                    "con la sesión del usuario."
                ),
                business_impact=(
                    "Si la validación de origen se relaja en el servidor, cualquier sitio podría leer "
                    "datos autenticados de los usuarios: fuga masiva de información de clientes."
                ),
                recommendation="Declarar una allowlist explícita de orígenes y nunca combinarla con '*'.",
                evidence=f"ACAO: {origin}; ACAC: true", references=("CWE-942", "OWASP CORS"),
            )]

        if origin.lower() == "null":
            return [self._result(
                sub_id=self._suffixed("cors_null_origin", path),
                severity="medium", likelihood="medium", status="fail",
                title="CORS acepta el origen 'null'",
                finding="Access-Control-Allow-Origin: null",
                business_impact=(
                    "El origen 'null' lo produce cualquier documento en un iframe con sandbox, "
                    "así que un atacante puede obtenerlo con facilidad y saltarse la restricción."
                ),
                recommendation="Eliminar 'null' de los orígenes aceptados.",
                evidence=f"ACAO: {origin}", references=("CWE-942",),
            )]

        if origin == "*":
            return [self._result(
                sub_id=self._suffixed("cors_wildcard", path),
                severity="low", likelihood="low", status="warning",
                title="CORS abierto a cualquier origen",
                finding="Access-Control-Allow-Origin: *",
                business_impact=(
                    "Aceptable para recursos públicos; si el endpoint devolviera datos privados "
                    "sería una fuga directa."
                ),
                recommendation="Restringir a los orígenes que realmente lo necesitan.",
                evidence=f"ACAO: {origin}", references=("OWASP CORS",),
            )]
        return []

    # -- calidad de la CSP --------------------------------------------------

    def _csp_quality(self, headers, path: str) -> list[CheckResult]:
        csp = headers.get("content-security-policy", "")
        report_only = headers.get("content-security-policy-report-only", "")

        if not csp and report_only:
            return [self._result(
                sub_id=self._suffixed("csp_report_only_not_enforced", path),
                severity="medium", likelihood="medium", status="fail",
                title="La CSP existe pero solo en modo reporte",
                finding=(
                    "Solo se envía Content-Security-Policy-Report-Only: las violaciones se registran, "
                    "pero nada se bloquea."
                ),
                business_impact=(
                    "Da la apariencia de tener CSP sin ninguna protección real frente a XSS. "
                    "Es un falso sentido de seguridad en auditorías."
                ),
                recommendation="Promover la política a Content-Security-Policy una vez validada.",
                evidence=report_only[:300], references=("OWASP CSP",),
            )]
        if not csp:
            return []  # la ausencia total ya la reporta http_headers.py

        policy = parse_csp(csp)
        out: list[CheckResult] = []
        script_src = policy.get("script-src", policy.get("default-src", []))

        if "base-uri" not in policy:
            out.append(self._result(
                sub_id=self._suffixed("csp_missing_base_uri", path),
                severity="medium", likelihood="medium", status="fail",
                title="La CSP no restringe base-uri",
                finding="La política no declara la directiva 'base-uri'.",
                business_impact=(
                    "Con una inyección de HTML el atacante puede insertar una etiqueta <base> y "
                    "desviar todos los scripts de ruta relativa a su propio servidor, anulando la "
                    "protección de los nonces. Es la evasión de CSP más habitual."
                ),
                recommendation="Añadir \"base-uri 'none'\" (o 'self') a la política.",
                evidence=csp[:300], references=("OWASP CSP", "CWE-79"),
            ))

        if "object-src" not in policy and "default-src" not in policy:
            out.append(self._result(
                sub_id=self._suffixed("csp_missing_object_src", path),
                severity="low", likelihood="medium", status="warning",
                title="La CSP no restringe object-src",
                finding="No se declara 'object-src' ni un 'default-src' que lo cubra.",
                business_impact="Deja abierta la ejecución vía plugins/objetos embebidos.",
                recommendation="Añadir \"object-src 'none'\".",
                evidence=csp[:300], references=("OWASP CSP",),
            ))

        if script_src and not has_strict_source(script_src):
            wildcard = any(s in ("*", "https:", "data:") for s in script_src)
            if wildcard or "'unsafe-inline'" in script_src:
                out.append(self._result(
                    sub_id=self._suffixed("csp_script_src_permissive", path),
                    severity="medium", likelihood="medium", status="fail",
                    title="La CSP permite scripts sin restricción efectiva",
                    finding=f"script-src sin nonce ni hash y con orígenes amplios: {' '.join(script_src)[:200]}",
                    business_impact=(
                        "Una política basada en listas de dominios se evade con archivos JSONP o "
                        "librerías alojadas en esos mismos dominios: no detiene un XSS real."
                    ),
                    recommendation="Migrar a una CSP estricta con nonce por respuesta y 'strict-dynamic'.",
                    evidence=csp[:300], references=("OWASP CSP",),
                ))
        elif script_src and has_strict_source(script_src):
            out.append(self._result(
                sub_id=self._suffixed("csp_strict_configured", path),
                severity="info", likelihood="low", status="pass",
                title="CSP estricta configurada",
                finding="script-src usa nonce, hash o 'strict-dynamic'.",
                business_impact="Mitigación efectiva de XSS a nivel de navegador.",
                recommendation="Mantener el nonce único por respuesta y revisar la política ante cada cambio.",
                evidence=csp[:300], references=("OWASP CSP",),
            ))
        return out

    # -- legado -------------------------------------------------------------

    def _legacy(self, headers, path: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        xss = headers.get("x-xss-protection", "").strip()
        if xss and not xss.startswith("0"):
            out.append(self._result(
                sub_id=self._suffixed("xss_protection_legacy", path),
                severity="low", likelihood="low", status="warning",
                title="X-XSS-Protection activado con un valor obsoleto",
                finding=f"X-XSS-Protection: {xss}",
                business_impact=(
                    "El filtro XSS de los navegadores antiguos llegó a introducir vulnerabilidades "
                    "propias; los navegadores actuales lo ignoran. Mantenerlo activo no protege y "
                    "puede confundir una auditoría."
                ),
                recommendation="Establecer 'X-XSS-Protection: 0' y confiar la mitigación a la CSP.",
                evidence=xss, references=("OWASP Secure Headers",),
            ))

        hsts = headers.get("strict-transport-security", "")
        if hsts and "preload" not in hsts.lower():
            out.append(self._result(
                sub_id=self._suffixed("hsts_not_preloaded", path),
                severity="info", likelihood="low", status="info",
                title="HSTS sin directiva preload",
                finding=f"Strict-Transport-Security: {hsts}",
                business_impact=(
                    "La primera visita de un usuario nuevo todavía puede ocurrir por HTTP y ser "
                    "interceptada antes de que HSTS se active."
                ),
                recommendation=(
                    "Añadir 'preload' con max-age >= 31536000 e includeSubDomains, y enviar el "
                    "dominio a la lista de precarga de los navegadores."
                ),
                evidence=hsts, references=("OWASP HSTS",),
            ))
        return out
