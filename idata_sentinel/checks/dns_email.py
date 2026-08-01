"""Seguridad de DNS y de correo electrónico — plan maestro §4 (Módulo 2).

Cubre las señales que hoy definen una postura de email/DNS sana:
SPF (RFC 7208) con su límite de 10 lookups, DMARC (RFC 7489) y la fuerza real de
su política, MTA-STS (RFC 8461), TLS-RPT (RFC 8460), CAA (RFC 8659) y DNSSEC.
Todo es lectura de registros públicos: no se envía correo ni se prueba nada.
"""
from __future__ import annotations

import re

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.dns_resolver import DnsRecords, DnsResolver

#: Mecanismos SPF que gastan una de las 10 consultas DNS permitidas (RFC 7208 §4.6.4).
_SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")
_SPF_LOOKUP_LIMIT = 10

_ALL_QUALIFIER = re.compile(r"([-~?+])all\b", re.IGNORECASE)
_DMARC_POLICY = re.compile(r"\bp\s*=\s*(none|quarantine|reject)\b", re.IGNORECASE)

#: Dominios de los buzones de reportes DMARC **por defecto** de proveedores de
#: hosting/registro. Cuando el `rua` apunta aquí, los informes agregados los
#: recibe el proveedor y no el titular del dominio: la política puede estar
#: activa, pero el dueño no ve quién lo suplanta.
#:
#: Ojo: un `rua` a un dominio externo es legítimo cuando se usa una plataforma de
#: análisis DMARC (dmarcian, EasyDMARC, etc.) contratada por el titular. Por eso
#: sólo se marcan los buzones *por defecto* del proveedor —el caso "lo dejó el
#: asistente del registrador y nadie lo cambió"—, no cualquier destino externo.
_DMARC_DEFAULT_PROVIDERS = {
    "onsecureserver.net": "GoDaddy",
    "secureserver.net": "GoDaddy",
}


def find_spf(txt_records: tuple[str, ...]) -> str | None:
    for record in txt_records:
        if record.lower().replace('"', "").strip().startswith("v=spf1"):
            return record.replace('"', "").strip()
    return None


def spf_qualifier(spf: str) -> str:
    """'-all' (hard fail) | '~all' (soft) | '?all' (neutral) | '+all' (todo permitido)."""
    match = _ALL_QUALIFIER.search(spf)
    return match.group(1) if match else ""


def count_spf_lookups(spf: str) -> int:
    lowered = spf.lower()
    total = 0
    for mechanism in _SPF_LOOKUP_MECHANISMS:
        total += lowered.count(mechanism)
    # 'a' y 'mx' sin ':' también gastan lookup
    for bare in (" a ", " mx "):
        total += f" {lowered} ".count(bare)
    return total


def find_dmarc(txt_records: tuple[str, ...]) -> str | None:
    for record in txt_records:
        if record.lower().replace('"', "").strip().startswith("v=dmarc1"):
            return record.replace('"', "").strip()
    return None


def dmarc_policy(dmarc: str) -> str:
    match = _DMARC_POLICY.search(dmarc)
    return match.group(1).lower() if match else "none"


def dmarc_addresses(dmarc: str, tag: str = "rua") -> list[str]:
    """Direcciones declaradas en un tag `rua=`/`ruf=` del registro DMARC.

    Formato RFC 7489 §6.3: `rua=mailto:a@x.com,mailto:b@y.com!10m` —
    separadas por coma, con prefijo `mailto:` y un sufijo opcional de tamaño `!…`.
    """
    match = re.search(rf"\b{tag}\s*=\s*([^;]+)", dmarc, re.IGNORECASE)
    if not match:
        return []
    addresses: list[str] = []
    for part in match.group(1).split(","):
        part = part.strip()
        if part.lower().startswith("mailto:"):
            part = part[len("mailto:") :]
        part = part.split("!", 1)[0].strip()  # descarta el límite de tamaño
        if part:
            addresses.append(part)
    return addresses


def dmarc_rua_default_provider(dmarc: str) -> tuple[str, str] | None:
    """Devuelve `(dirección, proveedor)` si algún `rua` apunta al buzón por
    defecto de un proveedor conocido, o `None`."""
    for address in dmarc_addresses(dmarc, "rua"):
        domain = address.rsplit("@", 1)[-1].lower().strip() if "@" in address else ""
        for suffix, provider in _DMARC_DEFAULT_PROVIDERS.items():
            if domain == suffix or domain.endswith("." + suffix):
                return address, provider
    return None


class DnsEmailCheck(BaseCheck):
    """No opera sobre `ScanContext` (no es HTTP): el runner del Módulo 2 lo invoca
    con el host y los registros ya resueltos, para no repetir consultas DNS."""

    id = "dns_email"
    category = "DNS y Correo"
    module = "asset_inventory"

    async def run(self, ctx) -> list[CheckResult]:  # pragma: no cover - no aplica
        raise NotImplementedError("DnsEmailCheck se invoca vía evaluate(), no run().")

    async def evaluate(self, host: str, records: DnsRecords, dns: DnsResolver) -> list[CheckResult]:
        out: list[CheckResult] = []
        txt = records.get("TXT")
        receives_mail = bool(records.get("MX"))

        out.extend(self._spf_results(host, txt, receives_mail, records.measured("TXT")))
        out.extend(await self._dmarc_results(host, dns, receives_mail))
        if receives_mail:
            out.extend(await self._transport_results(host, dns))
        out.extend(self._caa_results(host, records))
        out.extend(await self._dnssec_results(host, dns))
        return out

    def _unmeasured(self, *, sub_id: str, query: str) -> CheckResult:
        """La consulta DNS no concluyó: no se puede afirmar nada sobre el registro.

        Sin esto, un timeout de TXT se emitía como `spf_missing` sobre un dominio
        que sí publica SPF, con la recomendación de publicar uno que ya existe.
        """
        return self._error_result(
            sub_id=sub_id,
            reason=(
                f"La consulta DNS de {query} no concluyó (timeout o fallo del servidor). "
                "No se puede afirmar si el registro existe."
            ),
            evidence=f"consulta sin respuesta: {query}",
        )

    # -- SPF ---------------------------------------------------------------

    def _spf_results(
        self, host: str, txt: tuple[str, ...], receives_mail: bool, measured: bool = True
    ) -> list[CheckResult]:
        if not measured:
            return [self._unmeasured(sub_id=f"spf_unmeasured@{host}", query=f"TXT {host}")]
        spf = find_spf(txt)
        if spf is None:
            severity = "medium" if receives_mail else "low"
            return [self._result(
                sub_id=f"spf_missing@{host}", severity=severity, likelihood="medium", status="fail",
                title=f"Falta registro SPF en {host}",
                finding=f"No se encontró un registro TXT con 'v=spf1' para {host}.",
                business_impact=(
                    "Cualquiera puede enviar correo simulando ser este dominio: riesgo de "
                    "fraude al cliente (phishing con la marca) y de daño reputacional."
                ),
                recommendation="Publicar un TXT 'v=spf1 ... -all' declarando los emisores autorizados.",
                evidence=f"TXT observados: {', '.join(txt[:5]) or '(ninguno)'}",
                references=("RFC 7208",),
            )]

        out: list[CheckResult] = []
        qualifier = spf_qualifier(spf)
        if qualifier in ("+", "?", ""):
            out.append(self._result(
                sub_id=f"spf_weak_policy@{host}", severity="medium", likelihood="medium", status="fail",
                title=f"Política SPF permisiva en {host}",
                finding=f"El SPF termina en '{qualifier or 'sin'}all': no instruye rechazar remitentes no autorizados.",
                business_impact="El SPF existe pero no bloquea la suplantación; da falsa sensación de protección.",
                recommendation="Cerrar la política con '-all' (o '~all' durante la transición).",
                evidence=spf[:200], references=("RFC 7208 §4.6.4",),
            ))
        elif qualifier == "~":
            out.append(self._result(
                sub_id=f"spf_softfail@{host}", severity="low", likelihood="low", status="warning",
                title=f"SPF en softfail en {host}",
                finding="El SPF termina en '~all' (softfail): los receptores marcan pero no rechazan.",
                business_impact="Protección parcial; adecuada solo como etapa transitoria.",
                recommendation="Migrar a '-all' una vez validados todos los emisores legítimos.",
                evidence=spf[:200], references=("RFC 7208",),
            ))

        lookups = count_spf_lookups(spf)
        if lookups > _SPF_LOOKUP_LIMIT:
            out.append(self._result(
                sub_id=f"spf_lookup_limit@{host}", severity="medium", likelihood="medium", status="fail",
                title=f"SPF excede el límite de 10 consultas DNS en {host}",
                finding=f"Se contaron ~{lookups} mecanismos con resolución DNS (límite RFC: {_SPF_LOOKUP_LIMIT}).",
                business_impact=(
                    "Los receptores devuelven 'permerror' y el SPF deja de aplicarse: "
                    "el correo legítimo puede rebotar y la protección anti-spoofing se pierde."
                ),
                recommendation="Reducir 'include:' anidados o aplanar el registro con una herramienta de flattening.",
                evidence=spf[:200], references=("RFC 7208 §4.6.4",),
            ))
        return out

    # -- DMARC -------------------------------------------------------------

    async def _dmarc_results(self, host: str, dns: DnsResolver, receives_mail: bool) -> list[CheckResult]:
        answer = await dns.txt(f"_dmarc.{host}")
        if answer.failed:
            return [self._unmeasured(sub_id=f"dmarc_unmeasured@{host}", query=f"TXT _dmarc.{host}")]
        dmarc = find_dmarc(answer.values)
        if dmarc is None:
            severity = "medium" if receives_mail else "low"
            return [self._result(
                sub_id=f"dmarc_missing@{host}", severity=severity, likelihood="medium", status="fail",
                title=f"Falta registro DMARC en {host}",
                finding=f"No se encontró _dmarc.{host} con 'v=DMARC1'.",
                business_impact=(
                    "Sin DMARC no hay política declarada ante correos falsificados ni visibilidad "
                    "de quién está suplantando el dominio."
                ),
                recommendation=f"Publicar _dmarc.{host} TXT con 'v=DMARC1; p=quarantine; rua=mailto:...'.",
                evidence="", references=("RFC 7489",),
            )]

        out: list[CheckResult] = []
        policy = dmarc_policy(dmarc)
        if policy == "none":
            out.append(self._result(
                sub_id=f"dmarc_policy_none@{host}", severity="medium", likelihood="medium", status="fail",
                title=f"DMARC en modo monitoreo (p=none) en {host}",
                finding="La política DMARC es 'p=none': se reporta, pero no se rechaza ni cuarentena nada.",
                business_impact="Los correos falsificados con la marca siguen llegando a la bandeja del destinatario.",
                recommendation="Endurecer a 'p=quarantine' y luego 'p=reject' tras validar los flujos legítimos.",
                evidence=dmarc[:200], references=("RFC 7489",),
            ))
        provider = dmarc_rua_default_provider(dmarc)
        if provider is not None:
            address, name = provider
            out.append(self._result(
                sub_id=f"dmarc_rua_default_provider@{host}",
                severity="low", likelihood="medium", status="warning",
                title=f"Los reportes DMARC de {host} van al buzón por defecto de {name}",
                finding=(
                    f"El registro DMARC envía los informes agregados a '{address}', la dirección "
                    f"por defecto de {name}. Los reportes los recibe el proveedor, no el titular "
                    f"del dominio."
                ),
                business_impact=(
                    "Con la política DMARC activa pero el 'rua' apuntando al proveedor, el titular "
                    "no recibe los informes: no tiene visibilidad de quién intenta suplantar el "
                    "dominio ni puede medir el avance del despliegue. Se opera a ciegas."
                ),
                recommendation=(
                    "Apuntar 'rua=' a un buzón propio monitoreado o a una plataforma de análisis "
                    "DMARC bajo control del titular, para recuperar la visibilidad."
                ),
                evidence=dmarc[:200], references=("RFC 7489 §7",),
            ))
        elif "rua=" not in dmarc.lower():
            out.append(self._result(
                sub_id=f"dmarc_no_reporting@{host}", severity="low", likelihood="low", status="warning",
                title=f"DMARC sin dirección de reportes agregados en {host}",
                finding="El registro DMARC no declara 'rua='.",
                business_impact="Sin reportes no hay forma de saber quién suplanta el dominio ni de medir el avance.",
                recommendation="Agregar 'rua=mailto:dmarc@<dominio>' para recibir reportes agregados.",
                evidence=dmarc[:200], references=("RFC 7489 §7",),
            ))
        return out

    # -- MTA-STS / TLS-RPT -------------------------------------------------

    async def _transport_results(self, host: str, dns: DnsResolver) -> list[CheckResult]:
        out: list[CheckResult] = []
        mta_sts = await dns.txt(f"_mta-sts.{host}")
        if mta_sts.failed:
            out.append(self._unmeasured(
                sub_id=f"mta_sts_unmeasured@{host}", query=f"TXT _mta-sts.{host}"))
        elif not any("v=stsv1" in r.lower() for r in mta_sts.values):
            out.append(self._result(
                sub_id=f"mta_sts_missing@{host}", severity="low", likelihood="medium", status="warning",
                title=f"Sin política MTA-STS en {host}",
                finding=f"No se encontró _mta-sts.{host} con 'v=STSv1'.",
                business_impact=(
                    "El correo entrante puede ser degradado a texto plano por un atacante en red "
                    "(downgrade de STARTTLS), exponiendo su contenido."
                ),
                recommendation="Publicar _mta-sts TXT y el archivo de política en https://mta-sts.<dominio>/.well-known/mta-sts.txt.",
                evidence="", references=("RFC 8461",),
            ))
        tls_rpt = await dns.txt(f"_smtp._tls.{host}")
        if tls_rpt.failed:
            out.append(self._unmeasured(
                sub_id=f"tls_rpt_unmeasured@{host}", query=f"TXT _smtp._tls.{host}"))
        elif not any("v=tlsrptv1" in r.lower() for r in tls_rpt.values):
            out.append(self._result(
                sub_id=f"tls_rpt_missing@{host}", severity="info", likelihood="low", status="info",
                title=f"Sin TLS-RPT en {host}",
                finding=f"No se encontró _smtp._tls.{host} con 'v=TLSRPTv1'.",
                business_impact="No se reciben reportes de fallos de cifrado en la entrega de correo.",
                recommendation="Publicar _smtp._tls TXT con 'v=TLSRPTv1; rua=mailto:...'.",
                evidence="", references=("RFC 8460",),
            ))
        return out

    # -- CAA / DNSSEC ------------------------------------------------------

    def _caa_results(self, host: str, records: DnsRecords) -> list[CheckResult]:
        if not records.measured("CAA"):
            return [self._unmeasured(sub_id=f"caa_unmeasured@{host}", query=f"CAA {host}")]
        if records.get("CAA"):
            return []
        return [self._result(
            sub_id=f"caa_missing@{host}", severity="low", likelihood="low", status="warning",
            title=f"Sin registro CAA en {host}",
            finding=f"No hay registros CAA para {host}: cualquier CA puede emitir certificados del dominio.",
            business_impact=(
                "Amplía la superficie para un certificado fraudulento emitido por una CA no prevista, "
                "habilitando sitios de phishing con HTTPS válido."
            ),
            recommendation="Publicar CAA restringiendo la emisión a las CAs efectivamente usadas.",
            evidence="", references=("RFC 8659",),
        )]

    async def _dnssec_results(self, host: str, dns: DnsResolver) -> list[CheckResult]:
        answer = await dns.query(host, "DNSKEY")
        if answer.failed:
            return [self._unmeasured(sub_id=f"dnssec_unmeasured@{host}", query=f"DNSKEY {host}")]
        if answer.values:
            return []
        return [self._result(
            sub_id=f"dnssec_missing@{host}", severity="low", likelihood="low", status="warning",
            title=f"DNSSEC no habilitado en {host}",
            finding=f"No se observaron registros DNSKEY para {host}.",
            business_impact=(
                "Las respuestas DNS del dominio no son verificables: un envenenamiento de caché "
                "puede desviar a los usuarios a infraestructura del atacante."
            ),
            recommendation="Habilitar DNSSEC en el proveedor de DNS y publicar el registro DS en el registrar.",
            evidence="", references=("RFC 4033",),
        )]
