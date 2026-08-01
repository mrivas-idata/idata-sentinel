"""TLS/SSL (plan_implementacion_escaneo_vulnerabilidades.md §2.2).

Recolección (socket/ssl, bloqueante, corre en thread) separada de evaluación
(función pura, testeable offline con certificados generados a mano).
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "EXPORT", "NULL", "DES-CBC", "MD5")
_HANDSHAKE_TIMEOUT = 10.0
_EXPIRING_SOON_DAYS = 30


@dataclass
class TlsCollection:
    """Lo observado en un handshake TLS. Todo opcional: puede fallar
    parcialmente (p.ej. cert leído pero cadena no confiable)."""

    protocol: str | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None
    certificate: x509.Certificate | None = None
    chain_trusted: bool | None = None
    hostname_matches: bool | None = None
    supports_legacy_protocol: bool = False
    connect_error: str | None = None


def _collect_tls_sync(host: str, port: int = 443) -> TlsCollection:
    result = TlsCollection()

    verified_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.protocol = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_name, _, result.cipher_bits = cipher
                der = ssock.getpeercert(binary_form=True)
                result.certificate = x509.load_der_x509_certificate(der, default_backend())
                result.chain_trusted = True
                result.hostname_matches = True
    except ssl.SSLCertVerificationError as e:
        result.chain_trusted = False
        result.hostname_matches = True
        try:
            insecure_ctx = ssl._create_unverified_context()  # noqa: SLF001 — solo para leer el cert, no para "aceptar" tráfico
            with socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock:
                with insecure_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result.protocol = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result.cipher_name, _, result.cipher_bits = cipher
                    der = ssock.getpeercert(binary_form=True)
                    result.certificate = x509.load_der_x509_certificate(der, default_backend())
        except (OSError, ssl.SSLError) as e2:
            result.connect_error = str(e2)
            return result
        if "hostname mismatch" in str(e).lower() or isinstance(e, ssl.CertificateError):
            result.hostname_matches = False
    except (OSError, socket.timeout, ssl.SSLError) as e:
        result.connect_error = str(e)
        return result

    for legacy_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy_ctx.check_hostname = False
            legacy_ctx.verify_mode = ssl.CERT_NONE
            legacy_ctx.minimum_version = legacy_version
            legacy_ctx.maximum_version = legacy_version
            with socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock:
                with legacy_ctx.wrap_socket(sock, server_hostname=host):
                    result.supports_legacy_protocol = True
                    break
        except (OSError, ssl.SSLError):
            continue

    return result


async def collect_tls(host: str, port: int = 443) -> TlsCollection:
    return await asyncio.to_thread(_collect_tls_sync, host, port)


def _subject_cn(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        return str(cert.subject)


def _not_after_utc(cert: x509.Certificate) -> datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def evaluate_tls(collection: TlsCollection, host: str) -> list[dict]:
    """Traduce una TlsCollection a hallazgos crudos (kwargs de BaseCheck._result).
    Función pura, sin I/O — testeable con TlsCollection construidas a mano."""
    findings: list[dict] = []

    if collection.certificate is None:
        return findings  # sin handshake exitoso: el caller decide cómo reportarlo (§4)

    if collection.supports_legacy_protocol:
        findings.append(dict(
            sub_id="tls_legacy_protocol", severity="high", likelihood="medium", status="fail",
            title="El servidor acepta TLS 1.0/1.1",
            finding="El servidor negocia protocolos TLS obsoletos (1.0/1.1).",
            business_impact="Protocolos obsoletos con criptografía débil conocida; MITM más viable.",
            recommendation="Deshabilitar TLS 1.0/1.1; exigir TLS 1.2 como mínimo.",
            evidence=f"host={host}", references=("CWE-326",),
        ))

    weak_cipher = collection.cipher_name and any(
        marker in collection.cipher_name.upper() for marker in _WEAK_CIPHER_MARKERS
    )
    weak_bits = collection.cipher_bits is not None and collection.cipher_bits < 128
    if weak_cipher or weak_bits:
        findings.append(dict(
            sub_id="tls_weak_cipher", severity="high", likelihood="medium", status="fail",
            title="Cipher suite débil negociada",
            finding=f"Cipher negociado: {collection.cipher_name} ({collection.cipher_bits} bits).",
            business_impact="Confidencialidad del canal comprometida.",
            recommendation="Configurar cipher suites modernas (AEAD, >=128 bits, sin RC4/3DES/export).",
            evidence=f"{collection.cipher_name} / {collection.cipher_bits} bits", references=("CWE-327",),
        ))

    cert = collection.certificate
    now = datetime.now(timezone.utc)
    not_after = _not_after_utc(cert)
    if not_after < now:
        findings.append(dict(
            sub_id="cert_expired", severity="critical", likelihood="high", status="fail",
            title="Certificado TLS expirado",
            finding=f"El certificado expiró el {not_after.isoformat()}.",
            business_impact="Navegadores bloquean/alertan; pérdida de confianza y disponibilidad efectiva.",
            recommendation="Renovar el certificado de inmediato.",
            evidence=not_after.isoformat(), references=("CWE-298",),
        ))
    else:
        days_left = (not_after - now).days
        if days_left < _EXPIRING_SOON_DAYS:
            findings.append(dict(
                sub_id="cert_expiring_soon", severity="medium", likelihood="high", status="warning",
                title="Certificado TLS por vencer",
                finding=f"El certificado vence en {days_left} día(s) ({not_after.isoformat()}).",
                business_impact="Riesgo operacional inminente de caída del sitio por certificado vencido.",
                recommendation="Renovar el certificado antes del vencimiento; automatizar renovación.",
                evidence=not_after.isoformat(), references=(),
            ))

    if collection.chain_trusted is False:
        findings.append(dict(
            sub_id="cert_chain_untrusted", severity="high", likelihood="high", status="fail",
            title="Cadena de certificado no confiable",
            finding="La verificación de la cadena de confianza falló (self-signed o CA desconocida).",
            business_impact="Plausible MITM; la confianza del canal está rota.",
            recommendation="Usar un certificado emitido por una CA públicamente confiable.",
            evidence=_subject_cn(cert), references=("CWE-295",),
        ))

    if collection.hostname_matches is False:
        findings.append(dict(
            sub_id="cert_hostname_mismatch", severity="high", likelihood="high", status="fail",
            title="El certificado no coincide con el dominio",
            finding=f"El certificado presentado no cubre el hostname {host}.",
            business_impact="El certificado no es válido para este dominio; alerta de navegador.",
            recommendation="Emitir/instalar un certificado con el hostname correcto en CN/SAN.",
            evidence=_subject_cn(cert), references=("CWE-297",),
        ))

    if (
        not findings
        and collection.chain_trusted
        and collection.hostname_matches
        and not collection.supports_legacy_protocol
        and collection.protocol in ("TLSv1.2", "TLSv1.3")
    ):
        findings.append(dict(
            sub_id="tls_ok", severity="info", likelihood="low", status="pass",
            title="Configuración TLS saludable",
            finding=f"Protocolo {collection.protocol}, cadena confiable, certificado vigente.",
            business_impact="N/A.", recommendation="Mantener el hardening actual.",
            evidence=f"{collection.protocol} / {collection.cipher_name}", references=(),
        ))

    return findings


def _tls_version_tuple(protocol: str) -> tuple[int, ...]:
    """'TLSv1.2' -> (1, 2). Un protocolo no reconocido queda como (0,) para no
    fallar en falso una comparación de baseline."""
    match = re.search(r"(\d+)\.(\d+)", protocol or "")
    return (int(match.group(1)), int(match.group(2))) if match else (0,)


class TlsSslCheck(BaseCheck):
    id = "tls_ssl"
    category = "TLS/SSL"
    modes = frozenset({"passive", "audit"})
    #: El handshake, el certificado y la redirección a HTTPS son propiedades de
    #: la infraestructura: se miden igual aunque delante haya un intersticial.
    content_dependent = False

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []

        collection = await collect_tls(ctx.host)
        if collection.certificate is None:
            out.append(self._error_result(
                sub_id="tls_unreachable",
                reason=f"No se pudo completar el handshake TLS con {ctx.host}: {collection.connect_error}",
            ))
        else:
            for raw in evaluate_tls(collection, ctx.host):
                out.append(self._result(**raw))

        out.extend(await self._check_https_redirect(ctx))
        out.extend(self._tls_baseline_mismatch(collection, ctx))
        return out

    def _tls_baseline_mismatch(self, collection, ctx: ScanContext) -> list[CheckResult]:
        """Compara la versión TLS negociada contra el mínimo acordado (plan activo §5)."""
        from idata_sentinel.core.baseline import for_context

        baseline = for_context(ctx)
        if baseline is None or collection.protocol is None:
            return []
        requirement = baseline.tls_min_version("/")
        if requirement is None:
            return []
        min_version, severity = requirement
        if _tls_version_tuple(collection.protocol) >= _tls_version_tuple(min_version):
            return []
        return [self._result(
            sub_id=f"tls_baseline_mismatch@{ctx.host}",
            severity=severity, likelihood="medium", status="fail", confidence="confirmed",
            title="Versión TLS por debajo del baseline acordado",
            finding=(
                f"El baseline v{baseline.version} exige al menos {min_version}; el servidor "
                f"negoció {collection.protocol}."
            ),
            business_impact="La configuración TLS no cumple el estándar de hardening comprometido con el cliente.",
            recommendation=f"Deshabilitar versiones anteriores a {min_version} en el servidor.",
            evidence=f"negociado={collection.protocol}, mínimo acordado={min_version}",
            references=("baseline",),
        )]

    async def _check_https_redirect(self, ctx: ScanContext) -> list[CheckResult]:
        outcome = await ctx.get_http_outcome("/")
        if not outcome.ok:
            return []  # servidor no responde en 80 en absoluto: no es el hallazgo que este check cubre
        resp = outcome.response
        location = resp.headers.get("location", "")
        redirects_to_https = 300 <= resp.status_code < 400 and location.lower().startswith("https://")
        if redirects_to_https:
            return []
        return [self._result(
            sub_id="no_https_redirect", severity="medium", likelihood="high", status="fail",
            title="No hay redirección forzada a HTTPS",
            finding=f"http://{ctx.host}/ respondió {resp.status_code} sin redirigir a HTTPS.",
            business_impact="Tráfico en claro por defecto si el usuario no fuerza HTTPS manualmente.",
            recommendation="Redirigir (301/308) todo el tráfico HTTP a HTTPS.",
            evidence=f"status={resp.status_code} location={location}", references=("CWE-319",),
        )]
