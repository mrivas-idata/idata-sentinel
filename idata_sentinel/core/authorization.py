"""Gate legal de autorización (plan maestro §1.1) — obligatorio antes de cualquier
check activo. El modo passive nunca pasa por acá."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class AuthorizationRequest:
    """Datos exigidos por el plan maestro §1.1 antes de habilitar modo audit."""

    target: str
    allowed_domains: tuple[str, ...]
    authorized_by: str
    contract_reference: str
    confirmed: bool = False  # equivalente a --i-have-authorization / checkbox en UI
    audit_paths: tuple[str, ...] = ()
    audit_endpoints: tuple[str, ...] = ()
    hardening_baseline: dict = field(default_factory=dict)
    #: Activos internos que el cliente aporta para el inventario ampliado
    #: (plan maestro §4, modo auditoría). Se filtran contra `allowed_domains`.
    additional_assets: tuple[str, ...] = ()

    def is_complete(self) -> bool:
        return bool(
            self.confirmed
            and self.authorized_by.strip()
            and self.contract_reference.strip()
            and self.allowed_domains
        )


def _domain_in_scope(host: str, allowed_domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for allowed in allowed_domains:
        allowed = allowed.lower().rstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


@dataclass
class AuditLogger:
    """Log append-only de decisiones de autorización (evidencia de debida diligencia)."""

    path: Path = field(default_factory=lambda: Path("audit_log.json"))

    def record(
        self,
        *,
        target: str,
        decision: str,
        request: AuthorizationRequest | None,
        source_ip: str,
        active_context: dict | None = None,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            # "granted" | "denied_incomplete" | "denied_out_of_scope"
            # | "denied_active_unacknowledged"
            "decision": decision,
            "authorized_by": request.authorized_by if request else None,
            "contract_reference": request.contract_reference if request else None,
            "source_ip": source_ip,
        }
        # La auditoría activa amplía la evidencia, nunca la reduce (plan activo §8).
        # El material de sesión JAMÁS entra al log: solo el booleano.
        if active_context:
            entry["active_checks_enabled"] = active_context.get("active_checks_enabled", [])
            entry["active_acknowledged"] = active_context.get("active_acknowledged", False)
            entry["authenticated_scan"] = active_context.get("authenticated_scan", False)
            if "baseline_version" in active_context:
                entry["baseline_version"] = active_context["baseline_version"]
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class AuthorizationGate:
    """Decide si un target puede correr en modo `audit`."""

    def __init__(self, audit_logger: AuditLogger | None = None) -> None:
        self.audit_logger = audit_logger or AuditLogger()

    def authorize(
        self,
        request: AuthorizationRequest,
        *,
        source_ip: str = "unknown",
        active_context: dict | None = None,
    ) -> bool:
        host = urlparse(request.target).hostname or request.target

        if not request.is_complete():
            self.audit_logger.record(
                target=request.target, decision="denied_incomplete", request=request,
                source_ip=source_ip, active_context=active_context,
            )
            return False

        if not _domain_in_scope(host, request.allowed_domains):
            self.audit_logger.record(
                target=request.target, decision="denied_out_of_scope", request=request,
                source_ip=source_ip, active_context=active_context,
            )
            return False

        self.audit_logger.record(
            target=request.target, decision="granted", request=request,
            source_ip=source_ip, active_context=active_context,
        )
        return True
