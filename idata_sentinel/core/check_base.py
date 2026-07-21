"""Contrato estándar de un check (plan maestro §2) y clase base reutilizable."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from idata_sentinel.modules.vuln_identification.context import ScanContext

Severity = Literal["info", "low", "medium", "high", "critical"]
Likelihood = Literal["low", "medium", "high"]
Status = Literal["pass", "fail", "warning", "info"]
Mode = Literal["passive", "audit"]

_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
_VALID_LIKELIHOOD = {"low", "medium", "high"}
_VALID_STATUS = {"pass", "fail", "warning", "info"}


@dataclass(frozen=True)
class CheckResult:
    id: str
    module: str
    category: str
    severity: Severity
    likelihood: Likelihood
    status: Status
    title: str
    finding: str
    business_impact: str
    recommendation: str
    evidence: str
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in _VALID_SEVERITY:
            raise ValueError(f"severity inválida: {self.severity!r}")
        if self.likelihood not in _VALID_LIKELIHOOD:
            raise ValueError(f"likelihood inválida: {self.likelihood!r}")
        if self.status not in _VALID_STATUS:
            raise ValueError(f"status inválido: {self.status!r}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "module": self.module,
            "category": self.category,
            "severity": self.severity,
            "likelihood": self.likelihood,
            "status": self.status,
            "title": self.title,
            "finding": self.finding,
            "business_impact": self.business_impact,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "references": list(self.references),
        }


class BaseCheck(ABC):
    id: str
    category: str
    module: str = "vuln_identification"
    modes: frozenset[Mode] = frozenset({"passive", "audit"})

    @abstractmethod
    async def run(self, ctx: "ScanContext") -> list[CheckResult]: ...

    def _result(
        self,
        *,
        sub_id: str,
        severity: Severity,
        likelihood: Likelihood,
        status: Status,
        title: str,
        finding: str,
        business_impact: str,
        recommendation: str,
        evidence: str,
        references: tuple[str, ...] = (),
    ) -> CheckResult:
        return CheckResult(
            id=sub_id,
            module=self.module,
            category=self.category,
            severity=severity,
            likelihood=likelihood,
            status=status,
            title=title,
            finding=finding,
            business_impact=business_impact,
            recommendation=recommendation,
            evidence=evidence,
            references=references,
        )

    def _error_result(self, *, sub_id: str, reason: str, evidence: str = "") -> CheckResult:
        return self._result(
            sub_id=sub_id,
            severity="info",
            likelihood="low",
            status="info",
            title="No evaluable",
            finding=reason,
            business_impact="No se pudo evaluar este check; no representa un hallazgo de seguridad.",
            recommendation="Reintentar el escaneo; si persiste, verificar conectividad al objetivo.",
            evidence=evidence,
        )
