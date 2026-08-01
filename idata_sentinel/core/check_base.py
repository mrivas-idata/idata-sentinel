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

#: Cuánto respalda la evidencia al hallazgo. Separa "lo medí" de "lo deduje" de
#: "no pude medirlo", que hasta ahora se confundían en un mismo `status`.
#:
#: - ``confirmed``  un humano lo verificó, o dos señales independientes coinciden
#: - ``high``       observación directa (la cabecera no está en una respuesta 200)
#: - ``medium``     deducción de una sola señal (una versión expuesta implica un CVE)
#: - ``low``        heurística (una expresión regular sobre el HTML)
#: - ``unverified`` no se pudo medir; el hallazgo no afirma nada sobre el objetivo
Confidence = Literal["confirmed", "high", "medium", "low", "unverified"]

#: Resultado del triage humano. Al momento del escaneo nada está verificado:
#: es el auditor quien mueve este campo, y un informe firmado no debería llevar
#: hallazgos accionables que sigan en ``unverified``.
VerificationStatus = Literal[
    "unverified", "verified_true_positive", "verified_false_positive", "needs_review"
]

#: Claves exactas que produce ``CheckResult.to_dict()``. Vive aquí, junto a la
#: dataclass, porque hasta ahora el conjunto estaba copiado en ocho tests y
#: cualquier cambio del contrato obligaba a editarlos uno por uno.
FINDING_CONTRACT_KEYS = frozenset(
    {
        "id",
        "module",
        "category",
        "severity",
        "likelihood",
        "status",
        "confidence",
        "verification_status",
        "title",
        "finding",
        "business_impact",
        "recommendation",
        "evidence",
        "references",
    }
)

_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
_VALID_LIKELIHOOD = {"low", "medium", "high"}
_VALID_STATUS = {"pass", "fail", "warning", "info"}
_VALID_CONFIDENCE = {"confirmed", "high", "medium", "low", "unverified"}
_VALID_VERIFICATION = {
    "unverified",
    "verified_true_positive",
    "verified_false_positive",
    "needs_review",
}


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
    confidence: Confidence = "high"
    verification_status: VerificationStatus = "unverified"

    def __post_init__(self) -> None:
        if self.severity not in _VALID_SEVERITY:
            raise ValueError(f"severity inválida: {self.severity!r}")
        if self.likelihood not in _VALID_LIKELIHOOD:
            raise ValueError(f"likelihood inválida: {self.likelihood!r}")
        if self.status not in _VALID_STATUS:
            raise ValueError(f"status inválido: {self.status!r}")
        if self.confidence not in _VALID_CONFIDENCE:
            raise ValueError(f"confidence inválida: {self.confidence!r}")
        if self.verification_status not in _VALID_VERIFICATION:
            raise ValueError(f"verification_status inválido: {self.verification_status!r}")

    @property
    def is_measured(self) -> bool:
        """Si el check llegó a observar el objetivo.

        Un hallazgo ``unverified`` no afirma nada: no debe penalizar el score ni
        contar como cobertura. Es la distinción que faltaba cuando un timeout de
        DNS se reportó como "no existe registro SPF".
        """
        return self.confidence != "unverified"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "module": self.module,
            "category": self.category,
            "severity": self.severity,
            "likelihood": self.likelihood,
            "status": self.status,
            "confidence": self.confidence,
            "verification_status": self.verification_status,
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

    #: Si el check deduce del contenido o de las cabeceras que emite la
    #: aplicación. Cuando el servidor entrega una página intersticial anti-bot,
    #: lo observado no es el sitio y estos checks deben declararse no evaluables
    #: en vez de afirmar sobre la página equivocada (`core/interstitial.py`).
    #: Los checks que miden la infraestructura —TLS, DNS— no se ven afectados y
    #: lo marcan en `False`.
    content_dependent: bool = True

    #: Si el check ejecuta una **técnica activa** (auditoría no destructiva) que
    #: exige habilitación explícita por nombre además del gate legal
    #: (plan_implementacion_escaneo_activo.md §4). Los checks pasivos y los que
    #: solo expanden superficie declarada dejan esto en `False`; solo los checks
    #: de configuración activos (métodos HTTP, CORS, auth-enforcement, etc.) lo
    #: marcan en `True`. Aditivo: no cambia el comportamiento de ningún check
    #: existente.
    active: bool = False

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
        confidence: Confidence = "high",
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
            confidence=confidence,
        )

    def _error_result(self, *, sub_id: str, reason: str, evidence: str = "") -> CheckResult:
        """Resultado "no evaluable": el check no llegó a observar el objetivo.

        Va siempre con ``confidence="unverified"``, que es lo que impide que el
        motor de riesgo lo trate como una observación y que la dimensión cuente
        como cubierta.
        """
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
            confidence="unverified",
        )

    def _interstitial_result(self, signal) -> CheckResult:
        """El objetivo respondió con una página de verificación anti-bot.

        No es un fallo del objetivo ni un hallazgo de seguridad: es que no se
        pudo mirar el sitio. Se emite `unverified` para que ni penalice el score
        ni cuente esta dimensión como cubierta.
        """
        return self._error_result(
            sub_id=f"{self.id}_interstitial",
            reason=(
                f"{signal.summary} Este check no se ejecutó: evaluarlo sobre la página de "
                f"verificación habría producido hallazgos falsos sobre el sitio real."
            ),
            evidence=signal.evidence,
        )
