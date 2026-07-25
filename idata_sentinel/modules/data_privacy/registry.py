"""Registro explícito de checks del Módulo 3 (evita descubrimiento mágico)."""
from __future__ import annotations

from idata_sentinel.checks.privacy_signals import (
    ConsentTrackingCheck,
    PrivacyFormsCheck,
    PrivacyPolicyCheck,
)
from idata_sentinel.core.check_base import BaseCheck, Mode

ALL_CHECKS: list[type[BaseCheck]] = [
    PrivacyPolicyCheck,
    PrivacyFormsCheck,
    ConsentTrackingCheck,
]


def checks_for_mode(mode: Mode) -> list[BaseCheck]:
    return [C() for C in ALL_CHECKS if mode in C.modes]
