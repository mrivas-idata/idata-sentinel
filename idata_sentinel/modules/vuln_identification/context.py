"""`ScanContext` se movió a `core/scan_context.py` al pasar a compartirse con el
Módulo 3 (Datos Personales). Este alias mantiene el import histórico del Módulo 1."""
from __future__ import annotations

from idata_sentinel.core.scan_context import Mode, ScanContext

__all__ = ["Mode", "ScanContext"]
