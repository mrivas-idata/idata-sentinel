"""Gate de activación de capacidades activas (plan_implementacion_escaneo_activo.md §4).

Segundo gate, **ortogonal** al legal (`core/authorization.py`). El gate legal
responde "¿tiene el cliente derecho a que escaneemos este dominio?"; éste responde
"¿el operador pidió *esta* técnica activa, en este escaneo, y lo confirmó?".

Existe porque autorización legal ≠ activación técnica: un operador puede tener
`--i-have-authorization` sobre un dominio y aun así **no** querer que se dispare
la comprobación de métodos HTTP o el escaneo autenticado en esta corrida. Sin este
gate, un check activo correría "porque el modo era audit" — el accidente que todo
este diseño debe impedir.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from idata_sentinel.core.check_base import BaseCheck

#: Palabra reservada que expande a "todos los checks activos disponibles". No es un
#: atajo sin fricción: la CLI exige la doble confirmación y lista el alcance antes
#: de ejecutar (§4.2).
ALL = "all"


@dataclass(frozen=True)
class ActiveCapabilityGate:
    """Decide, por check, si su capacidad activa está habilitada.

    - ``enabled``: ids de checks activos que el operador nombró explícitamente.
    - ``acknowledged``: doble confirmación (`--i-understand-active` / checkbox).
    """

    enabled: frozenset[str]
    acknowledged: bool

    def allows(self, check: "BaseCheck", *, authorized: bool) -> bool:
        if not getattr(check, "active", False):
            return True  # check no-activo: este gate no lo gestiona
        return authorized and self.acknowledged and check.id in self.enabled

    @classmethod
    def disabled(cls) -> "ActiveCapabilityGate":
        """Gate cerrado: ninguna capacidad activa. Es el valor por defecto —el
        modo activo nunca se enciende por omisión."""
        return cls(frozenset(), acknowledged=False)

    @classmethod
    def resolve(
        cls,
        requested: Sequence[str],
        *,
        acknowledged: bool,
        available: Sequence[str],
    ) -> "ActiveCapabilityGate":
        """Construye el gate a partir de lo que pidió el operador.

        - `all` expande a `available` (la CLI ya validó la doble confirmación y
          listó el alcance antes de llamar aquí).
        - Los ids desconocidos se descartan en silencio: no habilitan nada. El
          principio es "ante la duda, no activar".
        """
        available_set = frozenset(available)
        if any(r.strip().lower() == ALL for r in requested):
            return cls(available_set, acknowledged=acknowledged)
        chosen = frozenset(r.strip() for r in requested if r.strip() in available_set)
        return cls(chosen, acknowledged=acknowledged)

    @property
    def any_requested(self) -> bool:
        return bool(self.enabled)
