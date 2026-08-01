"""Sesión provista por el cliente para escaneo autenticado
(plan_implementacion_escaneo_activo.md §7).

El cliente, dueño del activo, entrega **su propia** sesión ya autenticada para que
IDATA revise el comportamiento de la aplicación detrás del login. **Nunca** se
adivinan, fuerzan ni renuevan credenciales: se recibe material válido y se usa tal
cual, como lo haría el propio usuario, y **solo** para lectura.

Dos garantías estructurales:
- **Scope:** la sesión se adjunta únicamente a hosts que el cliente declaró y que
  además están en `allowed_domains`. Fuera de esa intersección, no se envía.
- **Secreto:** el material nunca se serializa ni entra a `repr`, `evidence` o
  `audit_log`. Solo se registra el booleano "hubo sesión provista".
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

SessionKind = Literal["cookie", "bearer"]


class SessionError(ValueError):
    """El archivo de sesión no se pudo interpretar o le falta información."""


@dataclass(frozen=True)
class ClientSession:
    kind: SessionKind
    #: Material sensible (cookie o token). Nunca se serializa: ver `__repr__`.
    material: str
    #: Hosts donde el cliente autorizó enviar la sesión. Se intersecta a su vez
    #: con `allowed_domains` del gate legal en el momento de adjuntarla.
    scope_hosts: frozenset[str]

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        return any(
            host == h or host.endswith("." + h)
            for h in (s.lower().rstrip(".") for s in self.scope_hosts)
        )

    def header_for(self, url: str) -> dict[str, str] | None:
        """Cabecera de autenticación para `url`, o `None` si está fuera de scope
        (en cuyo caso la petición se hace anónima, nunca con la sesión filtrada)."""
        if not self.in_scope(url):
            return None
        if self.kind == "cookie":
            return {"Cookie": self.material}
        return {"Authorization": f"Bearer {self.material}"}

    @classmethod
    def from_file(cls, path: str | Path) -> "ClientSession":
        """Carga la sesión desde un archivo JSON. Se usa archivo y no un flag de
        CLI a propósito: un token en la línea de comandos queda en el historial
        del shell, en `ps` y en logs de proceso; un archivo se lee a memoria y se
        puede borrar tras el escaneo."""
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise SessionError(f"No existe el archivo de sesión: {p}") from e
        except (json.JSONDecodeError, ValueError) as e:
            raise SessionError(f"El archivo de sesión no es JSON válido: {e}") from e
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> "ClientSession":
        if not isinstance(raw, dict):
            raise SessionError("El archivo de sesión debe ser un objeto JSON.")
        kind = str(raw.get("type", "")).lower()
        if kind not in ("cookie", "bearer"):
            raise SessionError("Campo 'type' debe ser 'cookie' o 'bearer'.")
        material = str(raw.get("value", "")).strip()
        if not material:
            raise SessionError("Campo 'value' (material de sesión) vacío.")
        scope = raw.get("scope_hosts") or []
        if not isinstance(scope, list) or not scope:
            raise SessionError("Campo 'scope_hosts' debe listar al menos un host.")
        return cls(
            kind=kind,  # type: ignore[arg-type]
            material=material,
            scope_hosts=frozenset(str(h).lower().strip().rstrip(".") for h in scope),
        )

    def __repr__(self) -> str:  # el material NUNCA aparece
        return f"ClientSession(kind={self.kind!r}, scope={sorted(self.scope_hosts)}, material=<redacted>)"
