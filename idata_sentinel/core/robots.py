"""Parseo y aplicación de robots.txt (plan maestro §1.2 — respetar robots.txt en modo pasivo).

Dos usos distintos conviven aquí:

- **Obedecer**: `can_fetch(path)` decide si el escáner puede pedir una ruta. Es
  la política del modo pasivo y no admite excepciones.
- **Observar**: `can_fetch(path, user_agent=...)` responde qué le permite el
  sitio a *otro* agente. Lo necesita el Módulo 5 para informar si el sitio se
  cierra a los motores generativos (plan SEO/GEO §7.1). No cambia lo que el
  escáner hace: solo lee la política publicada.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.robotparser import RobotFileParser

from idata_sentinel.core.http_client import USER_AGENT


@dataclass
class RobotsPolicy:
    _parser: RobotFileParser
    _found: bool
    #: Texto original. `RobotFileParser` no lo conserva y el Módulo 5 necesita
    #: releerlo para saber qué agentes están **nombrados**, que es distinto de
    #: qué agentes están permitidos.
    _text: str = ""

    @classmethod
    def empty(cls) -> "RobotsPolicy":
        parser = RobotFileParser()
        parser.parse([])
        return cls(_parser=parser, _found=False, _text="")

    @classmethod
    def from_text(cls, text: str) -> "RobotsPolicy":
        parser = RobotFileParser()
        parser.parse(text.splitlines())
        return cls(_parser=parser, _found=True, _text=text)

    @property
    def text(self) -> str:
        return self._text

    @property
    def found(self) -> bool:
        return self._found

    def can_fetch(self, path: str, user_agent: str | None = None) -> bool:
        """Si `user_agent` (por defecto, el nuestro) puede pedir `path`.

        Sin robots.txt todo está permitido, que es lo que asume cualquier
        rastreador y lo que dice el estándar.
        """
        if not self._found:
            return True
        return self._parser.can_fetch(user_agent or USER_AGENT, path)

    def names_agent(self, user_agent: str) -> bool:
        """Si el archivo menciona explícitamente a ese agente.

        Distingue «el sitio decidió permitirlo» de «el sitio no lo consideró».
        Ambas cosas dejan pasar al agente, pero solo la segunda es una omisión.
        """
        wanted = user_agent.lower()
        for raw in self._text.splitlines():
            line = raw.split("#", 1)[0].strip()
            field_name, _, value = line.partition(":")
            if field_name.strip().lower() == "user-agent" and value.strip().lower() == wanted:
                return True
        return False
