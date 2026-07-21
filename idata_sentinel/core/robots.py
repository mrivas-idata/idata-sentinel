"""Parseo y aplicación de robots.txt (plan maestro §1.2 — respetar robots.txt en modo pasivo)."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.robotparser import RobotFileParser

from idata_sentinel.core.http_client import USER_AGENT


@dataclass
class RobotsPolicy:
    _parser: RobotFileParser
    _found: bool

    @classmethod
    def empty(cls) -> "RobotsPolicy":
        parser = RobotFileParser()
        parser.parse([])
        return cls(_parser=parser, _found=False)

    @classmethod
    def from_text(cls, text: str) -> "RobotsPolicy":
        parser = RobotFileParser()
        parser.parse(text.splitlines())
        return cls(_parser=parser, _found=True)

    def can_fetch(self, path: str) -> bool:
        if not self._found:
            return True
        return self._parser.can_fetch(USER_AGENT, path)
