"""Identidad visual de IDATA, en un solo lugar (plan maestro §8).

El logo se incrusta como **data URI** en vez de referenciarse por ruta. Es la
única forma que funciona en los tres destinos sin código distinto para cada uno:

- WeasyPrint renderiza desde una cadena, sin URL base contra la que resolver
  rutas relativas.
- La app web sirve HTML que puede consumirse fuera de su propio dominio.
- Las vistas previas exportadas no pueden pedir recursos externos.

El PNG del repositorio está recortado y reducido a 320 px justo para que el
data URI no infle cada documento: pesa ~38 KB.
"""
from __future__ import annotations

import base64
import mimetypes
from functools import lru_cache
from pathlib import Path

import yaml

_BRANDING_DIR = Path(__file__).resolve().parent.parent / "branding"
_BRANDING_FILE = _BRANDING_DIR / "idata.yaml"


def _data_uri(path: Path) -> str | None:
    if not path.is_file():
        return None
    mime = mimetypes.guess_type(path.name)[0] or "image/png"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


@lru_cache(maxsize=1)
def load_branding() -> dict:
    """`logo_data_uri` queda en `None` si no hay logo configurado o el archivo
    no existe: las plantillas caen entonces al nombre de la empresa en texto."""
    branding = yaml.safe_load(_BRANDING_FILE.read_text(encoding="utf-8")) or {}

    logo = branding.get("logo_path")
    branding["logo_data_uri"] = _data_uri(_BRANDING_DIR / logo) if logo else None
    return branding
