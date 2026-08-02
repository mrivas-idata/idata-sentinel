"""Caché en disco del mejor inventario de subdominios conocido por dominio.

Motivación empírica: los registros de Certificate Transparency (crt.sh,
certspotter) son intermitentes, y hubo escaneos reales donde **todas** las fuentes
cayeron a la vez y el inventario quedó en "1 activo" pese a que el cliente tiene
decenas. Este caché conserva los nombres descubiertos en corridas anteriores para
que un re-escaneo no pierda el inventario cuando las fuentes están caídas.

No introduce falsos positivos: un subdominio que ya no existe, recuperado del
caché, se vuelve a perfilar en la corrida nueva y aparecerá como "no resuelve".
El caché preserva el **nombre a verificar**, no un estado; la verificación siempre
es fresca.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SubdomainCache:
    path: Path

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, ValueError, OSError) as e:
            logger.info("caché de subdominios ilegible (%s); se ignora", e)
            return {}

    def known(self, apex: str) -> set[str]:
        entry = self._load().get(apex.lower(), {})
        return set(entry.get("hosts", []))

    def update(self, apex: str, hosts) -> None:
        """Fusiona `hosts` con lo ya conocido para `apex` y persiste. Se llama solo
        cuando la corrida confirmó nombres en vivo: si todas las fuentes fallaron,
        el llamador no invoca esto y el caché anterior queda intacto."""
        hosts = {h.lower().rstrip(".") for h in hosts if h}
        if not hosts:
            return
        data = self._load()
        apex = apex.lower()
        merged = set(data.get(apex, {}).get("hosts", [])) | hosts
        data[apex] = {
            "hosts": sorted(merged),
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(data, ensure_ascii=False, indent=0), encoding="utf-8"
            )
        except OSError as e:  # el caché es una optimización: nunca rompe el escaneo
            logger.info("no se pudo escribir el caché de subdominios (%s)", e)
