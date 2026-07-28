"""Nombres de dominio: normalización y dominio registrable.

Vive en `core/` porque tres consumidores necesitan la misma respuesta y hasta
ahora cada uno la improvisaba:

- el descubrimiento por Certificate Transparency, que debe consultar el dominio
  registrable (con `www.` en la URL, el inventario salía siempre vacío);
- los checks de DNS y correo, que deben mirar SPF/DMARC en el dominio
  organizacional y no en el host (`_dmarc.www.dominio.cl` no existe por
  definición, y reportarlo como ausente produjo una recomendación errónea);
- la detección de entornos no productivos, que necesita saber qué etiquetas
  están *por delante* del dominio registrable.

No se usa la Public Suffix List completa a propósito: son ~9.000 reglas que
habría que mantener actualizadas para un puñado de sufijos que aparecen en la
práctica. Se cubren los multi-etiqueta habituales en Chile y la región, y se
declara el límite en vez de fingir exactitud.
"""
from __future__ import annotations

#: Sufijos públicos de dos etiquetas. Un dominio bajo uno de ellos necesita tres
#: etiquetas para ser registrable (`empresa.com.ar`, no `com.ar`).
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        # Chile
        "gob.cl", "gov.cl", "co.cl",
        # Cono sur y región
        "com.ar", "gob.ar", "org.ar", "net.ar", "edu.ar",
        "com.br", "gov.br", "org.br", "net.br", "edu.br",
        "com.pe", "gob.pe", "org.pe", "net.pe", "edu.pe",
        "com.co", "gov.co", "org.co", "net.co", "edu.co",
        "com.mx", "gob.mx", "org.mx", "net.mx", "edu.mx",
        "com.uy", "gub.uy", "org.uy", "net.uy", "edu.uy",
        "com.bo", "gob.bo", "org.bo", "net.bo", "edu.bo",
        "com.py", "gov.py", "org.py", "net.py", "edu.py",
        "com.ve", "gob.ve", "org.ve", "net.ve", "edu.ve",
        "com.ec", "gob.ec", "org.ec", "net.ec", "edu.ec",
        # Internacionales frecuentes
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "com.es", "com.au", "net.au", "org.au", "gov.au", "edu.au",
        "co.nz", "org.nz", "net.nz", "govt.nz",
        "co.za", "org.za", "com.sg", "com.hk", "co.jp", "or.jp", "ne.jp",
    }
)


def normalize_host(host: str) -> str:
    """Forma canónica de un nombre: minúsculas, sin punto final, sin puerto.

    Sin esto, `X.CL`, `x.cl.` y `x.cl:443` son tres activos distintos.
    """
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:  # IPv6 literal: [::1]:443
        return host[: host.index("]") + 1]
    # Un puerto solo se separa si lo que sigue son dígitos: así no se parte un
    # IPv6 sin corchetes.
    if ":" in host:
        head, _, tail = host.rpartition(":")
        if head and tail.isdigit():
            host = head
    return host


def registrable_domain(host: str) -> str:
    """Dominio bajo el que se registran los nombres: `www.a.b.cl` -> `b.cl`.

    Devuelve el host normalizado tal cual si no hay suficientes etiquetas o si
    parece una dirección IP — en ambos casos no hay nada que recortar.
    """
    host = normalize_host(host)
    if not host or _looks_like_ip(host):
        return host

    labels = host.split(".")
    if len(labels) <= 2:
        return host

    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_labels(host: str) -> list[str]:
    """Etiquetas que quedan por delante del dominio registrable.

    `beta.api.empresa.com.ar` -> `["beta", "api"]`. Es lo que hay que mirar para
    decidir si un activo es un entorno no productivo: el TLD de un apex no dice
    nada sobre el entorno.
    """
    host = normalize_host(host)
    apex = registrable_domain(host)
    if host == apex or not host.endswith("." + apex):
        return []
    return host[: -(len(apex) + 1)].split(".")


def is_subdomain_of(host: str, domain: str) -> bool:
    """Si `host` es el propio `domain` o cuelga de él."""
    host, domain = normalize_host(host), normalize_host(domain)
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _looks_like_ip(host: str) -> bool:
    if host.startswith("["):  # IPv6 entre corchetes
        return True
    if ":" in host:  # IPv6 sin corchetes
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts)
