"""Geometría de gráficos, calculada en Python y renderizada como SVG inline.

Sin librerías de charting ni CDN: el reporte se imprime con WeasyPrint (que no
ejecuta JavaScript) y la app web debe funcionar sin red externa. La misma
geometría alimenta ambos, así el gráfico del PDF y el de la web son idénticos.

Decisiones de color (guía de visualización de datos):
- La severidad es una escala de **estado**, no categórica: usa la paleta de
  estado fija y **siempre** va acompañada de su etiqueta de texto, nunca color
  solo. Esa es la mitigación documentada para el par medio/alto, cuyo ΔE de
  visión normal (13.6) queda bajo el piso de 15.
- El score es un **número protagonista** (hero figure) con un medidor debajo,
  no un gráfico: es un único valor contra un límite.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Paleta de estado fija. Validada a ≥3:1 sobre la superficie oscura de IDATA
#: (#131b2e). No se re-tematiza: un color de estado nunca imita a una serie.
SEVERITY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#3987e5",
    "info": "#898781",
}
SEVERITY_LABELS = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Bajo",
    "info": "Informativo",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

GRADE_COLORS = {
    "A": "#0ca30c",  # status good
    "B": "#0ca30c",
    "C": "#fab219",  # status warning
    "D": "#ec835a",  # status serious
    "F": "#d03b3b",  # status critical
}


@dataclass(frozen=True)
class Segment:
    key: str
    label: str
    count: int
    color: str
    percent: float


def severity_segments(counts: dict[str, int]) -> list[Segment]:
    """Segmentos de la barra apilada de severidad, en orden de gravedad.

    Solo se incluyen las severidades con al menos un hallazgo: un segmento de
    ancho cero no aporta y rompe el espaciado de 2px entre segmentos.
    """
    total = sum(counts.get(k, 0) for k in SEVERITY_ORDER)
    if total == 0:
        return []
    return [
        Segment(
            key=key,
            label=SEVERITY_LABELS[key],
            count=counts.get(key, 0),
            color=SEVERITY_COLORS[key],
            percent=round(counts.get(key, 0) * 100 / total, 1),
        )
        for key in SEVERITY_ORDER
        if counts.get(key, 0) > 0
    ]


@dataclass(frozen=True)
class Sparkline:
    points: str          # "x,y x,y …" para <polyline>
    area: str            # mismo trazo cerrado contra la base, para el relleno
    last_x: float
    last_y: float
    width: int
    height: int
    min_value: int
    max_value: int

    @property
    def has_data(self) -> bool:
        return bool(self.points)


def sparkline(
    values: list[int], *, width: int = 200, height: int = 48, padding: int = 4
) -> Sparkline:
    """Tendencia del score. Serie única: sin leyenda — el título ya la nombra."""
    if not values:
        return Sparkline("", "", 0, 0, width, height, 0, 0)

    low, high = min(values), max(values)
    span = (high - low) or 1
    inner_w = width - padding * 2
    inner_h = height - padding * 2

    if len(values) == 1:
        coords = [(padding + inner_w / 2, padding + inner_h / 2)]
    else:
        step = inner_w / (len(values) - 1)
        coords = [
            (padding + i * step, padding + inner_h - ((v - low) / span) * inner_h)
            for i, v in enumerate(values)
        ]

    points = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = f"{coords[0][0]:.1f},{height} {points} {coords[-1][0]:.1f},{height}"
    return Sparkline(
        points=points, area=area,
        last_x=round(coords[-1][0], 1), last_y=round(coords[-1][1], 1),
        width=width, height=height, min_value=low, max_value=high,
    )


def grade_color(grade: str) -> str:
    return GRADE_COLORS.get((grade or "").upper(), "#898781")


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#898781")


def severity_label(severity: str) -> str:
    return SEVERITY_LABELS.get(severity, severity)
