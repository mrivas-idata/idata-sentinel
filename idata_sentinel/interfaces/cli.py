"""CLI mínima (plan maestro §9.1, roadmap Fase 1 paso 6)."""
from __future__ import annotations

import asyncio
import json as json_module
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from idata_sentinel.core.authorization import AuthorizationRequest
from idata_sentinel.core.engine import Engine, ScanRequest
from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule
from idata_sentinel.reporting.pdf_export import export_pdf
from idata_sentinel.reporting.report_builder import build_report_context
from idata_sentinel.scoring.risk_engine import calculate

app = typer.Typer(help="IDATA Sentinel — diagnóstico de seguridad web.")
console = Console()

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_engine() -> Engine:
    engine = Engine()
    engine.register_module(VulnIdentificationModule())
    return engine


@app.command()
def scan(
    target: str = typer.Argument(..., help="URL objetivo, p.ej. https://ejemplo.cl"),
    mode: str = typer.Option("passive", "--mode", help="passive | audit"),
    i_have_authorization: bool = typer.Option(False, "--i-have-authorization"),
    authorized_by: str = typer.Option("", "--authorized-by", help="Nombre, cargo de quien autoriza"),
    contract: str = typer.Option("", "--contract", help="N° de contrato/orden"),
    allowed_domain: list[str] = typer.Option([], "--allowed-domain", help="Dominio en scope (repetible)"),
    json_output: Path = typer.Option(None, "--json", help="Ruta para exportar el resultado en JSON"),
    pdf_output: Path = typer.Option(None, "--pdf", help="Ruta para exportar el reporte ejecutivo en PDF"),
) -> None:
    """Ejecuta un escaneo de vulnerabilidades (Módulo 1) contra TARGET."""
    if mode not in ("passive", "audit"):
        console.print(f"[red]Modo inválido: {mode}. Usa 'passive' o 'audit'.[/red]")
        raise typer.Exit(code=1)

    authorization = None
    if mode == "audit":
        authorization = AuthorizationRequest(
            target=target,
            allowed_domains=tuple(allowed_domain) or (target,),
            authorized_by=authorized_by,
            contract_reference=contract,
            confirmed=i_have_authorization,
        )

    engine = _build_engine()
    request = ScanRequest(target=target, mode=mode, authorization=authorization)
    result = asyncio.run(engine.scan(request))

    risk = calculate(result["modules"])
    result["risk"] = risk.to_dict()

    _print_summary(target, result, risk)

    if json_output:
        json_output.write_text(json_module.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"\n[green]JSON exportado a {json_output}[/green]")

    if pdf_output:
        report_context = build_report_context(result, risk.to_dict())
        try:
            export_pdf(report_context, pdf_output)
            console.print(f"[green]PDF exportado a {pdf_output}[/green]")
        except Exception as e:
            console.print(f"[red]No se pudo generar el PDF ({type(e).__name__}: {e}).[/red]")
            console.print("[yellow]WeasyPrint requiere las librerías nativas de Pango/Cairo/GObject "
                           "(disponibles en el contenedor de Railway; ver plan de infraestructura §11.4).[/yellow]")


def _print_summary(target: str, result: dict, risk) -> None:
    console.print(f"\n[bold]IDATA Sentinel[/bold] — {target} (modo: {result['mode']})")
    console.print(f"Score: [bold]{risk.score}/100[/bold] ({risk.grade})\n")

    table = Table(title="Hallazgos")
    table.add_column("Severidad")
    table.add_column("ID")
    table.add_column("Título")

    all_findings = [f for findings in result["modules"].values() for f in findings]
    actionable = [f for f in all_findings if f["status"] in ("fail", "warning")]
    for f in sorted(actionable, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 5)):
        style = _SEVERITY_STYLE.get(f["severity"], "white")
        table.add_row(f"[{style}]{f['severity']}[/{style}]", f["id"], f["title"])

    if actionable:
        console.print(table)
    else:
        console.print("[green]Sin hallazgos fail/warning.[/green]")


if __name__ == "__main__":
    app()
