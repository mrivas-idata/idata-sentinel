"""CLI de IDATA Sentinel (plan maestro §9.1)."""
from __future__ import annotations

import asyncio
import json as json_module
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from idata_sentinel.core.active_gate import ActiveCapabilityGate
from idata_sentinel.core.authorization import AuditLogger, AuthorizationRequest
from idata_sentinel.core.engine import Engine, ScanRequest
from idata_sentinel.core.session import ClientSession, SessionError
from idata_sentinel.docs import all_modules, module_help
from idata_sentinel.modules.asset_inventory.module import AssetInventoryModule
from idata_sentinel.modules.data_privacy.module import DataPrivacyModule
from idata_sentinel.modules.monitoring.alerts import CollectingNotifier, WebhookNotifier
from idata_sentinel.modules.monitoring.module import MonitoringModule
from idata_sentinel.modules.monitoring.scheduler import MonitorScheduler
from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule
from idata_sentinel.reporting.pdf_export import export_pdf
from idata_sentinel.reporting.report_builder import build_report_context
from idata_sentinel.scoring.risk_engine import calculate
from idata_sentinel.storage.db import DEFAULT_DB_PATH, SCHEDULES, ScanStore

app = typer.Typer(help="IDATA Sentinel — plataforma de diagnóstico de seguridad web (IDATA Chile).")
monitor_app = typer.Typer(help="Monitoreo continuo: programa re-escaneos y detecta cambios.")
app.add_typer(monitor_app, name="monitor")

console = Console()

#: Alias corto (CLI) -> nombre interno del módulo.
MODULE_ALIASES = {
    "vuln": "vuln_identification",
    "assets": "asset_inventory",
    "privacy": "data_privacy",
    "monitor": "monitoring",
}

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


#: Mínimo que exige el plan maestro §1.2 para el modo pasivo. Es configurable
#: —el propio plan lo dice— pero bajarlo se advierte de forma explícita.
MIN_PASSIVE_RATE_LIMIT = 2.0


def _build_engine(
    *, store: ScanStore | None = None, notifiers: list | None = None, rate_limit: float = 2.0
) -> Engine:
    engine = Engine(rate_limit_seconds=rate_limit)
    engine.register_module(VulnIdentificationModule())
    engine.register_module(AssetInventoryModule())
    engine.register_module(DataPrivacyModule())
    if store is not None:
        engine.register_module(MonitoringModule(store, notifiers=notifiers or []))
    return engine


def _resolve_modules(raw: str) -> list[str] | None:
    """'all' (o vacío) = todos los registrados; si no, lista separada por comas
    con alias cortos (`vuln,assets`) o nombres internos."""
    raw = (raw or "").strip().lower()
    if not raw or raw == "all":
        return None
    return [MODULE_ALIASES.get(n.strip(), n.strip()) for n in raw.split(",") if n.strip()]


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(..., help="URL objetivo, p.ej. https://ejemplo.cl"),
    mode: str = typer.Option("passive", "--mode", help="passive | audit"),
    modules: str = typer.Option("all", "--modules", help="all | vuln,assets,privacy"),
    i_have_authorization: bool = typer.Option(False, "--i-have-authorization"),
    authorized_by: str = typer.Option("", "--authorized-by", help="Nombre, cargo de quien autoriza"),
    contract: str = typer.Option("", "--contract", help="N° de contrato/orden"),
    allowed_domain: list[str] = typer.Option([], "--allowed-domain", help="Dominio en scope (repetible)"),
    asset: list[str] = typer.Option([], "--asset", help="Activo adicional del cliente (solo audit, repetible)"),
    active_check: list[str] = typer.Option(
        [], "--active-check",
        help="Habilita UN check activo por su id (repetible; 'all' = todos). Solo audit.",
    ),
    i_understand_active: bool = typer.Option(
        False, "--i-understand-active",
        help="Doble confirmación obligatoria para ejecutar checks activos.",
    ),
    session_file: Path = typer.Option(
        None, "--session-file",
        help="Archivo JSON con la sesión provista por el cliente (escaneo autenticado).",
    ),
    record: bool = typer.Option(False, "--record", help="Guardar el escaneo y comparar contra la línea base"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db", help="Ruta de la base de datos local"),
    webhook: str = typer.Option("", "--webhook", help="URL para enviar alertas del monitoreo"),
    rate_limit: float = typer.Option(
        MIN_PASSIVE_RATE_LIMIT, "--rate-limit", help="Segundos entre requests al mismo host"
    ),
    json_output: Path = typer.Option(None, "--json", help="Ruta para exportar el resultado en JSON"),
    pdf_output: Path = typer.Option(None, "--pdf", help="Ruta para exportar el reporte ejecutivo en PDF"),
) -> None:
    """Ejecuta un escaneo de diagnóstico contra TARGET."""
    if mode not in ("passive", "audit"):
        console.print(f"[red]Modo inválido: {mode}. Usa 'passive' o 'audit'.[/red]")
        raise typer.Exit(code=1)
    if mode == "passive" and rate_limit < MIN_PASSIVE_RATE_LIMIT:
        console.print(
            f"[yellow]Aviso: rate limit de {rate_limit}s por debajo del mínimo de "
            f"{MIN_PASSIVE_RATE_LIMIT}s que define la política de modo pasivo.[/yellow]"
        )

    authorization = None
    if mode == "audit":
        authorization = AuthorizationRequest(
            target=target,
            allowed_domains=tuple(allowed_domain) or (target,),
            authorized_by=authorized_by,
            contract_reference=contract,
            confirmed=i_have_authorization,
            additional_assets=tuple(asset),
        )

    active_gate, client_session = _resolve_active_scope(
        target=target, mode=mode, active_check=active_check,
        i_understand_active=i_understand_active, session_file=session_file, db=db,
    )

    store = ScanStore(db) if record else None
    collector = CollectingNotifier()
    notifiers: list = [collector]
    if webhook:
        notifiers.append(WebhookNotifier(webhook))

    engine = _build_engine(
        store=store, notifiers=notifiers if record else None, rate_limit=rate_limit
    )
    request = ScanRequest(
        target=target, mode=mode, modules=_resolve_modules(modules), authorization=authorization,
        active_checks=active_gate.enabled, active_acknowledged=active_gate.acknowledged,
        client_session=client_session,
    )
    result = asyncio.run(engine.scan(request))

    risk = calculate(result["modules"])
    result["risk"] = risk.to_dict()

    if store is not None:
        all_findings = [f for group in result["modules"].values() for f in group]
        store.record_scan(
            target=target, mode=result["mode"], score=risk.score, grade=risk.grade,
            findings=all_findings, artifacts=result.get("artifacts", {}),
        )

    _print_summary(target, result, risk)
    if record and collector.sent:
        _print_alerts(collector.sent)

    if json_output:
        json_output.write_text(
            json_module.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
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

    all_findings = [f for findings in result["modules"].values() for f in findings]
    _print_coverage_warning(all_findings)

    table = Table(title="Hallazgos")
    table.add_column("Severidad")
    table.add_column("Módulo")
    table.add_column("ID")
    table.add_column("Título")

    actionable = [f for f in all_findings if f["status"] in ("fail", "warning")]
    for f in sorted(actionable, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 5)):
        style = _SEVERITY_STYLE.get(f["severity"], "white")
        table.add_row(
            f"[{style}]{f['severity']}[/{style}]", f["module"].replace("_", " "), f["id"], f["title"]
        )

    if actionable:
        console.print(table)
    else:
        console.print("[green]Sin hallazgos fail/warning.[/green]")

    surface = result.get("artifacts", {}).get("asset_inventory", {}).get("surface_map")
    if surface:
        t = surface["totals"]
        console.print(
            f"\n[bold]Superficie:[/bold] {t['discovered']} activo(s), {t['reachable']} accesible(s), "
            f"{t['https']} sobre HTTPS, {t['distinct_ips']} IP(s)."
        )


def _resolve_active_scope(
    *, target: str, mode: str, active_check: list[str],
    i_understand_active: bool, session_file: Path | None, db: Path,
) -> tuple[ActiveCapabilityGate, ClientSession | None]:
    """Resuelve el gate de activación y la sesión, aplicando las reglas del
    plan activo §4: activación por nombre, doble confirmación, y **aborto** —no
    degradación silenciosa— cuando se pide activo sin confirmar."""
    from idata_sentinel.modules.vuln_identification.registry import active_check_ids

    requested = [c.strip() for c in active_check if c.strip()]

    if requested and mode != "audit":
        console.print(
            "[red]Los checks activos solo corren en modo audit.[/red] "
            "Agrega --mode audit con autorización, o quita --active-check."
        )
        raise typer.Exit(code=1)

    if requested and not i_understand_active:
        # El operador PIDIÓ algo activo: hay que decírselo, no ejecutar a medias.
        AuditLogger(db.parent / "audit_log.json").record(
            target=target, decision="denied_active_unacknowledged",
            request=None, source_ip="cli",
            active_context={"active_checks_enabled": sorted(requested), "active_acknowledged": False,
                            "authenticated_scan": session_file is not None},
        )
        console.print(
            "[red]Pediste checks activos pero falta la confirmación.[/red]\n"
            "El modo activo no corre a medias: agrega [bold]--i-understand-active[/bold] "
            "para confirmar que tienes autorización para las técnicas activas."
        )
        raise typer.Exit(code=1)

    available = active_check_ids()
    if any(r.lower() == "all" for r in requested):
        console.print("[yellow]Se activarán TODOS los checks activos:[/yellow]")
        for cid in available:
            console.print(f"  · {cid}")
        console.print()
    else:
        unknown = [r for r in requested if r not in available]
        if unknown:
            console.print(
                f"[yellow]Ignorando check(s) activo(s) desconocido(s): {', '.join(unknown)}.[/yellow] "
                f"Disponibles: {', '.join(available) or '(ninguno)'}."
            )

    gate = ActiveCapabilityGate.resolve(
        requested, acknowledged=i_understand_active, available=available
    )

    if gate.enabled:
        # El operador ve el alcance activo exacto antes de que corra nada.
        console.print(Panel(
            "\n".join(f"  · {cid}" for cid in sorted(gate.enabled)),
            title="[bold]Técnicas activas que se ejecutarán[/bold]",
            border_style="red",
        ))
        console.print(
            "[dim]Auditoría activa no destructiva: solo GET/HEAD/OPTIONS, sin payloads. "
            "Autorización registrada en audit_log.json.[/dim]\n"
        )

    client_session = None
    if session_file is not None:
        try:
            client_session = ClientSession.from_file(session_file)
        except SessionError as e:
            console.print(f"[red]No se pudo cargar la sesión: {e}[/red]")
            raise typer.Exit(code=1) from e
        console.print("[dim]Escaneo autenticado: sesión provista por el cliente cargada.[/dim]")

    return gate, client_session


def _print_coverage_warning(findings: list[dict]) -> None:
    """Avisa arriba del todo cuando el escaneo no llegó a ver el sitio.

    Ordenado por severidad, este aviso cae al final de la tabla —es `info`, no
    es un problema del objetivo— justo cuando es lo primero que el operador
    tiene que saber: sin esto, el informe se entrega como si describiera el
    sitio del prospecto.
    """
    blocked = next(
        (f for f in findings if f["id"].startswith("scan_blocked_by_interstitial")), None
    )
    if blocked is None:
        return

    console.print(Panel(
        f"{blocked['finding']}\n\n[bold]{blocked['recommendation']}[/bold]",
        title="[bold]Cobertura incompleta — no entregar como diagnóstico del sitio[/bold]",
        border_style="yellow",
    ))
    console.print()


def _print_alerts(alerts: list) -> None:
    console.print("\n[bold]Alertas de monitoreo[/bold]")
    for alert in alerts:
        color = {"critical": "red", "warning": "yellow"}.get(alert.level, "cyan")
        console.print(f"  [{color}]•[/{color}] {alert.title} — {alert.summary}")


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------


@monitor_app.command("add")
def monitor_add(
    target: str = typer.Argument(..., help="URL a monitorear"),
    schedule: str = typer.Option("weekly", "--schedule", help=f"{' | '.join(SCHEDULES)}"),
    mode: str = typer.Option("passive", "--mode", help="passive | audit"),
    modules: str = typer.Option("all", "--modules", help="all | vuln,assets,privacy"),
    webhook: str = typer.Option("", "--webhook", help="URL de webhook para las alertas"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
) -> None:
    """Programa re-escaneos periódicos de TARGET."""
    if schedule not in SCHEDULES:
        console.print(f"[red]Cadencia inválida: {schedule}. Usa {' | '.join(SCHEDULES)}.[/red]")
        raise typer.Exit(code=1)

    record = ScanStore(db).add_monitor(
        target=target, schedule=schedule, mode=mode, webhook_url=webhook or None, modules=modules
    )
    console.print(f"[green]Monitor creado:[/green] {record.target} ({record.schedule}, modo {record.mode})")


@monitor_app.command("list")
def monitor_list(db: Path = typer.Option(DEFAULT_DB_PATH, "--db")) -> None:
    """Lista los monitores configurados."""
    monitors = ScanStore(db).list_monitors()
    if not monitors:
        console.print("[yellow]Sin monitores configurados.[/yellow]")
        return

    table = Table(title="Monitores")
    for column in ("Objetivo", "Cadencia", "Modo", "Último escaneo", "Estado"):
        table.add_column(column)
    for m in monitors:
        table.add_row(
            m.target, m.schedule, m.mode, m.last_run_at or "—",
            "[green]activo[/green]" if m.active else "[dim]inactivo[/dim]",
        )
    console.print(table)


@monitor_app.command("remove")
def monitor_remove(
    target: str = typer.Argument(...), db: Path = typer.Option(DEFAULT_DB_PATH, "--db")
) -> None:
    """Elimina un monitor."""
    if ScanStore(db).remove_monitor(target):
        console.print(f"[green]Monitor eliminado:[/green] {target}")
    else:
        console.print(f"[yellow]No había un monitor para {target}.[/yellow]")


@monitor_app.command("status")
def monitor_status(
    target: str = typer.Argument(..., help="URL monitoreada"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
) -> None:
    """Muestra la tendencia del score de un objetivo."""
    history = ScanStore(db).history(target)
    if not history:
        console.print(f"[yellow]Sin escaneos registrados para {target}.[/yellow]")
        return

    table = Table(title=f"Tendencia — {target}")
    for column in ("Fecha", "Modo", "Score", "Nota", "Hallazgos"):
        table.add_column(column)
    for record in history:
        actionable = sum(1 for f in record.findings if f.get("status") in ("fail", "warning"))
        table.add_row(
            record.scanned_at[:16], record.mode, str(record.score), record.grade, str(actionable)
        )
    console.print(table)

    first, last = history[0], history[-1]
    delta = last.score - first.score
    trend = "[green]mejoró[/green]" if delta > 0 else ("[red]empeoró[/red]" if delta < 0 else "se mantuvo")
    console.print(f"\nDesde el primer escaneo el score {trend} {abs(delta)} punto(s).")


@monitor_app.command("run")
def monitor_run(
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
    once: bool = typer.Option(True, "--once/--forever", help="Una pasada o bucle de worker"),
    rate_limit: float = typer.Option(
        MIN_PASSIVE_RATE_LIMIT, "--rate-limit", help="Segundos entre requests al mismo host"
    ),
) -> None:
    """Ejecuta los monitores vencidos (servicio `worker` del plan §11.2)."""
    store = ScanStore(db)

    async def _run_scan(record) -> None:
        console.print(f"[cyan]Re-escaneando[/cyan] {record.target}…")
        collector = CollectingNotifier()
        notifiers: list = [collector]
        if record.webhook_url:
            notifiers.append(WebhookNotifier(record.webhook_url))

        engine = _build_engine(store=store, notifiers=notifiers, rate_limit=rate_limit)
        result = await engine.scan(ScanRequest(
            target=record.target, mode=record.mode, modules=_resolve_modules(record.modules)
        ))
        risk = calculate(result["modules"])
        store.record_scan(
            target=record.target, mode=result["mode"], score=risk.score, grade=risk.grade,
            findings=[f for g in result["modules"].values() for f in g],
            artifacts=result.get("artifacts", {}),
        )
        console.print(f"  score {risk.score}/100 ({risk.grade})")
        if collector.sent:
            _print_alerts(collector.sent)

    scheduler = MonitorScheduler(store=store, run_scan=_run_scan)
    executed = asyncio.run(scheduler.run_due() if once else scheduler.serve_forever())
    if once:
        console.print(
            f"[green]{len(executed or [])} monitor(es) ejecutado(s).[/green]"
            if executed else "[yellow]Ningún monitor vencido.[/yellow]"
        )


# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------


@app.command("doc")
def doc(
    source: Path = typer.Argument(..., help="Archivo Markdown a renderizar"),
    pdf_output: Path = typer.Option(None, "--pdf", help="Ruta del PDF de salida"),
    html_output: Path = typer.Option(None, "--html", help="Ruta del HTML de salida"),
    title: str = typer.Option("", "--title", help="Título; por defecto, el primer H1"),
    subtitle: str = typer.Option("", "--subtitle"),
    doc_type: str = typer.Option("Documento", "--tipo", help="Bajada de portada"),
    version: str = typer.Option("", "--version"),
    with_internal: bool = typer.Option(
        False, "--con-notas-internas", help="Conserva los bloques internos de IDATA"
    ),
) -> None:
    """Convierte un Markdown en un documento PDF con identidad IDATA."""
    from idata_sentinel.reporting.document import DocumentMeta, build_document_context
    from idata_sentinel.reporting.pdf_export import export_document_pdf, render_document_html

    if not source.exists():
        console.print(f"[red]No existe el archivo: {source}[/red]")
        raise typer.Exit(code=1)
    if not pdf_output and not html_output:
        console.print("[red]Indica al menos --pdf o --html.[/red]")
        raise typer.Exit(code=1)

    context = build_document_context(
        source,
        meta=DocumentMeta(
            title=title, subtitle=subtitle, document_type=doc_type, version=version
        ),
        include_internal=with_internal,
    )

    if context["internal_blocks_removed"]:
        console.print(
            f"[dim]{context['internal_blocks_removed']} bloque(s) de notas internas "
            f"eliminado(s) de la versión entregable.[/dim]"
        )
    if with_internal:
        console.print("[yellow]Copia interna: conserva las notas de IDATA. No la entregues.[/yellow]")

    pending = context["placeholders"]
    if pending:
        console.print(
            f"\n[yellow]Faltan {len(pending)} dato(s) por completar antes de entregar:[/yellow]"
        )
        for item in pending:
            # markup=False: los marcadores usan corchetes, que Rich interpretaría
            # como etiquetas de estilo y descartaría.
            console.print(f"  · {item}", markup=False, style="yellow")
        console.print()

    if html_output:
        html_output.write_text(render_document_html(context), encoding="utf-8")
        console.print(f"[green]HTML exportado a {html_output}[/green]")

    if pdf_output:
        try:
            export_document_pdf(context, pdf_output)
            console.print(f"[green]PDF exportado a {pdf_output}[/green]")
        except Exception as e:
            console.print(f"[red]No se pudo generar el PDF ({type(e).__name__}: {e}).[/red]")
            console.print(
                "[yellow]WeasyPrint requiere las librerías nativas de Pango/Cairo/GObject. "
                "Están en la imagen Docker del proyecto; en Windows no suelen estarlo.[/yellow]"
            )
            raise typer.Exit(code=1) from e


@app.command("keygen")
def keygen() -> None:
    """Genera una clave para cifrar en reposo los datos de escaneo (plan §1.4)."""
    from idata_sentinel.storage.crypto import ENV_KEY, generate_key

    key = generate_key()
    console.print(f"[green]Clave generada:[/green]\n\n  {key}\n")
    console.print(
        f"Expórtala como [bold]{ENV_KEY}[/bold] antes de escanear.\n"
        "[yellow]Guárdala en el gestor de secretos, nunca en el repositorio: sin ella "
        "los escaneos ya cifrados son irrecuperables.[/yellow]"
    )


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interfaz de escucha"),
    port: int = typer.Option(8000, "--port"),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db"),
    token: str = typer.Option("", "--token", help="Token de acceso; vacío = app abierta"),
    with_scheduler: bool = typer.Option(
        False, "--con-monitoreo",
        help="Ejecuta el monitoreo dentro de este proceso (despliegue de un solo servicio)",
    ),
) -> None:
    """Levanta la app web (plan maestro §9.2)."""
    import uvicorn

    from idata_sentinel.interfaces.webapp import create_app

    effective_token = token or os.environ.get("IDATA_SENTINEL_TOKEN", "")
    if host not in ("127.0.0.1", "localhost") and not effective_token:
        console.print(
            "[red]Negado: exponer la app fuera de localhost sin token la convierte en un "
            "escáner abierto que cualquiera puede usar contra activos de terceros.[/red]\n"
            "Define --token o la variable IDATA_SENTINEL_TOKEN."
        )
        raise typer.Exit(code=1)

    console.print(f"[green]IDATA Sentinel[/green] en http://{host}:{port}")
    console.print(f"[dim]base de datos: {db.resolve()}[/dim]")
    if with_scheduler:
        console.print("[dim]monitoreo continuo activo en este mismo proceso[/dim]")

    uvicorn.run(
        create_app(store=ScanStore(db), token=effective_token, with_scheduler=with_scheduler),
        host=host,
        port=port,
    )


@app.command("help")
def help_command(
    module: str = typer.Argument(None, help="vuln | assets | privacy | monitor (vacío = todos)")
) -> None:
    """Explica qué hace cada módulo, qué detecta y bajo qué límites legales."""
    if module is None:
        table = Table(title="Módulos de IDATA Sentinel")
        for column in ("Alias", "Módulo", "Fase", "Qué resuelve"):
            table.add_column(column)
        for m in all_modules():
            table.add_row(f"[bold]{m.alias}[/bold]", m.label, m.phase, m.tagline)
        console.print(table)
        console.print("\nDetalle de un módulo: [bold]idata-sentinel help <alias>[/bold]")
        return

    info = module_help(module)
    if info is None:
        aliases = ", ".join(m.alias for m in all_modules())
        console.print(f"[red]Módulo desconocido: {module}.[/red] Opciones: {aliases}")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]{info.label}[/bold] — {info.phase}\n[italic]{info.tagline}[/italic]\n\n{info.purpose}",
        title=f"idata-sentinel --modules {info.alias}",
    ))

    console.print("\n[bold]Qué revisa[/bold]")
    for item in info.what_it_does:
        console.print(f"  • {item}")

    console.print("\n[bold]Hallazgos característicos[/bold]")
    for item in info.key_findings:
        console.print(f"  • {item}")

    console.print(Panel(info.legal, title="Límites legales", border_style="yellow"))

    console.print("\n[bold]Ejemplos[/bold]")
    for example in info.examples:
        console.print(f"  [cyan]{example}[/cyan]")

    console.print(f"\n[dim]En el reporte: {info.report_section}[/dim]")


if __name__ == "__main__":
    app()
