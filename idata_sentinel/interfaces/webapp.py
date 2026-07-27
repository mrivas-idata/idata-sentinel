"""App web de IDATA Sentinel (plan maestro §9.2).

Cola asíncrona en memoria: un escaneo tarda minutos por el rate limit, así que la
petición HTTP dispara un job y devuelve enseguida. Es el MVP que el plan describe;
Celery/APScheduler y Supabase entran en la Fase 7.

**Control de acceso**: si existe la variable de entorno `IDATA_SENTINEL_TOKEN`,
toda la app queda tras un formulario. Si no existe, la app avisa en pantalla y se
niega a escanear objetivos remotos salvo que quien la ejecuta lo fuerce — un
escáner abierto a Internet es una herramienta de abuso para terceros (§9.2).
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from idata_sentinel.core.authorization import AuthorizationRequest
from idata_sentinel.core.engine import Engine, ScanRequest
from idata_sentinel.docs import all_modules
from idata_sentinel.modules.asset_inventory.module import AssetInventoryModule
from idata_sentinel.modules.data_privacy.module import DataPrivacyModule
from idata_sentinel.modules.monitoring.module import MonitoringModule
from idata_sentinel.modules.monitoring.scheduler import MonitorScheduler
from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule
from idata_sentinel.reporting.branding import load_branding
from idata_sentinel.reporting.charts import (
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    grade_color,
    severity_color,
    severity_label,
    severity_segments,
    sparkline,
)
from idata_sentinel.reporting.report_builder import build_report_context
from idata_sentinel.scoring.risk_engine import calculate
from idata_sentinel.storage.db import DEFAULT_DB_PATH, ScanRecord, ScanStore

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).resolve().parent
TOKEN_COOKIE = "sentinel_token"

_MODULE_ALIASES = {
    "vuln": "vuln_identification",
    "assets": "asset_inventory",
    "privacy": "data_privacy",
}

#: Mínimo del modo pasivo (§1.2). Los re-escaneos programados lo respetan igual
#: que un escaneo manual.
MIN_RATE_LIMIT = 2.0

_COMPLIANCE_COLORS = {"brecha": "#d03b3b", "observacion": "#fab219", "sin_hallazgos": "#0ca30c"}
_COMPLIANCE_LABELS = {"brecha": "Brecha", "observacion": "Observación", "sin_hallazgos": "Sin hallazgos"}


@dataclass
class ScanJob:
    id: str
    target: str
    mode: str
    modules: str
    rate_limit: float
    status: str = "running"  # running | done | error
    stage: str = "Preparando el escaneo…"
    error: str = ""
    result: dict | None = None
    risk: dict | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _lifespan_with_scheduler(poll_seconds: float):
    """Arranca el monitoreo junto a la app y lo detiene con ella."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async def _rescan(monitor) -> None:
            job = ScanJob(
                id=secrets.token_urlsafe(8), target=monitor.target, mode=monitor.mode,
                modules=monitor.modules, rate_limit=MIN_RATE_LIMIT,
            )
            app.state.jobs[job.id] = job
            await _run_job(app, job, authorization=None, record=True)

        scheduler = MonitorScheduler(
            store=app.state.store, run_scan=_rescan, poll_seconds=poll_seconds
        )
        task = asyncio.create_task(scheduler.serve_forever())
        logger.info("monitoreo en proceso iniciado (cada %ss)", poll_seconds)
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    return lifespan


def _resolve_modules(raw: str) -> list[str] | None:
    raw = (raw or "").strip().lower()
    if not raw or raw == "all":
        return None
    return [_MODULE_ALIASES.get(n.strip(), n.strip()) for n in raw.split(",") if n.strip()]


def _short_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").rstrip("/")[:26]


def create_app(
    *,
    store: ScanStore | None = None,
    token: str | None = None,
    with_scheduler: bool = False,
    scheduler_poll_seconds: float = 3600.0,
) -> FastAPI:
    """Factory: recibir el almacén por parámetro mantiene los tests aislados.

    `with_scheduler` levanta el monitoreo dentro de este mismo proceso. Es lo que
    permite desplegar en un solo servicio: un volumen persistente se monta en un
    único servicio, así que web y worker separados no podrían compartir la base
    SQLite. Con Postgres gestionado se vuelve a separar en dos servicios.
    """
    app = FastAPI(
        title="IDATA Sentinel",
        docs_url=None,
        redoc_url=None,
        lifespan=_lifespan_with_scheduler(scheduler_poll_seconds) if with_scheduler else None,
    )
    app.mount("/static", StaticFiles(directory=_BASE_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))

    app.state.store = store or ScanStore(DEFAULT_DB_PATH)
    app.state.token = token if token is not None else os.environ.get("IDATA_SENTINEL_TOKEN", "")
    app.state.jobs: dict[str, ScanJob] = {}

    def require_auth(request: Request) -> None:
        if not app.state.token:
            return  # sin token configurado la app queda abierta y lo advierte en pantalla
        if request.cookies.get(TOKEN_COOKIE) != app.state.token:
            raise HTTPException(status_code=307, headers={"Location": "/acceso"})

    def base_context(request: Request, **extra) -> dict:
        store_ = app.state.store
        targets = [
            {
                "target": t,
                "short": _short_host(t),
                "color": grade_color((store_.latest_scan(t) or _EMPTY).grade),
            }
            for t in store_.targets()[:12]
        ]
        return {
            "request": request,
            "branding": load_branding(),
            "auth_enabled": bool(app.state.token),
            "targets": targets,
            "severity_color": severity_color,
            "severity_label": severity_label,
            "compliance_color": lambda s: _COMPLIANCE_COLORS.get(s, "#898781"),
            "compliance_label": lambda s: _COMPLIANCE_LABELS.get(s, s),
            "severity_legend": [(k, SEVERITY_LABELS[k], SEVERITY_COLORS[k]) for k in SEVERITY_ORDER],
            **extra,
        }

    # -- acceso ------------------------------------------------------------

    @app.get("/acceso", response_class=HTMLResponse)
    async def access_form(request: Request):
        return HTMLResponse(_ACCESS_PAGE)

    @app.post("/acceso")
    async def access_submit(token_input: str = Form(..., alias="token")):
        if not app.state.token or not secrets.compare_digest(token_input, app.state.token):
            return HTMLResponse(_ACCESS_PAGE.replace("<!--ERR-->", "Token inválido."), status_code=401)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(TOKEN_COOKIE, app.state.token, httponly=True, samesite="lax")
        return response

    # -- panel -------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, _: None = Depends(require_auth)):
        store_ = app.state.store
        overview, kpis = _build_overview(store_)
        return templates.TemplateResponse(
            request, "dashboard.html.jinja2",
            base_context(
                request, active="dashboard", overview=overview, kpis=kpis,
                monitors=store_.list_monitors(),
            ),
        )

    @app.get("/nuevo", response_class=HTMLResponse)
    async def new_scan(request: Request, _: None = Depends(require_auth)):
        return templates.TemplateResponse(
            request, "new_scan.html.jinja2",
            base_context(
                request, active="new", form={}, error=None,
                modules_help=[
                    {"label": m.label, "tagline": m.tagline, "color": color}
                    for m, color in zip(all_modules(), ("#3987e5", "#1baf7a", "#fab219", "#9085e9"))
                ],
            ),
        )

    @app.post("/escanear")
    async def start_scan(
        request: Request,
        _: None = Depends(require_auth),
        target: str = Form(...),
        mode: str = Form("passive"),
        modules: str = Form("all"),
        rate_limit: str = Form("2.0"),
        authorized_by: str = Form(""),
        contract: str = Form(""),
        allowed_domains: str = Form(""),
        i_have_authorization: str = Form(""),
        record: str = Form(""),
    ):
        error = _validate_scan_form(target, mode, i_have_authorization, authorized_by, contract)
        if error:
            return templates.TemplateResponse(
                request, "new_scan.html.jinja2",
                base_context(
                    request, active="new", error=error,
                    form={"target": target, "mode": mode},
                    modules_help=[
                        {"label": m.label, "tagline": m.tagline, "color": color}
                        for m, color in zip(all_modules(), ("#3987e5", "#1baf7a", "#fab219", "#9085e9"))
                    ],
                ),
                status_code=400,
            )

        try:
            rate = max(0.0, float(rate_limit))
        except ValueError:
            rate = 2.0

        job = ScanJob(
            id=secrets.token_urlsafe(8), target=target.strip(), mode=mode,
            modules=modules, rate_limit=rate,
        )
        app.state.jobs[job.id] = job

        authorization = None
        if mode == "audit":
            domains = tuple(
                d.strip() for d in allowed_domains.replace("\n", ",").split(",") if d.strip()
            )
            authorization = AuthorizationRequest(
                target=job.target,
                allowed_domains=domains or (job.target,),
                authorized_by=authorized_by,
                contract_reference=contract,
                confirmed=bool(i_have_authorization),
            )

        asyncio.create_task(
            _run_job(app, job, authorization=authorization, record=bool(record))
        )
        return RedirectResponse(f"/escaneo/{job.id}", status_code=303)

    @app.get("/escaneo/{job_id}", response_class=HTMLResponse)
    async def scan_view(request: Request, job_id: str, _: None = Depends(require_auth)):
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")

        if job.status != "done":
            return templates.TemplateResponse(
                request, "scan_status.html.jinja2", base_context(request, active="new", job=job)
            )
        return templates.TemplateResponse(
            request, "scan_result.html.jinja2",
            base_context(request, active="new", **_result_context(
                app.state.store, job.target, job.result, job.risk, job.created_at
            )),
        )

    @app.get("/objetivo", response_class=HTMLResponse)
    async def target_view(request: Request, target: str, _: None = Depends(require_auth)):
        record = app.state.store.latest_scan(target)
        if record is None:
            raise HTTPException(status_code=404, detail="Objetivo sin escaneos registrados")

        scan_result = {
            "target": record.target, "mode": record.mode,
            "modules": _group_by_module(record.findings), "artifacts": record.artifacts,
        }
        risk = calculate(scan_result["modules"]).to_dict()
        return templates.TemplateResponse(
            request, "scan_result.html.jinja2",
            base_context(request, active_target=target, **_result_context(
                app.state.store, target, scan_result, risk, record.scanned_at
            )),
        )

    @app.get("/ayuda", response_class=HTMLResponse)
    async def help_view(request: Request, _: None = Depends(require_auth)):
        return templates.TemplateResponse(
            request, "help.html.jinja2", base_context(request, active="help", modules=all_modules())
        )

    # -- API JSON (contrato estable, §9.3) ---------------------------------

    @app.get("/api/escaneo/{job_id}")
    async def api_job(job_id: str, _: None = Depends(require_auth)):
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        return JSONResponse({
            "id": job.id, "target": job.target, "mode": job.mode, "status": job.status,
            "stage": job.stage, "error": job.error, "risk": job.risk, "result": job.result,
        })

    @app.get("/api/objetivo")
    async def api_target(target: str, _: None = Depends(require_auth)):
        record = app.state.store.latest_scan(target)
        if record is None:
            raise HTTPException(status_code=404, detail="Objetivo sin escaneos registrados")
        modules = _group_by_module(record.findings)
        return JSONResponse({
            "target": record.target, "mode": record.mode, "scanned_at": record.scanned_at,
            "risk": calculate(modules).to_dict(), "modules": modules,
            "artifacts": record.artifacts,
        })

    @app.get("/api/modulos")
    async def api_modules(_: None = Depends(require_auth)):
        return JSONResponse([m.to_dict() for m in all_modules()])

    @app.get("/api/salud")
    async def api_health():
        return JSONResponse({"status": "ok", "auth": bool(app.state.token)})

    return app


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_EMPTY = ScanRecord(
    id=0, target="", mode="passive", scanned_at="", score=0, grade="",
    findings=[], artifacts={}, is_baseline=False,
)


def _validate_scan_form(
    target: str, mode: str, confirmed: str, authorized_by: str, contract: str
) -> str | None:
    if not target.strip().startswith(("http://", "https://")):
        return "La URL debe incluir el esquema, por ejemplo https://ejemplo.cl"
    if mode not in ("passive", "audit"):
        return "Modo inválido."
    if mode == "audit":
        if not confirmed:
            return "El modo auditoría exige declarar que cuentas con autorización escrita."
        if not authorized_by.strip() or not contract.strip():
            return "Indica quién autoriza y el número de contrato u orden de compra."
    return None


def _group_by_module(findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding.get("module", "desconocido"), []).append(finding)
    return grouped


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        if f.get("status") in ("fail", "warning"):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _build_overview(store: ScanStore) -> tuple[list[dict], dict]:
    overview: list[dict] = []
    total_severe = total_assets = total_reachable = total_scans = 0
    scores: list[int] = []

    for target in store.targets():
        history = store.history(target)
        latest = history[-1]
        counts = _severity_counts(latest.findings)
        surface = latest.surface_map() or {}
        totals = surface.get("totals", {})

        overview.append({
            "target": target,
            "score": latest.score,
            "grade": latest.grade,
            "grade_color": grade_color(latest.grade),
            "spark": sparkline([r.score for r in history], width=120, height=32),
            "segments": severity_segments(counts),
            "scanned_at": latest.scanned_at[:16].replace("T", " "),
        })
        scores.append(latest.score)
        total_scans += len(history)
        total_severe += counts.get("critical", 0) + counts.get("high", 0)
        total_assets += totals.get("discovered", 0)
        total_reachable += totals.get("reachable", 0)

    avg = round(sum(scores) / len(scores)) if scores else 0
    kpis = {
        "targets": len(overview), "scans": total_scans, "avg_score": avg,
        "avg_color": grade_color(_grade_of(avg)), "severe": total_severe,
        "assets": total_assets, "reachable": total_reachable,
    }
    return overview, kpis


def _grade_of(score: int) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return grade
    return "F"


def _result_context(
    store: ScanStore, target: str, scan_result: dict, risk: dict, scanned_at: str
) -> dict:
    report = build_report_context(scan_result, risk)
    history = store.history(target)
    trend = None
    spark = sparkline([])
    if len(history) > 1:
        from idata_sentinel.modules.monitoring.diff import build_trend

        trend = build_trend(history)
        spark = sparkline([p["score"] for p in trend["points"]], width=280, height=64)

    findings = report["all_findings"]
    return {
        "target": target,
        "mode": scan_result["mode"],
        "mode_label": report["mode_label"],
        "scanned_at": scanned_at[:16].replace("T", " "),
        "score": risk["score"],
        "grade": risk["grade"],
        "grade_color": grade_color(risk["grade"]),
        "segments": severity_segments(_severity_counts(findings)),
        "total_findings": len(findings),
        "findings": findings,
        "module_summaries": report["module_summaries"],
        "surface_map": report["surface_map"],
        "compliance": report["compliance"],
        "monitoring": scan_result.get("artifacts", {}).get("monitoring", {}).get("monitoring"),
        "trend": trend,
        "spark": spark,
    }


async def _run_job(
    app: FastAPI, job: ScanJob, *, authorization: AuthorizationRequest | None, record: bool
) -> None:
    try:
        job.stage = "Ejecutando los módulos de diagnóstico…"
        engine = Engine(rate_limit_seconds=job.rate_limit)
        engine.register_module(VulnIdentificationModule())
        engine.register_module(AssetInventoryModule())
        engine.register_module(DataPrivacyModule())
        if record:
            engine.register_module(MonitoringModule(app.state.store))

        result = await engine.scan(ScanRequest(
            target=job.target, mode=job.mode,
            modules=_resolve_modules(job.modules), authorization=authorization,
        ))
        risk = calculate(result["modules"])

        if record:
            job.stage = "Guardando el resultado…"
            app.state.store.record_scan(
                target=job.target, mode=result["mode"], score=risk.score, grade=risk.grade,
                findings=[f for group in result["modules"].values() for f in group],
                artifacts=result.get("artifacts", {}),
            )

        job.result = result
        job.risk = risk.to_dict()
        job.status = "done"
        job.stage = "Completado"
    except Exception as e:
        logger.exception("el escaneo %s falló", job.id)
        job.status = "error"
        job.error = f"{type(e).__name__}: {e}"


_ACCESS_PAGE = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acceso — IDATA Sentinel</title><link rel="stylesheet" href="/static/app.css"></head>
<body><div style="display:grid; place-items:center; min-height:100vh; padding:24px;">
<form class="card" method="post" action="/acceso" style="width:min(380px,100%);">
  <div class="brand-mark" style="margin-bottom:6px;">IDATA Sentinel</div>
  <div class="brand-sub" style="margin-bottom:22px;">Acceso restringido</div>
  <div class="field">
    <label for="token">Token de acceso</label>
    <input type="password" id="token" name="token" autofocus required>
  </div>
  <p style="color:#d03b3b; font-size:13px; margin:10px 0 0;"><!--ERR--></p>
  <button class="btn" type="submit" style="margin-top:18px; width:100%; justify-content:center;">Entrar</button>
</form></div></body></html>"""


app = None  # se construye en tiempo de arranque (uvicorn factory)


def get_app() -> FastAPI:
    """Punto de entrada para uvicorn: `uvicorn idata_sentinel.interfaces.webapp:get_app --factory`."""
    return create_app()
