from __future__ import annotations

import json

import httpx
import pytest
import respx

from idata_sentinel.core.authorization import AuthorizationRequest
from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.modules.asset_inventory.context import AssetProfile
from idata_sentinel.modules.asset_inventory.module import AssetInventoryModule
from idata_sentinel.modules.asset_inventory.surface import build_surface_map
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

APEX = "idata.test"

_CONTRACT_KEYS = FINDING_CONTRACT_KEYS


def _crtsh(*names: str) -> httpx.Response:
    return httpx.Response(200, text=json.dumps([{"name_value": n} for n in names]))


def _mock_certspotter(*names: str, response: httpx.Response | None = None) -> None:
    """El descubrimiento consulta dos registros de CT en paralelo. Los tests que
    solo simulan crt.sh dejan a certspotter sin mock, y el `return_exceptions`
    del gather se lo traga: el test pasaría por el motivo equivocado."""
    respx.get(url__startswith="https://api.certspotter.com/").mock(
        return_value=response
        if response is not None
        else httpx.Response(200, text=json.dumps([{"dns_names": list(names)}] if names else []))
    )


def _zone(extra: dict | None = None) -> dict:
    zone = {
        (APEX, "A"): ("203.0.113.10",),
        ("www." + APEX, "A"): ("203.0.113.10",),
        ("dev." + APEX, "A"): ("203.0.113.20",),
    }
    zone.update(extra or {})
    return zone


def _params(fake_dns_instance, *, mode="passive", authorized=False, authorization=None) -> RunParams:
    return RunParams(
        target=f"https://{APEX}",
        host=APEX,
        mode=mode,
        http=HttpClient(),
        rate_limiter=RateLimiter(min_interval=0.0),
        authorized=authorized,
        authorization=authorization,
        dns=fake_dns_instance,
    )


def _mock_web(default_body: str = "<html><title>IDATA</title></html>") -> None:
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=_crtsh("www." + APEX, "dev." + APEX)
    )
    _mock_certspotter()
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx/1.18.0"}, text=default_body)
    )
    respx.get(url__regex=r"http://[^/]*idata\.test/").mock(
        side_effect=httpx.ConnectError("sin http")
    )


# -- salida y contrato -----------------------------------------------------


@respx.mock
async def test_run_returns_module_output_with_surface_artifact(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    assert isinstance(output, ModuleOutput)
    assert "surface_map" in output.artifacts
    assert output.artifacts["surface_map"]["apex"] == APEX


@respx.mock
async def test_all_findings_conform_to_the_check_contract(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    assert output.findings
    for f in output.findings:
        assert set(f) == _CONTRACT_KEYS
        assert f["module"] == "asset_inventory"
        assert f["severity"] in {"info", "low", "medium", "high", "critical"}
        assert f["likelihood"] in {"low", "medium", "high"}
        assert f["status"] in {"pass", "fail", "warning", "info"}


@respx.mock
async def test_summary_finding_is_always_present(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))
    summary = next(f for f in output.findings if f["id"].startswith("attack_surface_summary"))
    assert summary["status"] == "info"


# -- descubrimiento y perfilado -------------------------------------------


@respx.mock
async def test_discovers_subdomains_and_profiles_each_one(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    hosts = {a["host"] for a in output.artifacts["surface_map"]["assets"]}
    assert hosts == {APEX, "www." + APEX, "dev." + APEX}
    assert output.artifacts["surface_map"]["totals"]["reachable"] == 3


@respx.mock
async def test_non_production_subdomain_is_flagged(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    flagged = [f for f in output.findings if f["id"].startswith("non_production_asset_exposed")]
    assert len(flagged) == 1
    assert "dev." + APEX in flagged[0]["id"]


@respx.mock
async def test_target_is_always_included_even_if_discovery_fails(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ConnectError("down"))
    _mock_certspotter()
    respx.get(url__regex=r"https://.*idata\.test/").mock(return_value=httpx.Response(200, text="ok"))

    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))
    hosts = {a["host"] for a in output.artifacts["surface_map"]["assets"]}
    assert hosts == {APEX}


@respx.mock
async def test_a_partial_discovery_is_declared_not_hidden(fake_dns):
    """Un inventario incompleto presentado como completo es peor que no tenerlo:
    el cliente creería que esa es toda su superficie de ataque. Con un registro
    caído el inventario sigue sirviendo, pero deja de ser exhaustivo."""
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ReadTimeout("lento"))
    _mock_certspotter("api." + APEX)
    respx.get(url__regex=r"https://.*idata\.test/").mock(return_value=httpx.Response(200, text="ok"))

    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    warning = next(
        f for f in output.findings if f["id"].startswith("asset_discovery_incomplete")
    )
    assert warning["status"] == "warning"
    assert "no puede presentarse como exhaustivo" in warning["finding"]
    assert "certspotter" in warning["finding"]  # se dice cuál respondió
    assert output.artifacts["surface_map"]["discovery_complete"] is False

    # …y lo que la fuente viva aportó se conserva: esa es la razón de tener dos.
    hosts = {a["host"] for a in output.artifacts["surface_map"]["assets"]}
    assert "api." + APEX in hosts


@respx.mock
async def test_a_total_discovery_failure_says_so(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ReadTimeout("lento"))
    _mock_certspotter(response=httpx.Response(502))
    respx.get(url__regex=r"https://.*idata\.test/").mock(return_value=httpx.Response(200, text="ok"))

    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    warning = next(
        f for f in output.findings if f["id"].startswith("asset_discovery_incomplete")
    )
    assert "Ningún registro" in warning["finding"]
    assert "incompleto" in warning["finding"]
    assert output.artifacts["surface_map"]["discovery_complete"] is False


@respx.mock
async def test_truncation_by_the_asset_cap_is_declared(fake_dns):
    """El tope de activos es una decisión de coste nuestra, no una medida de la
    superficie del cliente: presentarlo como el total repite el mismo engaño."""
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=_crtsh(*[f"a{i}.{APEX}" for i in range(30)])
    )
    _mock_certspotter()
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, text="ok")
    )
    respx.get(url__regex=r"http://[^/]*idata\.test/").mock(side_effect=httpx.ConnectError("x"))

    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    surface = output.artifacts["surface_map"]
    assert surface["discovery_total_known"] == 30
    assert surface["discovery_truncated"] > 0

    summary = next(f for f in output.findings if f["id"].startswith("attack_surface_summary"))
    assert "30 nombre(s)" in summary["finding"]
    assert "la superficie real es mayor" in summary["finding"]


@respx.mock
async def test_no_truncation_notice_when_everything_fits(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    assert output.artifacts["surface_map"]["discovery_truncated"] == 0
    summary = next(f for f in output.findings if f["id"].startswith("attack_surface_summary"))
    assert "superficie real es mayor" not in summary["finding"]


@respx.mock
async def test_sources_are_merged_and_their_origin_recorded(fake_dns):
    """Cada registro de CT ve un subconjunto distinto de certificados: la unión
    es el motivo de consultar dos, no la redundancia."""
    respx.get(url__startswith="https://crt.sh/").mock(return_value=_crtsh("www." + APEX))
    _mock_certspotter("dev." + APEX, "www." + APEX)
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, text="ok")
    )
    respx.get(url__regex=r"http://[^/]*idata\.test/").mock(side_effect=httpx.ConnectError("x"))

    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    assets = {a["host"]: a for a in output.artifacts["surface_map"]["assets"]}
    assert {"www." + APEX, "dev." + APEX} <= set(assets)
    assert assets["dev." + APEX]["source"] == "certspotter"       # solo la segunda lo vio
    assert assets["www." + APEX]["source"] == "crt.sh, certspotter"  # ambas
    assert output.artifacts["surface_map"]["discovery_complete"] is True


@respx.mock
async def test_a_complete_discovery_is_marked_as_such(fake_dns):
    _mock_web()
    output = await AssetInventoryModule().run(_params(fake_dns(_zone())))

    assert output.artifacts["surface_map"]["discovery_complete"] is True
    assert not any(f["id"].startswith("asset_discovery_incomplete") for f in output.findings)


@respx.mock
async def test_unresolvable_asset_is_inventoried_but_not_probed(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(return_value=_crtsh("gone." + APEX))
    _mock_certspotter()
    web = respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, text="ok")
    )

    resolver = fake_dns({(APEX, "A"): ("203.0.113.10",)}, nxdomains=("gone." + APEX,))
    output = await AssetInventoryModule().run(_params(resolver))

    assets = {a["host"]: a for a in output.artifacts["surface_map"]["assets"]}
    assert assets["gone." + APEX]["resolves"] is False
    assert assets["gone." + APEX]["reachable"] is False
    assert all("gone." not in str(call.request.url) for call in web.calls)


@respx.mock
async def test_falls_back_to_http_and_reports_missing_https(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(return_value=_crtsh())
    _mock_certspotter()
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(side_effect=httpx.ConnectError("sin tls"))
    respx.get(url__regex=r"http://[^/]*idata\.test/").mock(return_value=httpx.Response(200, text="ok"))

    output = await AssetInventoryModule().run(_params(fake_dns({(APEX, "A"): ("203.0.113.10",)})))

    assert any(f["id"].startswith("asset_without_https") for f in output.findings)


@respx.mock
async def test_detects_cdn_and_takeover_risk(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(return_value=_crtsh("old." + APEX))
    _mock_certspotter()
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, headers={"CF-RAY": "abc"}, text="ok")
    )
    respx.get(url__regex=r"http://[^/]*idata\.test/").mock(side_effect=httpx.ConnectError("x"))

    zone = {
        (APEX, "A"): ("203.0.113.10",),
        ("old." + APEX, "CNAME"): ("dead.herokuapp.com.",),
    }
    output = await AssetInventoryModule().run(_params(fake_dns(zone, nxdomains=())))

    surface = output.artifacts["surface_map"]
    assert "Cloudflare" in surface["provider_index"]["cdn"]
    assert surface["exposure_summary"]["takeover_risk"] == ["old." + APEX]
    assert any(f["id"].startswith("subdomain_takeover_risk") for f in output.findings)


# -- modo auditoría y scope ------------------------------------------------


@respx.mock
async def test_client_assets_are_included_only_when_authorized(fake_dns):
    _mock_web()
    authorization = AuthorizationRequest(
        target=f"https://{APEX}",
        allowed_domains=(APEX,),
        authorized_by="Alguien, CISO",
        contract_reference="OC-1",
        confirmed=True,
        additional_assets=("intranet." + APEX,),
    )
    zone = _zone({("intranet." + APEX, "A"): ("203.0.113.30",)})

    authorized = await AssetInventoryModule().run(
        _params(fake_dns(zone), mode="audit", authorized=True, authorization=authorization)
    )
    passive = await AssetInventoryModule().run(
        _params(fake_dns(zone), mode="passive", authorized=False, authorization=authorization)
    )

    assert "intranet." + APEX in {a["host"] for a in authorized.artifacts["surface_map"]["assets"]}
    assert "intranet." + APEX not in {a["host"] for a in passive.artifacts["surface_map"]["assets"]}


@respx.mock
async def test_client_assets_outside_scope_are_rejected(fake_dns):
    _mock_web()
    authorization = AuthorizationRequest(
        target=f"https://{APEX}",
        allowed_domains=(APEX,),
        authorized_by="Alguien, CISO",
        contract_reference="OC-1",
        confirmed=True,
        additional_assets=("banco.ajeno.test",),
    )
    output = await AssetInventoryModule().run(
        _params(fake_dns(_zone()), mode="audit", authorized=True, authorization=authorization)
    )

    hosts = {a["host"] for a in output.artifacts["surface_map"]["assets"]}
    assert "banco.ajeno.test" not in hosts
    assert not respx.calls.__len__() or all(
        "ajeno" not in str(c.request.url) for c in respx.calls
    )


# -- robustez --------------------------------------------------------------


@respx.mock
async def test_a_crashing_asset_does_not_break_the_inventory(fake_dns, monkeypatch):
    _mock_web()
    module = AssetInventoryModule()
    original = module._profile

    async def _explode(ctx, host, source):
        if host.startswith("dev."):
            raise RuntimeError("boom")
        return await original(ctx, host, source)

    monkeypatch.setattr(module, "_profile", _explode)
    output = await module.run(_params(fake_dns(_zone())))

    hosts = {a["host"] for a in output.artifacts["surface_map"]["assets"]}
    assert "dev." + APEX in hosts  # sigue inventariado, con perfil vacío
    assert output.findings


@respx.mock
async def test_max_assets_caps_the_inventory(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=_crtsh(*[f"a{i}.{APEX}" for i in range(30)])
    )
    respx.get(url__regex=r"https?://[^/]*idata\.test/").mock(return_value=httpx.Response(200, text="ok"))

    output = await AssetInventoryModule(max_assets=5).run(_params(fake_dns(_zone())))
    assert len(output.artifacts["surface_map"]["assets"]) == 5


@respx.mock
async def test_binary_content_type_does_not_break_profiling(fake_dns):
    respx.get(url__startswith="https://crt.sh/").mock(return_value=_crtsh())
    _mock_certspotter()
    respx.get(url__regex=r"https://[^/]*idata\.test/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "image/png"}, content=b"\x89PNG\x00")
    )
    output = await AssetInventoryModule().run(_params(fake_dns({(APEX, "A"): ("203.0.113.10",)})))
    asset = output.artifacts["surface_map"]["assets"][0]
    assert asset["reachable"] is True
    assert asset["title"] is None


# -- correlación -----------------------------------------------------------


def test_build_surface_map_indexes_and_counts():
    from idata_sentinel.checks.cloud_waf import CloudProfile
    from idata_sentinel.checks.tech_fingerprint import Detection
    from idata_sentinel.core.dns_resolver import DnsRecords

    profiles = [
        AssetProfile(
            host="www.idata.test",
            dns=DnsRecords(host="www.idata.test", records={"A": ("1.1.1.1",)}),
            reachable=True, scheme="https", status_code=200,
            technologies=(Detection(product="Nginx", version="1.18.0"),),
            cloud=CloudProfile(cdn=("Cloudflare",)),
        ),
        AssetProfile(
            host="dev.idata.test",
            dns=DnsRecords(host="dev.idata.test", records={"A": ("1.1.1.1",)}),
            reachable=True, scheme="http", status_code=200,
            technologies=(Detection(product="Nginx", version="1.18.0"),),
        ),
    ]
    surface = build_surface_map(profiles, apex="idata.test")

    assert surface["totals"] == {
        "discovered": 2, "resolving": 2, "reachable": 2,
        "https": 1, "distinct_ips": 1, "distinct_technologies": 1,
    }
    assert surface["technology_index"]["Nginx 1.18.0"] == ["www.idata.test", "dev.idata.test"]
    assert surface["ip_index"]["1.1.1.1"] == ["www.idata.test", "dev.idata.test"]
    assert surface["exposure_summary"]["without_https"] == ["dev.idata.test"]
    assert surface["exposure_summary"]["non_production"] == ["dev.idata.test"]
    assert surface["exposure_summary"]["without_cdn_or_waf"] == ["dev.idata.test"]


def test_build_surface_map_handles_empty_inventory():
    surface = build_surface_map([], apex="idata.test")
    assert surface["totals"]["discovered"] == 0
    assert surface["assets"] == []
