from __future__ import annotations

import pytest

from idata_sentinel.checks.asset_exposure import AssetExposureCheck, SubdomainTakeoverCheck
from idata_sentinel.checks.takeover import TakeoverSignal
from idata_sentinel.checks.tech_fingerprint import Detection
from idata_sentinel.modules.asset_inventory.context import AssetProfile, is_non_production
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


def _reachable(host="www.idata.test", **kwargs) -> AssetProfile:
    defaults = dict(reachable=True, scheme="https", status_code=200)
    return AssetProfile(host=host, **{**defaults, **kwargs})


# -- heurística de entorno no productivo -----------------------------------


@pytest.mark.parametrize("host", ["dev.idata.test", "staging-api.idata.test", "api_test.idata.test"])
def test_non_production_markers_detected(host):
    assert is_non_production(host) is not None


@pytest.mark.parametrize("host", ["developers.idata.test", "protest.idata.test", "www.idata.test"])
def test_non_production_avoids_substring_false_positives(host):
    assert is_non_production(host) is None


# -- AssetExposureCheck ----------------------------------------------------


def test_unreachable_asset_produces_no_findings():
    assert AssetExposureCheck().evaluate(AssetProfile(host="dev.idata.test")) == []


def test_non_production_asset_exposed():
    results = AssetExposureCheck().evaluate(_reachable("staging.idata.test", title="Panel"))
    finding = next(r for r in results if r.id.startswith("non_production_asset_exposed"))
    assert finding.severity == "medium"
    assert finding.status == "fail"
    assert "staging" in finding.evidence or "Panel" in finding.evidence


def test_asset_without_https_is_high_severity():
    results = AssetExposureCheck().evaluate(_reachable(scheme="http"))
    finding = next(r for r in results if r.id.startswith("asset_without_https"))
    assert (finding.severity, finding.likelihood) == ("high", "high")


def test_https_asset_has_no_transport_finding():
    assert "asset_without_https" not in _ids(AssetExposureCheck().evaluate(_reachable()))


def test_version_disclosure_reported_only_when_version_is_known():
    with_version = _reachable(technologies=(Detection(product="Nginx", version="1.18.0"),))
    without_version = _reachable(technologies=(Detection(product="Nginx", version=None),))

    assert "asset_tech_version_disclosure" in _ids(AssetExposureCheck().evaluate(with_version))
    assert "asset_tech_version_disclosure" not in _ids(AssetExposureCheck().evaluate(without_version))


def test_origin_leak_reported():
    results = AssetExposureCheck().evaluate(_reachable(origin_leak="x-real-ip: 10.0.0.1"))
    finding = next(r for r in results if r.id.startswith("origin_ip_leak"))
    assert finding.status == "warning"


def test_clean_asset_produces_nothing():
    assert AssetExposureCheck().evaluate(_reachable()) == []


# -- SubdomainTakeoverCheck ------------------------------------------------


def test_takeover_check_is_silent_without_signal():
    assert SubdomainTakeoverCheck().evaluate(_reachable()) == []


def test_takeover_finding_is_high_severity_and_names_the_service():
    profile = _reachable(
        "old.idata.test",
        takeover=TakeoverSignal(service="Heroku", cname="app.herokuapp.com", reason="nxdomain"),
    )
    finding = SubdomainTakeoverCheck().evaluate(profile)[0]
    assert finding.severity == "high"
    assert finding.status == "fail"
    assert "Heroku" in finding.finding
    assert "NXDOMAIN" in finding.finding


def test_takeover_recommendation_never_suggests_claiming_someone_elses_resource():
    profile = _reachable(
        takeover=TakeoverSignal(service="Amazon S3", cname="b.s3.amazonaws.com", reason="unclaimed_page")
    )
    finding = SubdomainTakeoverCheck().evaluate(profile)[0]
    assert "Eliminar el registro CNAME" in finding.recommendation


# -- contrato --------------------------------------------------------------


def test_asset_findings_conform_to_contract():
    profile = _reachable(
        "dev.idata.test",
        scheme="http",
        technologies=(Detection(product="WordPress", version="6.1"),),
        origin_leak="x-real-ip: 10.0.0.1",
        takeover=TakeoverSignal(service="Heroku", cname="a.herokuapp.com", reason="nxdomain"),
    )
    results = SubdomainTakeoverCheck().evaluate(profile) + AssetExposureCheck().evaluate(profile)
    assert len(results) == 5
    for r in results:
        assert r.module == "asset_inventory"
        assert set(r.to_dict()) == FINDING_CONTRACT_KEYS


async def test_asset_checks_reject_the_run_contract():
    for check in (AssetExposureCheck(), SubdomainTakeoverCheck()):
        with pytest.raises(NotImplementedError):
            await check.run(None)
