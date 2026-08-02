"""Feed de CVE desde OSV (Tier 1.1). El escaneo sigue offline; esto es la
herramienta de sync. OSV se mockea: no se toca la red en los tests."""
from __future__ import annotations

import yaml

from idata_sentinel.core.cve_feed import osv_vuln_to_hint, sync_cve_hints, wpvuln_to_hint

# Vuln real de wpvulnerability.net (forma abreviada): CF7 afectado hasta < 5.8.4.
_WPVULN_CF7 = {
    "name": "Contact Form 7 < 5.8.4",
    "operator": {"min_version": None, "max_version": "5.8.4", "max_operator": "lt"},
    "source": [{"id": "CVE-2023-6449", "name": "..."},
               {"id": "wpscan-uuid", "name": "..."}],
    "impact": {"cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H"}},
}

# Vuln de OSV abreviada (forma real: id/aliases/affected.ranges.events/severity).
_OSV_JQUERY = {
    "id": "GHSA-jquery-xss",
    "aliases": ["CVE-2020-11022"],
    "summary": "Cross-site scripting en jQuery antes de 3.5.0",
    "database_specific": {"severity": "MEDIUM"},
    "affected": [{"ranges": [{"type": "SEMVER", "events": [
        {"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}]}],
}


def test_osv_vuln_to_hint_maps_range_and_prefers_cve():
    hint = osv_vuln_to_hint("jquery", _OSV_JQUERY)
    assert hint["product"] == "jquery"
    assert (hint["min_version"], hint["max_version"]) == ("1.2.0", "3.5.0")
    assert hint["cve_ids"][0] == "CVE-2020-11022"   # CVE al frente, GHSA de respaldo
    assert hint["source"] == "osv"
    assert hint["cvss_severity"] == "medium"


def test_osv_vuln_without_usable_range_is_skipped():
    assert osv_vuln_to_hint("x", {"id": "CVE-1", "affected": []}) is None
    assert osv_vuln_to_hint("x", {"affected": [{"ranges": [{"type": "SEMVER",
        "events": [{"introduced": "0"}]}]}]}) is None  # sin 'fixed'


def test_wpvuln_to_hint_keeps_only_real_cves_and_maps_range():
    hint = wpvuln_to_hint("contact-form-7", _WPVULN_CF7)
    assert hint["product"] == "contact-form-7"
    assert (hint["min_version"], hint["max_version"]) == ("0", "5.8.4")
    assert hint["cve_ids"] == ["CVE-2023-6449"]  # solo CVE real; se descarta el uuid wpscan
    assert hint["source"] == "wpvulnerability"
    assert hint["cvss_severity"] == "high"       # C:H/I:H en el vector


def test_wpvuln_without_cve_is_skipped():
    assert wpvuln_to_hint("x", {"operator": {"max_version": "1.0"}, "source": [
        {"id": "some-wpscan-uuid"}]}) is None


async def _fake_fetch(ecosystem, package):
    return [_OSV_JQUERY] if package == "jquery" else []


async def _fake_wpvuln(kind, slug):
    return [_WPVULN_CF7] if slug == "contact-form-7" else []


async def test_sync_preserves_manual_entries_and_refreshes_feed(tmp_path):
    path = tmp_path / "cve_hints.yaml"
    # Estado previo: una entrada manual + una vieja del feed que debe refrescarse.
    path.write_text(yaml.safe_dump([
        {"product": "WordPress", "min_version": "0", "max_version": "6.4.2",
         "cve_ids": ["CVE-MANUAL"], "title": "manual", "cvss_severity": "high"},
        {"product": "jquery", "min_version": "0", "max_version": "1.0.0",
         "cve_ids": ["CVE-VIEJA"], "title": "vieja", "cvss_severity": "low", "source": "osv"},
    ]), encoding="utf-8")

    result = await sync_cve_hints(
        path=path, products=(("jquery", "npm", "jquery"),), fetch=_fake_fetch,
        wp_products=(("contact-form-7", "plugin"),), wpvuln_fetch=_fake_wpvuln)

    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    products = {e["product"] for e in entries}
    manual = [e for e in entries if e.get("source") not in ("osv", "wpvulnerability")]
    feed = [e for e in entries if e.get("source") in ("osv", "wpvulnerability")]

    # La manual se conserva; la vieja del feed se reemplazó por la fresca.
    assert any(e["cve_ids"] == ["CVE-MANUAL"] for e in manual)
    assert all(e["cve_ids"] != ["CVE-VIEJA"] for e in feed)
    assert any("CVE-2020-11022" in e["cve_ids"] for e in feed)   # npm vía OSV
    assert any("CVE-2023-6449" in e["cve_ids"] for e in feed)    # WordPress vía wpvulnerability
    assert result.entries_preserved == 1 and result.entries_from_feed == 2
    assert {"WordPress", "jquery", "contact-form-7"} <= products


async def test_sync_survives_a_failing_source(tmp_path):
    path = tmp_path / "cve_hints.yaml"

    async def _boom(ecosystem, package):
        raise RuntimeError("OSV caído")

    result = await sync_cve_hints(
        path=path, products=(("jquery", "npm", "jquery"),), fetch=_boom, wp_products=())
    assert result.products_failed == ["jquery"]
    assert result.entries_from_feed == 0
