"""Feed de CVE desde OSV (Tier 1.1). El escaneo sigue offline; esto es la
herramienta de sync. OSV se mockea: no se toca la red en los tests."""
from __future__ import annotations

import yaml

from idata_sentinel.core.cve_feed import osv_vuln_to_hint, sync_cve_hints

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


async def _fake_fetch(ecosystem, package):
    return [_OSV_JQUERY] if package == "jquery" else []


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
        path=path, products=(("jquery", "npm", "jquery"),), fetch=_fake_fetch)

    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    products = {e["product"] for e in entries}
    manual = [e for e in entries if e.get("source") != "osv"]
    feed = [e for e in entries if e.get("source") == "osv"]

    # La manual se conserva; la vieja del feed se reemplazó por la fresca.
    assert any(e["cve_ids"] == ["CVE-MANUAL"] for e in manual)
    assert all(e["cve_ids"] != ["CVE-VIEJA"] for e in feed)
    assert any("CVE-2020-11022" in e["cve_ids"] for e in feed)
    assert result.entries_preserved == 1 and result.entries_from_feed == 1
    assert "WordPress" in products and "jquery" in products


async def test_sync_survives_a_failing_source(tmp_path):
    path = tmp_path / "cve_hints.yaml"

    async def _boom(ecosystem, package):
        raise RuntimeError("OSV caído")

    result = await sync_cve_hints(path=path, products=(("jquery", "npm", "jquery"),), fetch=_boom)
    assert result.products_failed == ["jquery"]
    assert result.entries_from_feed == 0
