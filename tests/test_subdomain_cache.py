"""Caché de subdominios entre corridas: robustez ante archivos ausentes/corruptos."""
from __future__ import annotations

from idata_sentinel.core.subdomain_cache import SubdomainCache


def test_missing_file_yields_empty(tmp_path):
    cache = SubdomainCache(tmp_path / "no-existe.json")
    assert cache.known("idata.test") == set()


def test_corrupt_file_is_ignored(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{ esto no es json", encoding="utf-8")
    cache = SubdomainCache(path)
    assert cache.known("idata.test") == set()  # no revienta


def test_update_merges_and_persists(tmp_path):
    cache = SubdomainCache(tmp_path / "cache.json")
    cache.update("idata.test", {"dev.idata.test"})
    cache.update("idata.test", {"mail.idata.test", "dev.idata.test"})
    assert cache.known("idata.test") == {"dev.idata.test", "mail.idata.test"}


def test_update_is_case_insensitive_on_apex_and_ignores_empty(tmp_path):
    cache = SubdomainCache(tmp_path / "cache.json")
    cache.update("IDATA.test", {"Dev.idata.test", ""})
    assert cache.known("idata.test") == {"dev.idata.test"}
    cache.update("idata.test", set())  # nada que agregar: no falla
    assert cache.known("idata.test") == {"dev.idata.test"}


def test_separate_apexes_do_not_mix(tmp_path):
    cache = SubdomainCache(tmp_path / "cache.json")
    cache.update("idata.test", {"a.idata.test"})
    cache.update("otro.cl", {"b.otro.cl"})
    assert cache.known("idata.test") == {"a.idata.test"}
    assert cache.known("otro.cl") == {"b.otro.cl"}
