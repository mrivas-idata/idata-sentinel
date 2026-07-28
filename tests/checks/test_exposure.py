from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.exposure import ExposureCheck
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

ROOT = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


def _mock(root_body: str = "<html></html>", *, env=None, git=None) -> None:
    respx.get(ROOT).mock(return_value=httpx.Response(200, text=root_body))
    respx.get("https://example.test/.env").mock(
        return_value=httpx.Response(200, text=env) if env is not None else httpx.Response(404)
    )
    respx.get("https://example.test/.git/HEAD").mock(
        return_value=httpx.Response(200, text=git) if git is not None else httpx.Response(404)
    )


# -- archivos sensibles: el falso positivo del SPA -------------------------


@respx.mock
async def test_spa_serving_index_html_for_dot_env_is_not_a_finding(make_ctx):
    """Un catch-all que devuelve el index.html a /.env NO es una fuga.
    Regresión de un falso positivo visto en un escaneo real de un sitio SPA."""
    _mock(env='<!DOCTYPE html>\n<html lang="es-CL"><head><script>gtm</script></head></html>')
    assert "sensitive_file_exposed_.env" not in _ids(await ExposureCheck().run(make_ctx()))


@respx.mock
async def test_a_real_dot_env_is_reported_as_medium(make_ctx):
    _mock(env="DB_PASSWORD=super-secreto\nAPI_KEY=abc123\n")
    results = await ExposureCheck().run(make_ctx())

    finding = next(r for r in results if r.id.startswith("sensitive_file_exposed_.env"))
    assert finding.severity == "medium"
    assert finding.status == "fail"


@respx.mock
async def test_a_real_git_head_is_reported(make_ctx):
    _mock(git="ref: refs/heads/main\n")
    assert "sensitive_file_exposed_.git_HEAD" in _ids(await ExposureCheck().run(make_ctx()))


@respx.mock
async def test_git_head_with_a_raw_commit_hash_is_reported(make_ctx):
    _mock(git="a" * 40 + "\n")
    assert "sensitive_file_exposed_.git_HEAD" in _ids(await ExposureCheck().run(make_ctx()))


@respx.mock
async def test_empty_or_missing_files_are_not_reported(make_ctx):
    _mock(env="", git=None)
    assert not {i for i in _ids(await ExposureCheck().run(make_ctx())) if i.startswith("sensitive_file")}


@respx.mock
async def test_env_shaped_html_comment_does_not_trigger(make_ctx):
    """Contenido HTML que casualmente contiene 'X=...' no debe reportarse."""
    _mock(env="<html><body>CONFIG=algo dentro de la página</body></html>")
    assert "sensitive_file_exposed_.env" not in _ids(await ExposureCheck().run(make_ctx()))


# -- errores verbosos ------------------------------------------------------


@respx.mock
async def test_stack_trace_in_body_is_flagged(make_ctx):
    _mock("Traceback (most recent call last): File x line 3")
    finding = next(
        r for r in await ExposureCheck().run(make_ctx()) if r.id.startswith("verbose_error_exposed")
    )
    assert finding.severity == "medium"


@respx.mock
async def test_sql_error_signature_is_flagged(make_ctx):
    _mock("Error: SQLSTATE[42000] syntax error near")
    assert "verbose_error_exposed" in _ids(await ExposureCheck().run(make_ctx()))


@respx.mock
async def test_clean_page_has_no_verbose_error(make_ctx):
    _mock("<html><body>Bienvenido</body></html>")
    assert "verbose_error_exposed" not in _ids(await ExposureCheck().run(make_ctx()))


# -- metadatos -------------------------------------------------------------


@respx.mock
async def test_meta_generator_with_version_is_flagged(make_ctx):
    _mock('<meta name="generator" content="WordPress 6.4.2">')
    finding = next(
        r for r in await ExposureCheck().run(make_ctx()) if r.id.startswith("metadata_exposed_generator")
    )
    assert finding.status == "warning"


@respx.mock
async def test_debug_header_is_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(200, headers={"X-Debug": "on"}, text="<html></html>"))
    respx.get("https://example.test/.env").mock(return_value=httpx.Response(404))
    respx.get("https://example.test/.git/HEAD").mock(return_value=httpx.Response(404))
    assert "metadata_exposed_xdebug" in _ids(await ExposureCheck().run(make_ctx()))


# -- formularios inseguros -------------------------------------------------


@respx.mock
async def test_form_posting_over_http_is_high(make_ctx):
    _mock('<form action="http://example.test/login"><input name="pass"></form>')
    finding = next(
        r for r in await ExposureCheck().run(make_ctx()) if r.id.startswith("form_insecure_transport")
    )
    assert (finding.severity, finding.likelihood) == ("high", "high")


@respx.mock
async def test_https_form_is_not_flagged(make_ctx):
    _mock('<form action="/login"><input name="pass"></form>')
    assert "form_insecure_transport" not in _ids(await ExposureCheck().run(make_ctx()))


# -- robustez --------------------------------------------------------------


@respx.mock
async def test_unreachable_target_produces_nothing(make_ctx):
    respx.get(ROOT).mock(side_effect=httpx.ConnectError("caído"))
    respx.get("https://example.test/.env").mock(side_effect=httpx.ConnectError("caído"))
    respx.get("https://example.test/.git/HEAD").mock(side_effect=httpx.ConnectError("caído"))
    assert await ExposureCheck().run(make_ctx()) == []


@respx.mock
async def test_all_findings_conform_to_contract(make_ctx):
    _mock('<form action="http://x/l"><input name=p></form>', env="SECRET=1\n")
    results = await ExposureCheck().run(make_ctx())
    assert results
    for r in results:
        assert set(r.to_dict()) == FINDING_CONTRACT_KEYS
