from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.privacy_signals import (
    SENSITIVE_CATEGORIES,
    ConsentTrackingCheck,
    PrivacyFormsCheck,
    PrivacyPolicyCheck,
    detect_consent_banner,
    detect_pii_categories,
    detect_trackers,
    find_privacy_policy_links,
    parse_forms,
    third_party_cookies,
)

BASE = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


# -- parseo de formularios -------------------------------------------------


def test_parse_forms_extracts_action_method_and_fields():
    html = """
    <form action="/contacto" method="POST">
      <input name="nombre" type="text">
      <input name="email" type="email">
    </form>
    """
    form = parse_forms(html, BASE)[0]
    assert form.action == "/contacto"
    assert form.absolute_action == "https://example.test/contacto"
    assert form.method == "post"
    assert form.collects_pii


def test_pii_detected_from_name_id_placeholder_and_labels():
    by_name = parse_forms('<form><input name="rut"></form>', BASE)[0]
    by_placeholder = parse_forms('<form><input placeholder="Su teléfono"></form>', BASE)[0]
    by_label = parse_forms("<form><label>Dirección</label><input name=x></form>", BASE)[0]

    assert "rut" in by_name.pii_categories
    assert "telefono" in by_placeholder.pii_categories
    assert "direccion" in by_label.pii_categories


def test_form_without_pii_is_not_flagged():
    form = parse_forms('<form action="/buscar"><input name="q" placeholder="Buscar"></form>', BASE)[0]
    assert not form.collects_pii


def test_sensitive_categories_are_identified():
    form = parse_forms('<form><input name="isapre"><input name="renta"></form>', BASE)[0]
    assert form.sensitive_categories == {"salud", "socioeconomico"}
    assert form.sensitive_categories <= SENSITIVE_CATEGORIES


def test_form_action_relative_to_page_is_resolved():
    form = parse_forms('<form action="enviar.php"><input name="email"></form>', "https://example.test/a/b")[0]
    assert form.absolute_action == "https://example.test/a/enviar.php"


def test_form_without_action_posts_to_itself():
    form = parse_forms('<form><input name="email"></form>', BASE)[0]
    assert form.absolute_action == BASE
    assert not form.is_insecure


def test_insecure_form_is_detected_by_scheme():
    form = parse_forms('<form action="http://otro.test/x"><input name="rut"></form>', BASE)[0]
    assert form.is_insecure


def test_detect_pii_categories_on_empty_input():
    assert detect_pii_categories(()) == frozenset()


# -- consentimiento y rastreadores -----------------------------------------


@pytest.mark.parametrize(
    "html",
    ['<script src="https://cdn.cookiebot.com/uc.js"></script>',
     "<div>Utilizamos cookies para mejorar su experiencia</div>",
     '<div id="onetrust-banner-sdk"></div>'],
)
def test_consent_banner_signatures(html):
    assert detect_consent_banner(html) is not None


def test_consent_banner_absent():
    assert detect_consent_banner("<html><body>Bienvenido</body></html>") is None


def test_detect_trackers_identifies_service_and_controller():
    html = '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
    hits = detect_trackers(html)
    assert hits
    assert hits[0].name == "Google Analytics"
    assert hits[0].abroad is True


def test_detect_trackers_flags_session_replay():
    hits = detect_trackers('<script src="https://static.hotjar.com/c/hotjar-1.js"></script>')
    assert [h.kind for h in hits] == ["session_replay"]


def test_detect_trackers_reports_each_service_once():
    html = ('<script src="https://www.google-analytics.com/analytics.js"></script>'
            '<script src="https://www.googletagmanager.com/gtag/js"></script>')
    assert [h.name for h in detect_trackers(html)].count("Google Analytics") == 1


def test_no_trackers_on_clean_page():
    assert detect_trackers("<html><script src='/js/app.js'></script></html>") == []


def test_third_party_cookies_detected_by_domain_attribute():
    cookies = ("_ga=1; Domain=.doubleclick.net; Path=/", "sess=2; Domain=.example.test; Path=/", "plain=3")
    assert third_party_cookies(cookies, "example.test") == ["_ga (Domain=doubleclick.net)"]


# -- enlaces a política de privacidad --------------------------------------


def test_privacy_links_found_by_href_or_text():
    html = ('<a href="/politica-de-privacidad">Legal</a>'
            '<a href="/legal/x">Política de Privacidad</a>'
            '<a href="/nosotros">Nosotros</a>')
    links = find_privacy_policy_links(html, BASE)
    assert links == ["https://example.test/politica-de-privacidad", "https://example.test/legal/x"]


def test_privacy_links_ignore_anchors_and_scripts():
    html = '<a href="#privacidad">x</a><a href="javascript:privacidad()">y</a>'
    assert find_privacy_policy_links(html, BASE) == []


def test_privacy_links_are_deduplicated():
    html = '<a href="/privacidad">A</a><a href="/privacidad">Privacidad</a>'
    assert len(find_privacy_policy_links(html, BASE)) == 1


# -- checks ----------------------------------------------------------------


@respx.mock
async def test_insecure_pii_form_is_critical(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<a href="/privacidad">Privacidad</a>'
                  '<form action="http://example.test/x"><input name="rut"></form>'))
    results = await PrivacyFormsCheck().run(make_ctx())

    finding = next(r for r in results if r.id.startswith("pii_form_insecure_transport"))
    assert finding.severity == "critical"
    assert finding.status == "fail"


@respx.mock
async def test_pii_form_without_privacy_notice(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<form action="/x"><input name="email"></form>'))
    results = await PrivacyFormsCheck().run(make_ctx())
    assert "pii_form_without_privacy_notice" in _ids(results)


@respx.mock
async def test_pii_form_with_privacy_notice_is_not_flagged(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<a href="/privacidad">Privacidad</a><form action="/x"><input name="email"></form>'))
    results = await PrivacyFormsCheck().run(make_ctx())
    assert "pii_form_without_privacy_notice" not in _ids(results)


@respx.mock
async def test_sensitive_data_form_is_flagged(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<a href="/privacidad">P</a><form action="/x"><input name="diagnostico"></form>'))
    results = await PrivacyFormsCheck().run(make_ctx())

    finding = next(r for r in results if r.id.startswith("sensitive_data_collected"))
    assert finding.severity == "high"
    assert "salud" in finding.finding


@respx.mock
async def test_forms_check_is_silent_without_pii(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<form action="/buscar"><input name="q"></form>'))
    assert await PrivacyFormsCheck().run(make_ctx()) == []


@respx.mock
async def test_forms_check_survives_unreachable_target(make_ctx):
    respx.get("https://example.test/").mock(side_effect=httpx.ConnectError("caído"))
    assert await PrivacyFormsCheck().run(make_ctx()) == []


@respx.mock
async def test_trackers_without_consent_is_high(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<script src="https://www.google-analytics.com/analytics.js"></script>'))
    results = await ConsentTrackingCheck().run(make_ctx())

    finding = next(r for r in results if r.id == "trackers_without_consent")
    assert (finding.severity, finding.status) == ("high", "fail")


@respx.mock
async def test_consent_banner_downgrades_to_informative(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<script src="https://cdn.cookiebot.com/uc.js"></script>'
                  '<script src="https://www.google-analytics.com/analytics.js"></script>'))
    ids = _ids(await ConsentTrackingCheck().run(make_ctx()))
    assert "consent_banner_present" in ids
    assert "trackers_without_consent" not in ids


@respx.mock
async def test_international_transfer_and_session_replay(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<script src="https://static.hotjar.com/c/hotjar-1.js"></script>'))
    ids = _ids(await ConsentTrackingCheck().run(make_ctx()))
    assert {"international_data_transfer", "session_replay_active"} <= ids


@respx.mock
async def test_third_party_cookie_finding(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers={"Set-Cookie": "_ga=1; Domain=.doubleclick.net"}, text="<html></html>"))
    assert "third_party_cookies_on_landing" in _ids(await ConsentTrackingCheck().run(make_ctx()))


@respx.mock
async def test_clean_page_produces_no_consent_findings(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text="<html>hola</html>"))
    assert await ConsentTrackingCheck().run(make_ctx()) == []


@respx.mock
async def test_consent_check_reports_unreachable_as_info(make_ctx):
    respx.get("https://example.test/").mock(side_effect=httpx.ConnectError("caído"))
    results = await ConsentTrackingCheck().run(make_ctx())
    assert results[0].status == "info"


@respx.mock
async def test_privacy_policy_missing_is_high(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text="<html></html>"))
    finding = (await PrivacyPolicyCheck().run(make_ctx()))[0]
    assert finding.id == "privacy_policy_missing"
    assert finding.severity == "high"


@respx.mock
async def test_privacy_policy_present_and_reachable(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<a href="/privacidad">Privacidad</a>'))
    respx.get("https://example.test/privacidad").mock(return_value=httpx.Response(200, text="Política"))

    finding = (await PrivacyPolicyCheck().run(make_ctx()))[0]
    assert finding.id == "privacy_policy_present"
    assert finding.status == "pass"


@respx.mock
async def test_privacy_policy_link_broken(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, text='<a href="/privacidad">Privacidad</a>'))
    respx.get("https://example.test/privacidad").mock(return_value=httpx.Response(404))

    finding = (await PrivacyPolicyCheck().run(make_ctx()))[0]
    assert finding.id == "privacy_policy_unreachable"
    assert finding.status == "fail"


@respx.mock
async def test_privacy_check_never_guesses_paths(make_ctx):
    """Regla anti-fuzzing: sin enlace publicado, no se prueba ninguna ruta."""
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text="<html></html>"))
    await PrivacyPolicyCheck().run(make_ctx())

    requested = {c.request.url.path for c in respx.calls}
    assert requested == {"/"}
