from __future__ import annotations

from idata_sentinel.checks.takeover import evaluate_takeover, match_service


def test_match_service_recognises_known_saas():
    signature, cname = match_service(("bucket.s3.amazonaws.com.",))
    assert signature["service"] == "Amazon S3"
    assert cname == "bucket.s3.amazonaws.com"


def test_match_service_ignores_unknown_targets():
    assert match_service(("origin.idata.test.",)) is None


def test_nxdomain_on_known_service_is_a_takeover_signal():
    signal = evaluate_takeover(("app.herokuapp.com",), cname_resolves=False)
    assert signal is not None
    assert signal.service == "Heroku"
    assert signal.reason == "nxdomain"


def test_unclaimed_page_body_is_a_takeover_signal():
    signal = evaluate_takeover(
        ("org.github.io",),
        cname_resolves=True,
        body="<h1>There isn't a GitHub Pages site here.</h1>",
    )
    assert signal is not None
    assert signal.reason == "unclaimed_page"


def test_live_service_is_not_flagged():
    """Ambas condiciones son necesarias: un SaaS que resuelve y sirve contenido
    real no puede reportarse como riesgo."""
    assert evaluate_takeover(("org.github.io",), cname_resolves=True, body="<h1>Bienvenido</h1>") is None


def test_unknown_provider_never_flagged_even_if_dangling():
    assert evaluate_takeover(("origin.idata.test",), cname_resolves=False) is None


def test_no_cname_means_no_signal():
    assert evaluate_takeover((), cname_resolves=False) is None
