from __future__ import annotations

from idata_sentinel.checks.cloud_waf import detect_providers, leaked_origin


def test_detects_cdn_by_header():
    profile = detect_providers({"CF-RAY": "abc123"})
    assert profile.cdn == ("Cloudflare",)
    assert not profile.is_empty


def test_detects_provider_by_server_header():
    assert "Fastly" in detect_providers({"Server": "Varnish/Fastly"}).cdn


def test_detects_waf_by_cookie():
    profile = detect_providers({}, set_cookies=("incap_ses_123=abc; Path=/",))
    assert profile.waf == ("Imperva",)


def test_detects_cloud_by_cname():
    profile = detect_providers({}, cnames=("app.eu.herokuapp.com.",))
    assert profile.cloud == ("Heroku",)


def test_detects_several_providers_at_once():
    profile = detect_providers(
        {"CF-RAY": "x", "X-Amz-Cf-Id": "y"},
        set_cookies=("__cf_bm=z; Path=/",),
    )
    assert set(profile.cdn) == {"Cloudflare", "Amazon CloudFront"}
    assert profile.waf == ("Cloudflare WAF",)


def test_no_signals_yields_empty_profile():
    profile = detect_providers({"Server": "nginx"})
    assert profile.is_empty
    assert profile.to_dict() == {"cdn": [], "waf": [], "cloud": []}


def test_header_matching_is_case_insensitive():
    assert detect_providers({"cf-ray": "x"}).cdn == detect_providers({"CF-Ray": "x"}).cdn


def test_evidence_explains_each_match():
    profile = detect_providers({"CF-RAY": "x"})
    assert profile.evidence == ("Cloudflare: header cf-ray",)


def test_leaked_origin_detects_private_ip():
    assert leaked_origin({"X-Real-IP": "10.1.2.3"}) == "x-real-ip: 10.1.2.3"
    assert leaked_origin({"X-Backend-Server": "172.16.0.9"}) is not None


def test_leaked_origin_ignores_public_ips_and_absent_headers():
    assert leaked_origin({"X-Real-IP": "8.8.8.8"}) is None
    assert leaked_origin({}) is None
    assert leaked_origin(None) is None
