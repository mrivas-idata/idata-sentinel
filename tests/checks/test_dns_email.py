from __future__ import annotations

import pytest

from idata_sentinel.checks.dns_email import (
    DnsEmailCheck,
    count_spf_lookups,
    dmarc_addresses,
    dmarc_policy,
    dmarc_rua_default_provider,
    find_dmarc,
    find_spf,
    spf_qualifier,
)
from idata_sentinel.core.dns_resolver import DnsRecords
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

HOST = "idata.test"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


async def _evaluate(zone, fake_dns, *, records=None):
    resolver = fake_dns(zone)
    records = records if records is not None else await resolver.records_for(HOST)
    return await DnsEmailCheck().evaluate(HOST, records, resolver)


# -- funciones puras -------------------------------------------------------


def test_find_spf_ignores_unrelated_txt():
    assert find_spf(('google-site-verification=abc', 'v=spf1 -all')) == "v=spf1 -all"
    assert find_spf(("no-spf-here",)) is None


@pytest.mark.parametrize(
    "spf,expected",
    [("v=spf1 -all", "-"), ("v=spf1 ~all", "~"), ("v=spf1 ?all", "?"), ("v=spf1 +all", "+"), ("v=spf1", "")],
)
def test_spf_qualifier(spf, expected):
    assert spf_qualifier(spf) == expected


def test_count_spf_lookups_counts_resolving_mechanisms():
    spf = "v=spf1 include:a.cl include:b.cl a mx redirect=c.cl -all"
    assert count_spf_lookups(spf) == 5


def test_dmarc_policy_defaults_to_none_when_absent():
    assert dmarc_policy("v=DMARC1; p=reject") == "reject"
    assert dmarc_policy("v=DMARC1;") == "none"
    assert find_dmarc(("v=DMARC1; p=none",)) == "v=DMARC1; p=none"


# -- SPF -------------------------------------------------------------------


async def test_spf_missing_is_more_severe_when_domain_receives_mail(fake_dns):
    with_mx = await _evaluate({(HOST, "MX"): ("10 mail.idata.test.",)}, fake_dns)
    without_mx = await _evaluate({}, fake_dns)

    spf_with = next(r for r in with_mx if r.id.startswith("spf_missing"))
    spf_without = next(r for r in without_mx if r.id.startswith("spf_missing"))
    assert spf_with.severity == "medium"
    assert spf_without.severity == "low"
    assert spf_with.status == "fail"


async def test_spf_permissive_policy_is_flagged(fake_dns):
    results = await _evaluate({(HOST, "TXT"): ("v=spf1 include:x.cl +all",)}, fake_dns)
    assert "spf_weak_policy" in _ids(results)
    assert "spf_missing" not in _ids(results)


async def test_spf_softfail_is_a_warning_not_a_fail(fake_dns):
    results = await _evaluate({(HOST, "TXT"): ("v=spf1 ~all",)}, fake_dns)
    softfail = next(r for r in results if r.id.startswith("spf_softfail"))
    assert softfail.status == "warning"
    assert softfail.severity == "low"


async def test_spf_hard_fail_produces_no_spf_finding(fake_dns):
    results = await _evaluate({(HOST, "TXT"): ("v=spf1 include:x.cl -all",)}, fake_dns)
    assert not {i for i in _ids(results) if i.startswith("spf_")}


async def test_spf_lookup_limit_exceeded(fake_dns):
    spf = "v=spf1 " + " ".join(f"include:s{i}.cl" for i in range(12)) + " -all"
    results = await _evaluate({(HOST, "TXT"): (spf,)}, fake_dns)
    assert "spf_lookup_limit" in _ids(results)


# -- DMARC -----------------------------------------------------------------


async def test_dmarc_missing(fake_dns):
    results = await _evaluate({(HOST, "MX"): ("10 mx.idata.test.",)}, fake_dns)
    dmarc = next(r for r in results if r.id.startswith("dmarc_missing"))
    assert dmarc.severity == "medium"


async def test_dmarc_policy_none_and_missing_rua(fake_dns):
    results = await _evaluate({(f"_dmarc.{HOST}", "TXT"): ("v=DMARC1; p=none",)}, fake_dns)
    ids = _ids(results)
    assert "dmarc_policy_none" in ids
    assert "dmarc_no_reporting" in ids
    assert "dmarc_missing" not in ids


async def test_dmarc_reject_with_rua_is_clean(fake_dns):
    results = await _evaluate(
        {(f"_dmarc.{HOST}", "TXT"): ("v=DMARC1; p=reject; rua=mailto:d@idata.test",)}, fake_dns
    )
    assert not {i for i in _ids(results) if i.startswith("dmarc_")}


# -- rua a buzón por defecto del proveedor ---------------------------------


def test_dmarc_addresses_parses_the_rua_tag():
    dmarc = "v=DMARC1; p=quarantine; rua=mailto:a@x.com!10m,mailto:b@y.com; ruf=mailto:f@z.com"
    assert dmarc_addresses(dmarc, "rua") == ["a@x.com", "b@y.com"]
    assert dmarc_addresses(dmarc, "ruf") == ["f@z.com"]
    assert dmarc_addresses("v=DMARC1; p=none") == []


def test_dmarc_rua_default_provider_recognises_godaddy():
    dmarc = "v=DMARC1; p=quarantine; rua=mailto:dmarc_rua@onsecureserver.net"
    assert dmarc_rua_default_provider(dmarc) == ("dmarc_rua@onsecureserver.net", "GoDaddy")


def test_dmarc_rua_to_own_mailbox_is_not_a_provider_default():
    assert dmarc_rua_default_provider("v=DMARC1; p=reject; rua=mailto:dmarc@idata.test") is None


def test_dmarc_rua_to_a_dmarc_saas_is_not_flagged():
    """Un `rua` externo hacia una plataforma de análisis contratada por el titular
    es legítimo: sólo se marcan los buzones *por defecto* del proveedor."""
    assert dmarc_rua_default_provider("v=DMARC1; p=reject; rua=mailto:x@dmarcian.com") is None


async def test_dmarc_rua_default_provider_is_flagged(fake_dns):
    """Regresión del hallazgo real: p=quarantine pero rua al buzón por defecto de
    GoDaddy — la política está activa pero el titular no ve los reportes."""
    results = await _evaluate(
        {(f"_dmarc.{HOST}", "TXT"): (
            "v=DMARC1; p=quarantine; rua=mailto:dmarc_rua@onsecureserver.net",
        )},
        fake_dns,
    )
    ids = _ids(results)
    finding = next(r for r in results if r.id.startswith("dmarc_rua_default_provider"))
    assert finding.status == "warning"
    assert "GoDaddy" in finding.title
    # No debe además decir que falta rua: el rua existe, sólo apunta al lugar equivocado.
    assert "dmarc_no_reporting" not in ids
    # p=quarantine es endurecida: tampoco debe salir dmarc_policy_none.
    assert "dmarc_policy_none" not in ids


# -- DKIM / BIMI -----------------------------------------------------------


async def test_dkim_present_when_a_common_selector_resolves(fake_dns):
    zone = {
        (HOST, "MX"): ("10 mx.idata.test.",),
        (f"google._domainkey.{HOST}", "TXT"): ("v=DKIM1; k=rsa; p=MIGf...",),
    }
    ids = _ids(await _evaluate(zone, fake_dns))
    assert "dkim_present" in ids
    assert "dkim_not_found" not in ids


async def test_dkim_not_found_when_no_common_selector_resolves(fake_dns):
    ids = _ids(await _evaluate({(HOST, "MX"): ("10 mx.idata.test.",)}, fake_dns))
    assert "dkim_not_found" in ids


async def test_dkim_only_checked_when_domain_receives_mail(fake_dns):
    ids = _ids(await _evaluate({}, fake_dns))  # sin MX
    assert not {i for i in ids if i.startswith("dkim")}


async def test_bimi_present(fake_dns):
    zone = {(f"default._bimi.{HOST}", "TXT"): ("v=BIMI1; l=https://idata.test/logo.svg",)}
    assert "bimi_present" in _ids(await _evaluate(zone, fake_dns))


async def test_bimi_missing_is_informational(fake_dns):
    result = next(r for r in await _evaluate({}, fake_dns) if r.id.startswith("bimi_missing"))
    assert result.severity == "info" and result.status == "info"


# -- MTA-STS / TLS-RPT -----------------------------------------------------


async def test_transport_checks_only_run_when_domain_receives_mail(fake_dns):
    without_mx = _ids(await _evaluate({}, fake_dns))
    with_mx = _ids(await _evaluate({(HOST, "MX"): ("10 mx.idata.test.",)}, fake_dns))

    assert "mta_sts_missing" not in without_mx
    assert {"mta_sts_missing", "tls_rpt_missing"} <= with_mx


async def test_mta_sts_and_tls_rpt_present(fake_dns):
    zone = {
        (HOST, "MX"): ("10 mx.idata.test.",),
        (f"_mta-sts.{HOST}", "TXT"): ("v=STSv1; id=2026",),
        (f"_smtp._tls.{HOST}", "TXT"): ("v=TLSRPTv1; rua=mailto:t@idata.test",),
    }
    ids = _ids(await _evaluate(zone, fake_dns))
    assert "mta_sts_missing" not in ids
    assert "tls_rpt_missing" not in ids


# -- CAA / DNSSEC ----------------------------------------------------------


async def test_caa_and_dnssec_missing_are_reported(fake_dns):
    ids = _ids(await _evaluate({}, fake_dns))
    assert {"caa_missing", "dnssec_missing"} <= ids


async def test_caa_and_dnssec_present_are_silent(fake_dns):
    zone = {
        (HOST, "CAA"): ('0 issue "letsencrypt.org"',),
        (HOST, "DNSKEY"): ("257 3 13 abc",),
    }
    ids = _ids(await _evaluate(zone, fake_dns))
    assert "caa_missing" not in ids
    assert "dnssec_missing" not in ids


# -- contrato y robustez ---------------------------------------------------


async def test_all_results_conform_to_contract(fake_dns):
    results = await _evaluate({(HOST, "MX"): ("10 mx.idata.test.",)}, fake_dns)
    assert results
    for r in results:
        assert r.module == "asset_inventory"
        assert set(r.to_dict()) == FINDING_CONTRACT_KEYS


async def test_evaluate_survives_empty_records(fake_dns):
    resolver = fake_dns({})
    results = await DnsEmailCheck().evaluate(HOST, DnsRecords(host=HOST), resolver)
    assert results  # no evaluable != crash
