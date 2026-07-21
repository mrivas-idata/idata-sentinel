from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from idata_sentinel.checks.tls_ssl import TlsCollection, evaluate_tls


def _make_cert(not_before: datetime, not_after: datetime, cn: str = "example.test") -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )


def test_healthy_tls_produces_pass():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300))
    collection = TlsCollection(
        protocol="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        certificate=cert, chain_trusted=True, hostname_matches=True, supports_legacy_protocol=False,
    )
    findings = evaluate_tls(collection, "example.test")
    assert {f["sub_id"] for f in findings} == {"tls_ok"}


def test_legacy_protocol_flagged():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300))
    collection = TlsCollection(
        protocol="TLSv1.2", cipher_name="ECDHE-RSA-AES128-GCM-SHA256", cipher_bits=128,
        certificate=cert, chain_trusted=True, hostname_matches=True, supports_legacy_protocol=True,
    )
    findings = evaluate_tls(collection, "example.test")
    ids = {f["sub_id"] for f in findings}
    assert "tls_legacy_protocol" in ids
    assert "tls_ok" not in ids


def test_weak_cipher_flagged():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300))
    collection = TlsCollection(
        protocol="TLSv1.2", cipher_name="RC4-SHA", cipher_bits=128,
        certificate=cert, chain_trusted=True, hostname_matches=True,
    )
    findings = evaluate_tls(collection, "example.test")
    assert "tls_weak_cipher" in {f["sub_id"] for f in findings}


def test_weak_bits_flagged_even_with_strong_name():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300))
    collection = TlsCollection(
        protocol="TLSv1.2", cipher_name="SOME-CIPHER", cipher_bits=64,
        certificate=cert, chain_trusted=True, hostname_matches=True,
    )
    findings = evaluate_tls(collection, "example.test")
    assert "tls_weak_cipher" in {f["sub_id"] for f in findings}


def test_expired_certificate_is_critical():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=400), now - timedelta(days=10))
    collection = TlsCollection(protocol="TLSv1.2", certificate=cert, chain_trusted=True, hostname_matches=True)
    findings = evaluate_tls(collection, "example.test")
    expired = next(f for f in findings if f["sub_id"] == "cert_expired")
    assert expired["severity"] == "critical"
    assert expired["status"] == "fail"


def test_certificate_expiring_soon_is_warning():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=300), now + timedelta(days=10))
    collection = TlsCollection(protocol="TLSv1.2", certificate=cert, chain_trusted=True, hostname_matches=True)
    findings = evaluate_tls(collection, "example.test")
    expiring = next(f for f in findings if f["sub_id"] == "cert_expiring_soon")
    assert expiring["status"] == "warning"


def test_untrusted_chain_flagged():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300))
    collection = TlsCollection(protocol="TLSv1.3", certificate=cert, chain_trusted=False, hostname_matches=True)
    findings = evaluate_tls(collection, "example.test")
    assert "cert_chain_untrusted" in {f["sub_id"] for f in findings}


def test_hostname_mismatch_flagged():
    now = datetime.now(timezone.utc)
    cert = _make_cert(now - timedelta(days=30), now + timedelta(days=300), cn="other.test")
    collection = TlsCollection(protocol="TLSv1.3", certificate=cert, chain_trusted=True, hostname_matches=False)
    findings = evaluate_tls(collection, "example.test")
    assert "cert_hostname_mismatch" in {f["sub_id"] for f in findings}


def test_no_certificate_returns_empty():
    collection = TlsCollection(connect_error="Connection refused")
    assert evaluate_tls(collection, "example.test") == []
