from __future__ import annotations

import json

import pytest

from idata_sentinel.storage.crypto import (
    ENV_KEY,
    DecryptionError,
    FernetCipher,
    NullCipher,
    cipher_from_env,
    generate_key,
)
from idata_sentinel.storage.db import ScanStore

TARGET = "https://cliente.test"

_FINDING = {
    "id": "cert_expired", "module": "vuln_identification", "category": "TLS/SSL",
    "severity": "critical", "likelihood": "high", "status": "fail",
    "title": "Certificado expirado", "finding": "f", "business_impact": "b",
    "recommendation": "r", "evidence": "CN=cliente.test", "references": [],
}
_ARTIFACTS = {"asset_inventory": {"surface_map": {"apex": "cliente.test", "assets": []}}}


def _record(store: ScanStore):
    return store.record_scan(
        target=TARGET, mode="passive", score=55, grade="F",
        findings=[_FINDING], artifacts=_ARTIFACTS, scanned_at="2026-07-01T00:00:00+00:00",
    )


def _raw_row(store: ScanStore) -> tuple[str, int]:
    with store._connect() as conn:
        row = conn.execute("SELECT findings, encrypted FROM scans LIMIT 1").fetchone()
    return row["findings"], row["encrypted"]


# -- primitivas ------------------------------------------------------------


def test_generated_key_round_trips():
    cipher = FernetCipher(generate_key())
    assert cipher.decrypt(cipher.encrypt("secreto")) == "secreto"
    assert cipher.enabled is True


def test_ciphertext_does_not_leak_the_plaintext():
    assert "secreto" not in FernetCipher(generate_key()).encrypt("un secreto muy claro")


def test_invalid_key_is_rejected_with_a_useful_message():
    with pytest.raises(ValueError, match="keygen"):
        FernetCipher("no-es-una-clave")


def test_wrong_key_raises_decryption_error():
    ciphertext = FernetCipher(generate_key()).encrypt("secreto")
    with pytest.raises(DecryptionError, match=ENV_KEY):
        FernetCipher(generate_key()).decrypt(ciphertext)


def test_null_cipher_is_a_passthrough():
    cipher = NullCipher()
    assert cipher.enabled is False
    assert cipher.decrypt(cipher.encrypt("texto")) == "texto"


def test_cipher_from_env_prefers_the_explicit_key(monkeypatch):
    monkeypatch.setenv(ENV_KEY, generate_key())
    assert cipher_from_env("").enabled is False  # explícita vacía gana sobre el entorno
    assert cipher_from_env().enabled is True


def test_cipher_from_env_without_key(monkeypatch):
    monkeypatch.delenv(ENV_KEY, raising=False)
    assert cipher_from_env().enabled is False


# -- integración con el almacén -------------------------------------------


def test_store_without_key_writes_plaintext(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_KEY, raising=False)
    store = ScanStore(tmp_path / "claro.db")
    _record(store)

    raw, encrypted = _raw_row(store)
    assert encrypted == 0
    assert "cert_expired" in raw
    assert store.latest_scan(TARGET).encrypted is False


def test_store_with_key_encrypts_the_sensitive_blobs(tmp_path):
    store = ScanStore(tmp_path / "cifrado.db", cipher=FernetCipher(generate_key()))
    _record(store)

    raw, encrypted = _raw_row(store)
    assert encrypted == 1
    assert "cert_expired" not in raw
    assert "cliente.test" not in raw
    with pytest.raises(json.JSONDecodeError):  # el blob ya no es JSON legible
        json.loads(raw)


def test_encrypted_record_round_trips(tmp_path):
    store = ScanStore(tmp_path / "cifrado.db", cipher=FernetCipher(generate_key()))
    _record(store)

    record = store.latest_scan(TARGET)
    assert record.findings[0]["id"] == "cert_expired"
    assert record.surface_map()["apex"] == "cliente.test"
    assert record.encrypted is True


def test_queryable_columns_stay_in_the_clear(tmp_path):
    """Compromiso deliberado: objetivo, fecha y score se consultan sin descifrar."""
    key = generate_key()
    store = ScanStore(tmp_path / "cifrado.db", cipher=FernetCipher(key))
    _record(store)

    with store._connect() as conn:
        row = conn.execute("SELECT target, scanned_at, score, grade FROM scans").fetchone()
    assert row["target"] == TARGET
    assert row["score"] == 55
    assert row["grade"] == "F"


def test_history_and_baseline_work_encrypted(tmp_path):
    store = ScanStore(tmp_path / "cifrado.db", cipher=FernetCipher(generate_key()))
    _record(store)
    store.record_scan(target=TARGET, mode="passive", score=80, grade="B",
                      findings=[], artifacts={}, scanned_at="2026-08-01T00:00:00+00:00")

    assert [r.score for r in store.history(TARGET)] == [55, 80]
    assert store.baseline(TARGET).findings[0]["id"] == "cert_expired"


def test_reading_encrypted_data_without_the_key_fails_loudly(tmp_path):
    path = tmp_path / "cifrado.db"
    ScanStore(path, cipher=FernetCipher(generate_key())).record_scan(
        target=TARGET, mode="passive", score=55, grade="F", findings=[_FINDING], artifacts={},
    )
    with pytest.raises(DecryptionError, match=ENV_KEY):
        ScanStore(path, cipher=NullCipher()).latest_scan(TARGET)


def test_the_wrong_key_fails_loudly(tmp_path):
    path = tmp_path / "cifrado.db"
    ScanStore(path, cipher=FernetCipher(generate_key())).record_scan(
        target=TARGET, mode="passive", score=55, grade="F", findings=[_FINDING], artifacts={},
    )
    with pytest.raises(DecryptionError):
        ScanStore(path, cipher=FernetCipher(generate_key())).latest_scan(TARGET)


def test_existing_plaintext_database_still_reads_after_enabling_encryption(tmp_path):
    """Activar el cifrado no puede romper una base que ya existía."""
    path = tmp_path / "mixta.db"
    ScanStore(path, cipher=NullCipher()).record_scan(
        target=TARGET, mode="passive", score=40, grade="F",
        findings=[_FINDING], artifacts={}, scanned_at="2026-01-01T00:00:00+00:00",
    )

    encrypted_store = ScanStore(path, cipher=FernetCipher(generate_key()))
    encrypted_store.record_scan(
        target=TARGET, mode="passive", score=90, grade="A",
        findings=[], artifacts={}, scanned_at="2026-02-01T00:00:00+00:00",
    )

    history = encrypted_store.history(TARGET)
    assert [r.score for r in history] == [40, 90]
    assert [r.encrypted for r in history] == [False, True]
    assert history[0].findings[0]["id"] == "cert_expired"
