"""Comprobaciones de la configuración de despliegue (plan maestro §11).

Lo que se verifica aquí no es lógica de negocio, sino que el contenedor no
pierda datos ni exponga un escáner abierto. Son los dos errores de despliegue
que tienen consecuencias reales.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

import idata_sentinel.storage.db as db_module
from idata_sentinel.storage.db import ENV_DB_PATH

ROOT = Path(__file__).resolve().parent.parent


# -- persistencia ----------------------------------------------------------


def test_db_path_comes_from_the_environment(monkeypatch, tmp_path):
    """Sin esto la base vive dentro de la imagen y cada redeploy borra la línea
    base de todos los clientes."""
    destino = tmp_path / "volumen" / "sentinel.db"
    monkeypatch.setenv(ENV_DB_PATH, str(destino))
    recargado = importlib.reload(db_module)
    try:
        assert recargado.DEFAULT_DB_PATH == destino
        recargado.ScanStore(recargado.DEFAULT_DB_PATH)
        assert destino.exists()
    finally:
        monkeypatch.delenv(ENV_DB_PATH, raising=False)
        importlib.reload(db_module)


def test_db_path_falls_back_to_the_working_directory(monkeypatch):
    monkeypatch.delenv(ENV_DB_PATH, raising=False)
    recargado = importlib.reload(db_module)
    assert recargado.DEFAULT_DB_PATH == Path("idata_sentinel.db")


# -- Dockerfile ------------------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_container_declares_a_persistent_volume(dockerfile):
    assert 'VOLUME ["/data"]' in dockerfile
    assert "ENV IDATA_SENTINEL_DB=/data/sentinel.db" in dockerfile


def test_container_does_not_run_as_root(dockerfile):
    assert "USER sentinel" in dockerfile
    assert dockerfile.rstrip().index("USER sentinel") < dockerfile.rstrip().index("CMD")


def test_volume_is_writable_by_the_app_user(dockerfile):
    """Un volumen propiedad de root deja al proceso sin poder escribir."""
    assert "chown -R sentinel:sentinel /app /data" in dockerfile


def test_container_installs_weasyprint_native_libraries(dockerfile):
    """Sin ellas no hay PDF, que es el entregable del servicio."""
    for lib in ("libpango-1.0-0", "libpangocairo-1.0-0", "libgdk-pixbuf-2.0-0"):
        assert lib in dockerfile


def test_container_runs_the_scheduler_in_process(dockerfile):
    """Un volumen se monta en un solo servicio: web y worker separados no
    podrían compartir la base SQLite."""
    assert "--con-monitoreo" in dockerfile


# -- Railway ---------------------------------------------------------------


@pytest.fixture(scope="module")
def railway() -> dict:
    return json.loads((ROOT / "railway.json").read_text(encoding="utf-8"))


def test_railway_builds_from_the_dockerfile(railway):
    assert railway["build"]["builder"] == "DOCKERFILE"


def test_railway_uses_the_health_endpoint(railway):
    assert railway["deploy"]["healthcheckPath"] == "/api/salud"


def test_railway_start_command_binds_the_injected_port(railway):
    comando = railway["deploy"]["startCommand"]
    assert "--port $PORT" in comando
    assert "--host 0.0.0.0" in comando


def test_railway_runs_a_single_replica(railway):
    """SQLite en un volumen no admite varios escritores."""
    assert railway["deploy"]["numReplicas"] == 1
