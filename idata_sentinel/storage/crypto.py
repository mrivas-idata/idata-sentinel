"""Cifrado en reposo de los datos de escaneo (plan maestro §1.4).

Los hallazgos y el inventario de activos describen las debilidades de un cliente:
si la base se filtra, el atacante recibe el mapa ya hecho. Por eso el contenido
sensible se cifra con Fernet (AES-128-CBC + HMAC, de `cryptography`, que ya es
dependencia del proyecto).

**Qué se cifra y qué no.** Solo los blobs sensibles: `findings` y `artifacts`. El
objetivo, la fecha y el score quedan en claro porque son las columnas por las que
se consulta y ordena — cifrarlas obligaría a descifrar la tabla entera para listar
un histórico. Es un compromiso deliberado: se protege el detalle explotable, no el
hecho de que un dominio fue escaneado.

Sin clave configurada el almacén guarda en claro y cada fila registra en qué modo
se escribió, así una base existente sigue leyéndose tras activar el cifrado.
"""
from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from cryptography.fernet import Fernet, InvalidToken

ENV_KEY = "IDATA_SENTINEL_ENCRYPTION_KEY"


class DecryptionError(RuntimeError):
    """La fila está cifrada pero la clave actual no la abre."""


@runtime_checkable
class Cipher(Protocol):
    enabled: bool

    def encrypt(self, plaintext: str) -> str: ...
    def decrypt(self, ciphertext: str) -> str: ...


class NullCipher:
    """Sin clave configurada: se guarda en claro y se deja constancia en la fila."""

    enabled = False

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, ciphertext: str) -> str:
        return ciphertext


class FernetCipher:
    enabled = True

    def __init__(self, key: str | bytes) -> None:
        try:
            self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())
        except (ValueError, TypeError) as e:
            raise ValueError(
                "Clave de cifrado inválida: se espera una clave Fernet en base64 de 32 bytes. "
                "Genera una con 'idata-sentinel keygen'."
            ) from e

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as e:
            raise DecryptionError(
                "No se pudo descifrar un registro: la clave no corresponde a la que "
                f"cifró estos datos. Verifica {ENV_KEY}."
            ) from e


def generate_key() -> str:
    return Fernet.generate_key().decode()


def cipher_from_env(key: str | None = None) -> Cipher:
    """`key` explícita > variable de entorno > sin cifrado."""
    resolved = key if key is not None else os.environ.get(ENV_KEY, "")
    return FernetCipher(resolved) if resolved else NullCipher()
