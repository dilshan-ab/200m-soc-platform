"""Secret store abstraction. Secrets are write-only through the API: never returned to clients."""
from __future__ import annotations

from typing import Protocol

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import get_settings
from .models import SecretRecord, utcnow


class SecretStore(Protocol):
    def put(self, db: Session, ref: str, value: str) -> None: ...
    def get(self, db: Session, ref: str) -> str | None: ...
    def delete(self, db: Session, ref: str) -> None: ...


class LocalSecretStore:
    """Fernet-encrypted rows. Intended for development / single-node; Vault in production."""

    def __init__(self, key: str | None = None) -> None:
        k = key or get_settings().secrets_key
        if not k:
            k = Fernet.generate_key().decode()  # ephemeral (dev/test only)
        self._f = Fernet(k.encode())

    def put(self, db: Session, ref: str, value: str) -> None:
        row = db.get(SecretRecord, ref)
        ct = self._f.encrypt(value.encode()).decode()
        if row:
            row.ciphertext, row.version, row.updated_at = ct, row.version + 1, utcnow()
        else:
            db.add(SecretRecord(ref=ref, ciphertext=ct))
        db.flush()

    def get(self, db: Session, ref: str) -> str | None:
        row = db.get(SecretRecord, ref)
        if not row:
            return None
        try:
            return self._f.decrypt(row.ciphertext.encode()).decode()
        except InvalidToken:
            return None

    def delete(self, db: Session, ref: str) -> None:
        row = db.get(SecretRecord, ref)
        if row:
            db.delete(row)
            db.flush()


class VaultSecretStore:
    """HashiCorp Vault / OpenBao KV v2 over HTTP."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        s = get_settings()
        self._base = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_mount}"
        self._c = client or httpx.Client(headers={"X-Vault-Token": s.vault_token}, timeout=5.0, verify=True)

    def put(self, db: Session, ref: str, value: str) -> None:
        r = self._c.post(f"{self._base}/data/soc/{ref}", json={"data": {"value": value}})
        r.raise_for_status()

    def get(self, db: Session, ref: str) -> str | None:
        r = self._c.get(f"{self._base}/data/soc/{ref}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()["data"]["data"]["value"]

    def delete(self, db: Session, ref: str) -> None:
        self._c.delete(f"{self._base}/metadata/soc/{ref}").raise_for_status()


_store: SecretStore | None = None


def get_secret_store() -> SecretStore:
    global _store
    if _store is None:
        s = get_settings()
        _store = VaultSecretStore() if s.secret_backend == "vault" else LocalSecretStore()
    return _store


def set_secret_store(store: SecretStore | None) -> None:
    global _store
    _store = store
