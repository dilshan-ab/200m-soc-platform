"""Tool instances: validation, secret handling, connector construction."""
from __future__ import annotations

import re
import secrets as pysecrets
from typing import Any

from sqlalchemy.orm import Session

from ..connectors.base import Connector, ConnectorError, Manifest, get_connector_cls
from ..models import ConnectorState, Tool
from ..security import SecurityError, is_bundled_caldera_url, validate_egress_url
from ..vault import get_secret_store

_LIST_SPLIT = re.compile(r"[,\n]")


def secret_ref(tool_id: str, field: str) -> str:
    return f"tools/{tool_id}/{field}"


def split_config(manifest: Manifest, values: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Validate submitted fields against the manifest; returns (public config, secrets)."""
    known = {f.name: f for f in manifest.fields}
    unknown = set(values) - set(known)
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(sorted(unknown))}")
    cfg: dict[str, Any] = {}
    sec: dict[str, str] = {}
    for name, f in known.items():
        v = values.get(name)
        if v in (None, ""):
            v = f.default if not f.secret else None
        if v in (None, "", []):
            if f.required:
                raise ValueError(f"field '{name}' is required")
            continue
        if f.type == "list" and isinstance(v, str):
            v = [x.strip() for x in _LIST_SPLIT.split(v) if x.strip()]
        if f.type == "number":
            v = int(str(v))
        if f.type == "url" and not f.secret and not (manifest.type == "caldera" and f.name == "url" and is_bundled_caldera_url(str(v))):
            try:
                validate_egress_url(str(v)) if f.name == "url" and manifest.type not in ("clickup",) else None
            except SecurityError as e:
                raise ValueError(f"{name}: {e}") from e
        if isinstance(v, str) and len(v) > 20000:
            raise ValueError(f"field '{name}' too long")
        if f.secret:
            sec[name] = str(v)
        else:
            cfg[name] = v
    return cfg, sec


def store_secrets(db: Session, tool: Tool, secrets: dict[str, str]) -> None:
    store = get_secret_store()
    refs = dict(tool.secret_refs or {})
    for name, value in secrets.items():
        ref = secret_ref(tool.id, name)
        store.put(db, ref, value)
        refs[name] = ref
    tool.secret_refs = refs


def purge_secrets(db: Session, tool: Tool) -> None:
    store = get_secret_store()
    for ref in (tool.secret_refs or {}).values():
        store.delete(db, ref)
    if tool.webhook_secret_ref:
        store.delete(db, tool.webhook_secret_ref)


def load_secrets(db: Session, tool: Tool) -> dict[str, str]:
    store = get_secret_store()
    out: dict[str, str] = {}
    for name, ref in (tool.secret_refs or {}).items():
        v = store.get(db, ref)
        if v is not None:
            out[name] = v
    if tool.webhook_secret_ref:
        v = store.get(db, tool.webhook_secret_ref)
        if v:
            out["_webhook"] = v
    return out


def build_connector(db: Session, tool: Tool) -> Connector:
    cls = get_connector_cls(tool.type)
    secrets = load_secrets(db, tool)
    missing = [f for f in cls.manifest.secret_fields if f not in secrets and next(x for x in cls.manifest.fields if x.name == f).required]
    if missing:
        raise ConnectorError(f"missing secrets: {', '.join(missing)}")
    return cls(dict(tool.config or {}), secrets)


def ensure_state(db: Session, tool: Tool) -> ConnectorState:
    if tool.state is None:
        tool.state = ConnectorState(tool_id=tool.id)
        db.flush()
    return tool.state


def new_webhook_secret(db: Session, tool: Tool) -> str:
    """Generate (or rotate) the webhook secret. Returned once; stored only in the secret store."""
    value = pysecrets.token_urlsafe(32)
    ref = secret_ref(tool.id, "_webhook")
    get_secret_store().put(db, ref, value)
    tool.webhook_secret_ref = ref
    return value
