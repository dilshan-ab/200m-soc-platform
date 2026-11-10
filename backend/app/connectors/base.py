"""Connector SDK: every tool type is a plugin with a manifest + a Connector implementation."""
from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from ..security import validate_egress_url


class ConnectorError(Exception):
    pass


@dataclass
class FieldSpec:
    name: str
    label: str
    type: str = "text"  # text|url|password|number|file|textarea|bool|list
    required: bool = True
    secret: bool = False
    help: str = ""
    default: Any = None


@dataclass
class Manifest:
    type: str
    label: str
    category: str  # detection|case|intel|response|vuln|ops|notify|identity
    link_method: str
    direction: list[str]  # pull|push|action|two-way|out|login
    auth: str
    fields: list[FieldSpec]
    capabilities: list[str] = field(default_factory=list)  # poll_alerts poll_assets poll_findings webhook action enrich notify case_sync status
    test_checks: list[str] = field(default_factory=list)
    webhook: bool = False
    setup_hint: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "type": self.type, "label": self.label, "category": self.category, "link_method": self.link_method,
            "direction": self.direction, "auth": self.auth, "capabilities": self.capabilities,
            "test_checks": self.test_checks, "webhook": self.webhook, "setup_hint": self.setup_hint,
            "fields": [f.__dict__ for f in self.fields],
        }

    @property
    def secret_fields(self) -> list[str]:
        return [f.name for f in self.fields if f.secret]


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class NormAlert:
    source_id: str
    title: str
    severity: str = "low"
    time: datetime | None = None
    description: str = ""
    rule_id: str = ""
    mitre: list[str] = field(default_factory=list)
    compliance: dict[str, Any] = field(default_factory=dict)
    host: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    username: str = ""
    file_hash: str = ""
    category: str = "security"
    agent_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PollResult:
    alerts: list[NormAlert] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    checkpoint: dict[str, Any] = field(default_factory=dict)
    version: str = ""


HttpFactory = Callable[[bool | ssl.SSLContext], httpx.Client]


def _default_factory(verify: bool | ssl.SSLContext) -> httpx.Client:
    return httpx.Client(timeout=15.0, verify=verify, follow_redirects=False)


_factory: HttpFactory = _default_factory


def set_http_factory(f: HttpFactory | None) -> None:
    global _factory
    _factory = f or _default_factory


class Connector:
    """Base class. `cfg` is the tool config; `secrets` holds decrypted secret fields (memory only)."""

    manifest: Manifest

    def __init__(self, cfg: dict[str, Any], secrets: dict[str, str]) -> None:
        self.cfg = cfg
        self.secrets = secrets
        self._client: httpx.Client | None = None

    # ---- HTTP with egress policy applied to every request
    def client(self) -> httpx.Client:
        if self._client is None:
            verify: bool | ssl.SSLContext = True
            if self.cfg.get("ca_cert"):
                verify = ssl.create_default_context(cadata=self.cfg["ca_cert"])
            self._client = _factory(verify)
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def base_url(self) -> str:
        return str(self.cfg.get("url", "")).rstrip("/")

    def request(self, method: str, path: str = "", *, url: str | None = None, **kw: Any) -> httpx.Response:
        target = url or f"{self.base_url()}{path}"
        try:
            validate_egress_url(target)
        except ValueError as e:
            raise ConnectorError(f"egress policy: {e}") from e
        try:
            r = self.client().request(method, target, **kw)
        except httpx.HTTPError as e:
            raise ConnectorError(f"request failed: {type(e).__name__}") from e
        return r

    def json(self, method: str, path: str = "", **kw: Any) -> Any:
        r = self.request(method, path, **kw)
        if r.status_code >= 400:
            raise ConnectorError(f"HTTP {r.status_code} from {self.manifest.type}")
        try:
            return r.json()
        except ValueError as e:
            raise ConnectorError("invalid JSON response") from e

    # ---- plugin surface (override as needed)
    def test(self) -> list[CheckResult]:
        raise NotImplementedError

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        return PollResult(checkpoint=checkpoint)

    def parse_webhook(self, payload: dict[str, Any]) -> list[NormAlert]:
        return []

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        raise ConnectorError(f"{self.manifest.type} does not support action {action_key}")

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        raise ConnectorError(f"{self.manifest.type} does not support enrichment")

    def notify(self, subject: str, body: str, address: str) -> None:
        raise ConnectorError(f"{self.manifest.type} cannot send notifications")

    def create_case(self, case: dict[str, Any]) -> str:
        raise ConnectorError(f"{self.manifest.type} cannot create cases")

    def verdict(self, *, ok: bool, detail: str = "") -> CheckResult:
        return CheckResult(self.manifest.test_checks[0] if self.manifest.test_checks else "check", ok, detail)


REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    REGISTRY[cls.manifest.type] = cls
    return cls


def get_connector_cls(type_: str) -> type[Connector]:
    from . import plugins  # noqa: F401  (registers all plugins)

    try:
        return REGISTRY[type_]
    except KeyError as e:
        raise ConnectorError(f"unknown tool type {type_}") from e


def all_manifests() -> list[Manifest]:
    from . import plugins  # noqa: F401

    return [c.manifest for c in REGISTRY.values()]
