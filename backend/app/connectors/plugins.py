"""Tool plugins. Each declares a manifest and implements the capabilities it advertises."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import smtplib
import socket
import ssl
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

import httpx
import yaml

from ..config import get_settings
from ..security import validate_egress_url
from .base import (
    CheckResult,
    Connector,
    ConnectorError,
    Manifest,
    NormAlert,
    PollResult,
    register,
)
from .base import (
    FieldSpec as F,
)

URL = F("url", "Base URL", "url", help="https://host:port (https + approved internal networks only)")
CA = F("ca_cert", "CA certificate (PEM)", "textarea", required=False)


def _parse_ts(v: Any) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, UTC)
    if isinstance(v, str):
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00").replace("+0000", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _basic(c: Connector) -> tuple[str, str]:
    return str(c.cfg.get("username", "")), c.secrets.get("password", "")


def _bearer(c: Connector, field: str = "api_key") -> dict[str, str]:
    return {"Authorization": f"Bearer {c.secrets.get(field, '')}"}


# ----------------------------------------------------------------------------- Wazuh
@register
class WazuhIndexer(Connector):
    manifest = Manifest(
        "wazuh_indexer", "Wazuh indexer", "detection", "REST poll (OpenSearch API)", ["pull"], "user + password (read-only role)",
        [URL, F("username", "Username"), F("password", "Password", "password", secret=True),
         F("index_pattern", "Index pattern", required=False, default="wazuh-alerts-*"), CA],
        ["poll_alerts", "poll_assets"], ["Reads latest alert from wazuh-alerts-*"],
    )

    def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        idx = self.cfg.get("index_pattern") or "wazuh-alerts-*"
        return self.json("POST", f"/{idx}/_search", json=body, auth=_basic(self))  # type: ignore[no-any-return]

    def test(self) -> list[CheckResult]:
        d = self._search({"size": 1, "sort": [{"timestamp": "desc"}]})
        hits = d.get("hits", {}).get("hits", [])
        return [CheckResult(self.manifest.test_checks[0], True, f"{len(hits)} alert(s) readable")]

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        ts = checkpoint.get("ts")
        if ts is None:
            # First poll ever: seed the checkpoint at the current newest alert instead of
            # crawling the entire historical backlog from the beginning forward.
            latest = self._search({"size": 1, "sort": [{"timestamp": "desc"}]})
            hits = latest.get("hits", {}).get("hits", [])
            seed = hits[0].get("_source", {}).get("timestamp") if hits else None
            return PollResult(checkpoint={"ts": seed} if seed else {})
        q: dict[str, Any] = {"range": {"timestamp": {"gt": ts}}}
        d = self._search({"size": limit, "sort": [{"timestamp": "asc"}], "query": q})
        out: list[NormAlert] = []
        last = ts
        for h in d.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            out.append(self.normalize(h["_id"], src))
            last = src.get("timestamp", last)
        return PollResult(alerts=out, checkpoint={"ts": last} if last else {})

    @staticmethod
    def normalize(_id: str, s: dict[str, Any]) -> NormAlert:
        rule, agent, data = s.get("rule", {}), s.get("agent", {}), s.get("data", {})
        comp = {k: rule[k] for k in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc") if k in rule}
        return NormAlert(
            source_id=str(_id), title=str(rule.get("description", "Wazuh alert"))[:500], severity=str(rule.get("level", 3)),
            time=_parse_ts(s.get("timestamp")), rule_id=str(rule.get("id", "")), mitre=list((rule.get("mitre") or {}).get("id", [])),
            compliance=comp, host=str(agent.get("name", "")), agent_id=str(agent.get("id", "")), src_ip=str(data.get("srcip", "")),
            username=str(data.get("dstuser", data.get("srcuser", ""))), file_hash=str((s.get("syscheck") or {}).get("sha256_after", "")),
            raw={"level": rule.get("level"), "groups": rule.get("groups", []), "location": s.get("location", "")},
        )


@register
class WazuhManager(Connector):
    manifest = Manifest(
        "wazuh_manager", "Wazuh manager", "detection", "REST API + integration webhook", ["pull", "push", "action"], "API user -> JWT",
        [URL, F("username", "API user"), F("password", "Password", "password", secret=True), CA],
        ["webhook", "action", "poll_assets"], ["Token issued", "Agents listed", "Test webhook received"], webhook=True,
        setup_hint="Add an <integration> block to ossec.conf pointing to the generated webhook URL with the secret as bearer token.",
    )

    def _token(self) -> dict[str, str]:
        r = self.request("POST", "/security/user/authenticate?raw=true", auth=_basic(self))
        if r.status_code != 200:
            raise ConnectorError(f"authentication failed (HTTP {r.status_code})")
        return {"Authorization": f"Bearer {r.text.strip()}"}

    def test(self) -> list[CheckResult]:
        h = self._token()
        res = [CheckResult("Token issued", True)]
        d = self.json("GET", "/agents?limit=1", headers=h)
        res.append(CheckResult("Agents listed", True, f"{d.get('data', {}).get('total_affected_items', 0)} agents"))
        return res

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        h = self._token()
        d = self.json("GET", f"/agents?limit={limit}&select=id,name,ip,os.name,status,lastKeepAlive", headers=h)
        assets = []
        for a in d.get("data", {}).get("affected_items", []):
            assets.append({"agent_id": a.get("id"), "name": a.get("name"), "ips": [a.get("ip")] if a.get("ip") else [],
                           "os": (a.get("os") or {}).get("name", ""), "agent_status": a.get("status", "unknown"),
                           "last_seen": a.get("lastKeepAlive")})
        return PollResult(assets=assets, checkpoint=checkpoint)

    def parse_webhook(self, payload: dict[str, Any]) -> list[NormAlert]:
        _id = payload.get("id") or f"{payload.get('timestamp')}-{(payload.get('rule') or {}).get('id')}-{(payload.get('agent') or {}).get('id')}"
        return [WazuhIndexer.normalize(str(_id), payload)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        h = self._token()
        cmd = {"block_ip": "firewall-drop", "unblock_ip": "firewall-drop", "restart_agent": "restart-wazuh", "disable_account": "disable-account"}.get(action_key)
        if not cmd:
            raise ConnectorError(f"unsupported action {action_key}")
        results = []
        for t in targets:
            body = {"command": cmd, "arguments": [t] if action_key in ("block_ip", "unblock_ip", "disable_account") else [], "alert": {"data": {"srcip": t}}}
            agent = params.get("agent_id", "000")
            d = self.json("PUT", f"/active-response?agents_list={agent}", json=body, headers=h)
            results.append({"target": t, "affected": d.get("data", {}).get("total_affected_items", 0)})
        return {"results": results}


# ----------------------------------------------------------------------------- Case / intel
@register
class TheHive(Connector):
    manifest = Manifest(
        "thehive", "TheHive", "case", "REST API v1 + webhook", ["two-way"], "API key (Bearer)",
        [URL, F("api_key", "API key", "password", secret=True), F("organisation", "Organisation", required=False), CA],
        ["webhook", "case_sync"], ["Cases listed", "Webhook test received"], webhook=True,
    )

    def _h(self) -> dict[str, str]:
        h = _bearer(self)
        if self.cfg.get("organisation"):
            h["X-Organisation"] = str(self.cfg["organisation"])
        return h

    def test(self) -> list[CheckResult]:
        self.json("POST", "/api/v1/query", json={"query": [{"_name": "listCase"}, {"_name": "page", "from": 0, "to": 1}]}, headers=self._h())
        return [CheckResult("Cases listed", True)]

    def create_case(self, case: dict[str, Any]) -> str:
        sev = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(case.get("severity", "medium"), 2)
        d = self.json("POST", "/api/v1/case", headers=self._h(), json={"title": case["title"], "description": case.get("description", ""), "severity": sev})
        return str(d.get("_id") or d.get("id"))


@register
class Cortex(Connector):
    manifest = Manifest(
        "cortex", "Cortex", "intel", "REST API", ["action"], "API key",
        [URL, F("api_key", "API key", "password", secret=True), F("analyzers", "Enabled analyzers", "list", required=False), CA],
        ["enrich"], ["Analyzer list returned"],
    )

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/api/analyzer", headers=_bearer(self))
        return [CheckResult("Analyzer list returned", True, f"{len(d)} analyzers")]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        dt = {"ip": "ip", "domain": "domain", "hash": "hash", "url": "url"}.get(itype, "other")
        out: dict[str, Any] = {}
        for az in (self.cfg.get("analyzers") or [])[:5]:
            d = self.json("POST", f"/api/analyzer/{az}/run", headers=_bearer(self), json={"data": indicator, "dataType": dt})
            out[az] = {"job": d.get("id"), "status": d.get("status")}
        return {"analyzers": out, "verdict": "unknown"}


@register
class Misp(Connector):
    manifest = Manifest(
        "misp", "MISP", "intel", "REST API (PyMISP)", ["pull", "action"], "Auth key",
        [URL, F("auth_key", "Auth key", "password", secret=True), F("default_event", "Default event for IOC push", required=False),
         F("default_tlp", "Default TLP", required=False, default="AMBER"), CA],
        ["enrich"], ["Test attribute search works"],
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": self.secrets.get("auth_key", ""), "Accept": "application/json"}

    def test(self) -> list[CheckResult]:
        self.json("POST", "/attributes/restSearch", headers=self._h(), json={"limit": 1, "returnFormat": "json"})
        return [CheckResult("Test attribute search works", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        d = self.json("POST", "/attributes/restSearch", headers=self._h(), json={"value": indicator, "returnFormat": "json", "limit": 20})
        attrs = d.get("response", {}).get("Attribute", [])
        return {"matches": len(attrs), "events": sorted({a.get("event_id") for a in attrs}), "verdict": "malicious" if attrs else "unknown"}


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.]{1,200}$")
_VELO_CONFIG_KEYS = ("ca_certificate", "client_cert", "client_private_key", "api_connection_string")
# Remediation artifacts shipped with Velociraptor; the same artifact removes its policy with RemovePolicy=Y.
_QUARANTINE_ARTIFACTS = {"windows": "Windows.Remediation.Quarantine", "linux": "Linux.Remediation.Quarantine"}
_MAX_VELO_ROWS = 10_000


@register
class Velociraptor(Connector):
    manifest = Manifest(
        "velociraptor", "Velociraptor", "response", "gRPC API", ["pull", "action"], "API client certificate (YAML)",
        [F("api_config", "API client config (api_client.conf.yaml)", "textarea", secret=True,
           help="Output of: velociraptor config api_client. Needs the ca_certificate, client_cert, client_private_key and api_connection_string keys."),
         F("allowed_artifacts", "Allowed artifacts", "list", required=False, help="Only these artifacts can be collected. Isolation uses a built-in quarantine artifact.")],
        ["action"], ["SELECT * FROM info() returns"],
        setup_hint="Create an API client with the minimum role (for example investigator) and allow the gRPC port from this node.",
    )

    def _config(self) -> dict[str, str]:
        try:
            cfg = yaml.safe_load(self.secrets.get("api_config", ""))
        except yaml.YAMLError as e:
            raise ConnectorError("api_config is not valid YAML") from e
        if not isinstance(cfg, dict):
            raise ConnectorError("api_config must be the YAML written by 'velociraptor config api_client'")
        missing = [k for k in _VELO_CONFIG_KEYS if not isinstance(cfg.get(k), str) or not cfg[k]]
        if missing:
            raise ConnectorError("api_config is missing: " + ", ".join(missing))
        return {k: cfg[k] for k in _VELO_CONFIG_KEYS}

    def _run(self, vql: str, env: dict[str, str] | None = None, *, timeout: int = 30) -> list[dict[str, Any]]:
        """Run one VQL query. Caller-supplied values go in `env` (referenced by name in the VQL), never into the query text."""
        try:
            import grpc  # type: ignore[import-not-found]
            from pyvelociraptor import api_pb2, api_pb2_grpc  # type: ignore[import-not-found]
        except ImportError as e:
            raise ConnectorError("pyvelociraptor is not installed on this node") from e
        cfg = self._config()
        target = cfg["api_connection_string"]
        try:
            validate_egress_url(f"https://{target}")
        except ValueError as e:
            raise ConnectorError(f"egress policy: {e}") from e
        request = api_pb2.VQLCollectorArgs(
            max_wait=1, max_row=1000, timeout=timeout,
            Query=[api_pb2.VQLRequest(Name="soc", VQL=vql)],
            env=[api_pb2.VQLEnv(key=k, value=v) for k, v in (env or {}).items()],
        )
        rows: list[dict[str, Any]] = []
        try:
            creds = grpc.ssl_channel_credentials(
                root_certificates=cfg["ca_certificate"].encode(), private_key=cfg["client_private_key"].encode(), certificate_chain=cfg["client_cert"].encode())
            # The server certificate is issued to "VelociraptorServer" regardless of how it is reached; trust is pinned to the configured CA.
            options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
            with grpc.secure_channel(target, creds, options) as channel:
                for resp in api_pb2_grpc.APIStub(channel).Query(request, timeout=timeout + 10):
                    if resp.Response:
                        rows.extend(json.loads(resp.Response))
                    if len(rows) > _MAX_VELO_ROWS:
                        raise ConnectorError("velociraptor returned too many rows")
        except grpc.RpcError as e:
            code = e.code().name if hasattr(e, "code") and callable(e.code) else "RpcError"
            raise ConnectorError(f"request failed: {code}") from e
        except ValueError as e:
            raise ConnectorError("invalid response from velociraptor") from e
        return rows

    def test(self) -> list[CheckResult]:
        rows = self._run("SELECT * FROM info()")
        if not rows:
            raise ConnectorError("info() returned no rows")
        return [CheckResult("SELECT * FROM info() returns", True, str(rows[0].get("Hostname", "")))]

    def _resolve_client(self, host: str) -> dict[str, str]:
        rows = self._run(
            "SELECT client_id, os_info.system AS os, os_info.hostname AS hostname, os_info.fqdn AS fqdn FROM clients(search=Search)",
            {"Search": f"host:{host}"},
        )
        want = host.lower()
        hits = [r for r in rows if want in (str(r.get("hostname", "")).lower(), str(r.get("fqdn", "")).lower())]
        if not hits:
            raise ConnectorError(f"no Velociraptor client found for host {host}")
        if len(hits) > 1:
            raise ConnectorError(f"host {host} matches {len(hits)} Velociraptor clients; refusing to guess")
        return {"client_id": str(hits[0].get("client_id", "")), "os": str(hits[0].get("os", "")).lower()}

    def _collect(self, client_id: str, artifact: str, artifact_params: dict[str, str]) -> str:
        rows = self._run(
            "SELECT collect_client(client_id=ClientId, artifacts=Artifact, env=parse_json(data=ArtifactParams)) AS Flow FROM scope()",
            {"ClientId": client_id, "Artifact": artifact, "ArtifactParams": json.dumps(artifact_params)},
        )
        flow = (rows[0].get("Flow") if rows else None) or {}
        flow_id = flow.get("flow_id") if isinstance(flow, dict) else None
        if not flow_id:
            raise ConnectorError("collection was not scheduled")
        return str(flow_id)

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        allowed = set(self.cfg.get("allowed_artifacts") or [])
        if action_key == "collect_artifact" and params.get("artifact") not in allowed:
            raise ConnectorError("artifact not on allow-list")
        if action_key == "kill_process":
            raise ConnectorError("kill_process is not supported: the request carries no process identifier")
        if action_key not in ("isolate_host", "release_host", "collect_artifact"):
            raise ConnectorError(f"unsupported action {action_key}")
        if not targets:
            raise ConnectorError("no target host")
        for h in targets:
            if not _HOST_RE.match(h):
                raise ConnectorError(f"invalid host name {h!r}")
        artifact = str(params.get("artifact", ""))
        if action_key == "collect_artifact" and not _ARTIFACT_RE.match(artifact):
            raise ConnectorError("invalid artifact name")
        extra = {str(k): str(v) for k, v in (params.get("artifact_params") or {}).items()} if action_key == "collect_artifact" else {}
        done: dict[str, Any] = {}
        failed: dict[str, str] = {}
        for host in targets:
            try:
                client = self._resolve_client(host)
                if action_key == "collect_artifact":
                    flow = self._collect(client["client_id"], artifact, extra)
                else:
                    art = _QUARANTINE_ARTIFACTS.get(client["os"])
                    if art is None:
                        raise ConnectorError(f"isolation is not supported for {client['os'] or 'unknown'} hosts")
                    flow = self._collect(client["client_id"], art, {"RemovePolicy": "Y" if action_key == "release_host" else "N"})
                done[host] = {"client_id": client["client_id"], "flow_id": flow}
            except ConnectorError as e:
                failed[host] = str(e)
        if failed:
            raise ConnectorError("failed for " + "; ".join(f"{h}: {m}" for h, m in failed.items()) + (f" (succeeded for {', '.join(done)})" if done else ""))
        return {"hosts": done}


_GVM_SEVERITIES = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"))
_MAX_SCAN_TARGETS = 64


def _gvm_severity(cvss: float) -> str:
    return next((name for floor, name in _GVM_SEVERITIES if cvss >= floor), "low")


def _gvm_finding(r: Any) -> dict[str, Any] | None:
    """Normalise one GMP <result> element. Returns None when it has no usable identifier."""
    host = r.find("host")
    ip = (host.text or "").strip() if host is not None and host.text else ""
    nvt = r.find("nvt")
    oid = nvt.get("oid", "") if nvt is not None else ""
    cves = [ref.get("id", "") for ref in (nvt.iterfind("refs/ref") if nvt is not None else []) if ref.get("type", "").lower() == "cve" and ref.get("id")]
    vuln_id = cves[0] if cves else oid
    if not vuln_id:
        return None
    try:
        cvss = float(r.findtext("severity") or 0)
    except ValueError:
        cvss = 0.0
    return {
        "vuln_id": vuln_id, "oid": oid, "cves": cves, "title": (r.findtext("name") or vuln_id)[:400], "cvss": cvss, "severity": _gvm_severity(cvss),
        "component": (r.findtext("port") or "")[:200], "ip": ip, "hostname": (host.findtext("hostname") or "").strip() if host is not None else "",
        "result_id": r.get("id", ""), "modified": r.findtext("modification_time") or r.findtext("creation_time") or "",
    }


@register
class OpenVas(Connector):
    manifest = Manifest(
        "openvas", "OpenVAS / GVM", "vuln", "GMP (python-gvm)", ["pull", "action"], "GVM user",
        [F("host", "Host or socket path", help="Hostname/IP of gvmd, or an absolute path to its unix socket"), F("port", "Port", "number", required=False, default=9390),
         F("username", "User"), F("password", "Password", "password", secret=True),
         F("ca_cert", "CA certificate (PEM)", "textarea", required=False, help="Required for TCP connections: the gvmd certificate is verified against this CA."),
         F("allowed_scan_configs", "Allowed scan configs", "list", required=False, help="Names or IDs; scans can only use these")],
        ["poll_findings", "action"], ["Version + task list returned"],
        setup_hint="Needs GVM 22.4 or newer (GMP 22.4+). Use a dedicated GVM user with only the roles it needs.",
    )

    def _connection(self) -> Any:
        try:
            from gvm.connections import TLSConnection, UnixSocketConnection  # type: ignore[import-not-found]
        except ImportError as e:
            raise ConnectorError("python-gvm is not installed on this node") from e
        host = str(self.cfg.get("host", "")).strip()
        if not host:
            raise ConnectorError("host is required")
        if host.startswith("/"):
            return UnixSocketConnection(path=host, timeout=30)
        port = int(self.cfg.get("port") or 9390)
        ca = self.cfg.get("ca_cert")
        if not ca:
            raise ConnectorError("a CA certificate is required to verify the GVM TLS connection")
        try:
            validate_egress_url(f"https://{host}:{port}")
        except ValueError as e:
            raise ConnectorError(f"egress policy: {e}") from e

        class PinnedTLS(TLSConnection):  # python-gvm's TLSConnection does not verify the server unless client certs are also configured
            def _new_socket(self) -> ssl.SSLSocket:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=ca)
                ctx.check_hostname = False  # gvmd certificates are rarely issued for the address used; trust is pinned to the CA instead
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=False)
                sock.settimeout(self._timeout)
                return sock

        return PinnedTLS(hostname=host, port=port, timeout=30)

    @contextmanager
    def _gmp(self) -> Iterator[Any]:
        try:
            from gvm.errors import GvmError  # type: ignore[import-not-found]
            from gvm.protocols.gmp import GMP  # type: ignore[import-not-found]
            from gvm.transforms import EtreeCheckCommandTransform  # type: ignore[import-not-found]
        except ImportError as e:
            raise ConnectorError("python-gvm is not installed on this node") from e
        conn = self._connection()
        try:
            with GMP(conn, transform=EtreeCheckCommandTransform()) as gmp:
                try:
                    gmp.authenticate(str(self.cfg.get("username", "")), self.secrets.get("password", ""))
                except GvmError as e:
                    raise ConnectorError("GVM authentication failed") from e
                yield gmp
        except ConnectorError:
            raise
        except (GvmError, OSError) as e:
            raise ConnectorError(f"request failed: {type(e).__name__}") from e

    def test(self) -> list[CheckResult]:
        with self._gmp() as gmp:
            version = gmp.get_version().findtext("version") or "unknown"
            tasks = gmp.get_tasks(filter_string="rows=1")
            count = tasks.findtext("task_count") or str(len(tasks.findall("task")))
        return [CheckResult("Version + task list returned", True, f"GMP {version}, {count} tasks")]

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        last = _parse_ts(checkpoint["last_modified"]) if checkpoint.get("last_modified") else None
        with self._gmp() as gmp:
            resp = gmp.get_results(filter_string=f"severity>0 sort-reverse=modified rows={min(max(limit, 1), 1000)}", details=True)
            findings: list[dict[str, Any]] = []
            newest = last
            for r in resp.findall("result"):
                f = _gvm_finding(r)
                if f is None:
                    continue
                ts = _parse_ts(f["modified"]) if f["modified"] else None
                if last is not None and ts is not None and ts <= last:
                    continue
                if ts is not None and (newest is None or ts > newest):
                    newest = ts
                findings.append(f)
        cp = {"last_modified": newest.isoformat()} if newest else dict(checkpoint)
        return PollResult(findings=findings, checkpoint=cp)

    @staticmethod
    def _pick(resp: Any, tag: str, *, id_or_name: str | None = None, prefer: tuple[str, ...] = ()) -> Any:
        items = resp.findall(tag)
        if id_or_name is not None:
            return next((i for i in items if id_or_name in (i.get("id"), i.findtext("name"))), None)
        for name in prefer:
            hit = next((i for i in items if i.findtext("name") == name), None)
            if hit is not None:
                return hit
        return items[0] if items else None

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        if action_key != "run_scan":
            raise ConnectorError(f"unsupported action: {action_key}")
        want = str(params.get("scan_config", ""))
        if not want or want not in set(self.cfg.get("allowed_scan_configs") or []):
            raise ConnectorError("scan config not on allow-list")
        if not targets or len(targets) > _MAX_SCAN_TARGETS:
            raise ConnectorError(f"between 1 and {_MAX_SCAN_TARGETS} scan targets are required")
        for t in targets:
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                if not _HOST_RE.match(t):
                    raise ConnectorError(f"invalid scan target {t!r}") from None
        with self._gmp() as gmp:
            config = self._pick(gmp.get_scan_configs(), "config", id_or_name=want)
            if config is None:
                raise ConnectorError("scan config not found on GVM")
            scanner = self._pick(gmp.get_scanners(), "scanner", prefer=("OpenVAS Default",))
            port_list = self._pick(gmp.get_port_lists(), "port_list", prefer=("All IANA assigned TCP",))
            if scanner is None or port_list is None:
                raise ConnectorError("GVM has no scanner or port list available")
            tag = uuid.uuid4().hex[:8]
            target_id = task_id = ""
            try:
                target_id = gmp.create_target(f"soc-{tag}", hosts=list(targets), port_list_id=port_list.get("id")).get("id", "")
                task_id = gmp.create_task(f"soc-scan-{tag}", config.get("id"), target_id, scanner.get("id")).get("id", "")
                report_id = gmp.start_task(task_id).findtext("report_id") or ""
            except Exception:
                for cleanup, rid in ((gmp.delete_task, task_id), (gmp.delete_target, target_id)):
                    if rid:
                        with suppress(Exception):
                            cleanup(rid)
                raise
        return {"task_id": task_id, "target_id": target_id, "report_id": report_id, "scan_config": want}


@register
class Shuffle(Connector):
    manifest = Manifest(
        "shuffle", "Shuffle", "response", "REST API + webhook", ["action", "push"], "API key",
        [URL, F("api_key", "API key", "password", secret=True), F("exposed_workflows", "Exposed workflows", "list", required=False), CA],
        ["action", "webhook"], ["Workflow list returned"], webhook=True,
    )

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/api/v1/workflows", headers=_bearer(self))
        return [CheckResult("Workflow list returned", True, f"{len(d)} workflows")]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        wf = params.get("workflow")
        if wf not in (self.cfg.get("exposed_workflows") or []):
            raise ConnectorError("workflow not exposed")
        d = self.json("POST", f"/api/v1/workflows/{wf}/execute", headers=_bearer(self), json={"execution_argument": {"targets": targets}})
        return {"execution_id": d.get("execution_id", "")}


@register
class Opsi(Connector):
    manifest = Manifest(
        "opsi", "OPSI", "ops", "JSON-RPC", ["pull", "action"], "user + password",
        [URL, F("username", "User"), F("password", "Password", "password", secret=True), F("allowed_products", "Allowed products", "list", required=False), CA],
        ["action", "poll_assets"], ["backend_info returns"],
    )

    def _rpc(self, method: str, params: list[Any] | None = None) -> Any:
        d = self.json("POST", "", json={"id": 1, "method": method, "params": params or []}, auth=_basic(self))
        if d.get("error"):
            raise ConnectorError(f"opsi error: {str(d['error'])[:120]}")
        return d.get("result")

    def test(self) -> list[CheckResult]:
        self._rpc("backend_info")
        return [CheckResult("backend_info returns", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        prod = params.get("product")
        if action_key != "deploy_patch" or prod not in (self.cfg.get("allowed_products") or []):
            raise ConnectorError("product not on allow-list")
        for t in targets:
            self._rpc("setProductActionRequestWithDependencies", [prod, t, "setup"])
        return {"queued": len(targets)}


@register
class Bareos(Connector):
    manifest = Manifest(
        "bareos", "Bareos", "ops", "REST API / director console", ["pull", "action"], "Restricted console",
        [URL, F("console", "Console name"), F("password", "Password", "password", secret=True), F("allowed_jobs", "Allowed jobs", "list", required=False), CA],
        ["action"], ["status director returns"],
    )

    def test(self) -> list[CheckResult]:
        self.json("GET", "/api/v1/status/director", auth=(str(self.cfg.get("console", "")), self.secrets.get("password", "")))
        return [CheckResult("status director returns", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        job = params.get("job")
        if job not in (self.cfg.get("allowed_jobs") or []):
            raise ConnectorError("job not on allow-list")
        d = self.json("POST", "/api/v1/jobs/run", json={"job": job}, auth=(str(self.cfg.get("console", "")), self.secrets.get("password", "")))
        return {"job_id": d.get("jobid", "")}


# ----------------------------------------------------------------------------- Ops monitoring
@register
class UptimeKuma(Connector):
    manifest = Manifest(
        "uptime_kuma", "Uptime Kuma", "ops", "Webhook + metrics", ["push", "pull"], "API key",
        [F("url", "Metrics base URL", "url"), F("api_key", "API key", "password", secret=True), CA],
        ["webhook", "status"], ["Metrics readable", "Test notification received"], webhook=True,
    )

    def test(self) -> list[CheckResult]:
        r = self.request("GET", "/metrics", auth=("", self.secrets.get("api_key", "")))
        if r.status_code != 200:
            raise ConnectorError(f"metrics unreadable (HTTP {r.status_code})")
        return [CheckResult("Metrics readable", True)]

    def parse_webhook(self, payload: dict[str, Any]) -> list[NormAlert]:
        hb, mon = payload.get("heartbeat") or {}, payload.get("monitor") or {}
        if not mon:
            return []
        down = hb.get("status") == 0
        name = str(mon.get("name", "monitor"))
        return [NormAlert(
            source_id=f"kuma-{mon.get('id')}-{hb.get('time', payload.get('msg', ''))}", title=f"{'DOWN' if down else 'UP'}: {name}",
            severity="critical" if down else "info", time=_parse_ts(hb.get("time")), host=str(mon.get("hostname") or name),
            category="infrastructure", rule_id="kuma.down" if down else "kuma.up", description=str(payload.get("msg", ""))[:1000],
            raw={"monitor": name, "status": "down" if down else "up"},
        )]


@register
class PrometheusConn(Connector):
    manifest = Manifest(
        "prometheus", "Prometheus", "ops", "HTTP API", ["pull"], "None / basic auth (private network)",
        [URL, F("username", "User", required=False), F("password", "Password", "password", required=False, secret=True)],
        ["status"], ["`up` query returns"],
    )

    def test(self) -> list[CheckResult]:
        auth = (str(self.cfg["username"]), self.secrets.get("password", "")) if self.cfg.get("username") else None
        d = self.json("GET", "/api/v1/query", params={"query": "up"}, auth=auth)
        if d.get("status") != "success":
            raise ConnectorError("query failed")
        return [CheckResult("`up` query returns", True)]


# ----------------------------------------------------------------------------- Notify / ticketing
@register
class ClickUp(Connector):
    manifest = Manifest(
        "clickup", "ClickUp", "notify", "REST API v2 + webhook", ["two-way"], "API token",
        [F("url", "API URL", "url", default="https://api.clickup.com/api/v2"), F("api_token", "API token", "password", secret=True),
         F("team_id", "Team ID"), F("list_id", "List ID"), F("status_map", "Status mapping", "textarea", required=False)],
        ["notify", "webhook"], ["Test task created and deleted"], webhook=True,
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": self.secrets.get("api_token", "")}

    def test(self) -> list[CheckResult]:
        d = self.json("POST", f"/list/{self.cfg['list_id']}/task", headers=self._h(), json={"name": "SOC platform connection test"})
        self.request("DELETE", f"/task/{d['id']}", headers=self._h())
        return [CheckResult("Test task created and deleted", True)]

    def notify(self, subject: str, body: str, address: str) -> None:
        self.json("POST", f"/list/{address or self.cfg['list_id']}/task", headers=self._h(), json={"name": subject[:200], "description": body[:4000]})


@register
class Slack(Connector):
    manifest = Manifest(
        "slack", "Slack", "notify", "Incoming webhook", ["out"], "Webhook URL",
        [F("webhook_url", "Webhook URL", "url", secret=True, help="https://hooks.slack.com/... (outbound only)")],
        ["notify"], ["Test message sent"],
    )

    def notify(self, subject: str, body: str, address: str) -> None:
        url = self.secrets.get("webhook_url", "")
        if not url.startswith("https://hooks.slack.com/"):
            raise ConnectorError("webhook URL must be an https://hooks.slack.com/ address")
        r = self.client().post(url, json={"text": f"*{subject}*\n{body}"[:3500]})
        if r.status_code >= 400:
            raise ConnectorError(f"slack HTTP {r.status_code}")

    def test(self) -> list[CheckResult]:
        self.notify("SOC platform", "Connection test", "")
        return [CheckResult("Test message sent", True)]


@register
class Telegram(Connector):
    manifest = Manifest(
        "telegram", "Telegram", "notify", "Bot API", ["out"], "Bot token",
        [F("bot_token", "Bot token", "password", secret=True), F("chat_ids", "Chat IDs", "list")],
        ["notify"], ["Test message sent"],
    )

    def notify(self, subject: str, body: str, address: str) -> None:
        tok = self.secrets.get("bot_token", "")
        r = self.client().post(f"https://api.telegram.org/bot{tok}/sendMessage", json={"chat_id": address, "text": f"{subject}\n{body}"[:3800]})
        if r.status_code >= 400:
            raise ConnectorError(f"telegram HTTP {r.status_code}")

    def test(self) -> list[CheckResult]:
        chats = self.cfg.get("chat_ids") or []
        if not chats:
            raise ConnectorError("no chat IDs configured")
        self.notify("SOC platform", "Connection test", str(chats[0]))
        return [CheckResult("Test message sent", True)]


@register
class Email(Connector):
    manifest = Manifest(
        "email", "Email (SMTP)", "notify", "SMTP", ["out"], "SMTP credentials",
        [F("host", "SMTP host"), F("port", "Port", "number", default=587), F("username", "User", required=False),
         F("password", "Password", "password", required=False, secret=True), F("sender", "Sender address"), F("recipients", "Recipient groups", "list", required=False)],
        ["notify"], ["Test email sent"],
    )

    def notify(self, subject: str, body: str, address: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = str(self.cfg["sender"]), address, subject.replace("\n", " ")[:200]
        msg.set_content(body)
        try:
            with smtplib.SMTP(str(self.cfg["host"]), int(self.cfg.get("port", 587)), timeout=15) as s:
                s.starttls()
                if self.cfg.get("username"):
                    s.login(str(self.cfg["username"]), self.secrets.get("password", ""))
                s.send_message(msg)
        except (OSError, smtplib.SMTPException) as e:
            raise ConnectorError(f"smtp failed: {type(e).__name__}") from e

    def test(self) -> list[CheckResult]:
        to = (self.cfg.get("recipients") or [self.cfg.get("sender")])[0]
        self.notify("SOC platform test", "Connection test", str(to))
        return [CheckResult("Test email sent", True)]


@register
class KeycloakConn(Connector):
    manifest = Manifest(
        "keycloak", "Keycloak", "identity", "OIDC", ["login"], "Client ID + secret",
        [F("url", "Realm URL", "url"), F("client_id", "Client ID"), F("client_secret", "Client secret", "password", secret=True),
         F("role_mapping", "Role mapping", "textarea", required=False)],
        [], ["Login flow works"],
    )

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/.well-known/openid-configuration")
        if "authorization_endpoint" not in d:
            raise ConnectorError("not an OIDC discovery document")
        return [CheckResult("Login flow works", True, "discovery document valid")]


# ----------------------------------------------------------------------------- Threat intel enrichment
@register
class VirusTotal(Connector):
    manifest = Manifest(
        "virustotal", "VirusTotal", "intel", "REST API v3", ["action"], "API key",
        [F("url", "API URL", "url", default="https://www.virustotal.com/api/v3"), F("api_key", "API key", "password", secret=True)],
        ["enrich"], ["IP lookup returns"],
        setup_hint="API key from your VirusTotal account (Settings → API Key). Public-tier keys are rate-limited to 4 req/min.",
    )

    def _h(self) -> dict[str, str]:
        return {"x-apikey": self.secrets.get("api_key", "")}

    def test(self) -> list[CheckResult]:
        self.json("GET", "/ip_addresses/8.8.8.8", headers=self._h())
        return [CheckResult("IP lookup returns", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        path_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
        if itype == "url":
            vid = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            path = f"/urls/{vid}"
        else:
            path = f"/{path_map.get(itype, 'ip_addresses')}/{indicator}"
        d = self.json("GET", path, headers=self._h())
        attrs = d.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        return {"malicious": malicious, "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
                "verdict": "malicious" if malicious > 0 else "unknown", "stats": stats}


@register
class AbuseIpDb(Connector):
    manifest = Manifest(
        "abuseipdb", "AbuseIPDB", "intel", "REST API v2", ["action"], "API key",
        [F("url", "API URL", "url", default="https://api.abuseipdb.com/api/v2"), F("api_key", "API key", "password", secret=True)],
        ["enrich"], ["IP check returns"],
        setup_hint="API key from abuseipdb.com account settings. Only IP indicators are supported.",
    )

    def _h(self) -> dict[str, str]:
        return {"Key": self.secrets.get("api_key", ""), "Accept": "application/json"}

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/check", params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90}, headers=self._h())
        if "data" not in d:
            raise ConnectorError("unexpected response shape")
        return [CheckResult("IP check returns", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        if itype != "ip":
            raise ConnectorError("AbuseIPDB only supports IP indicators")
        d = self.json("GET", "/check", params={"ipAddress": indicator, "maxAgeInDays": 90}, headers=self._h())
        data = d.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {"abuse_score": score, "total_reports": data.get("totalReports", 0), "isp": data.get("isp"),
                "verdict": "malicious" if score >= 50 else ("suspicious" if score > 0 else "unknown")}


@register
class AlienVaultOtx(Connector):
    manifest = Manifest(
        "otx", "AlienVault OTX", "intel", "REST API", ["action"], "API key",
        [F("url", "API URL", "url", default="https://otx.alienvault.com/api/v1"), F("api_key", "API key", "password", secret=True)],
        ["enrich"], ["Indicator lookup returns"],
        setup_hint="API key from your OTX account page (otx.alienvault.com → Settings → API Integration).",
    )

    def _h(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": self.secrets.get("api_key", "")}

    def test(self) -> list[CheckResult]:
        self.json("GET", "/indicators/IPv4/8.8.8.8/general", headers=self._h())
        return [CheckResult("Indicator lookup returns", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        type_map = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}
        otx_type = type_map.get(itype, "IPv4")
        section = "analysis" if otx_type == "file" else "general"
        d = self.json("GET", f"/indicators/{otx_type}/{indicator}/{section}", headers=self._h())
        pulses = d.get("pulse_info", {}).get("count", 0)
        return {"pulse_count": pulses, "verdict": "malicious" if pulses > 0 else "unknown"}


@register
class OpenCti(Connector):
    manifest = Manifest(
        "opencti", "OpenCTI", "intel", "GraphQL API", ["action"], "API token (Bearer)",
        [URL, F("api_key", "API token", "password", secret=True), CA],
        ["enrich"], ["GraphQL introspection works"],
        setup_hint="Token from your OpenCTI user profile. Enrichment searches STIX cyber-observables by value.",
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.secrets.get('api_key', '')}", "Content-Type": "application/json"}

    def _gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        d = self.json("POST", "/graphql", headers=self._h(), json={"query": query, "variables": variables or {}})
        if d.get("errors"):
            raise ConnectorError(str(d["errors"])[:200])
        return d.get("data", {})

    def test(self) -> list[CheckResult]:
        self._gql("{ __typename }")
        return [CheckResult("GraphQL introspection works", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        query = """
        query ObservableSearch($search: String) {
          stixCyberObservables(search: $search, first: 5) {
            edges { node { id entity_type observable_value } }
          }
        }"""
        d = self._gql(query, {"search": indicator})
        edges = d.get("stixCyberObservables", {}).get("edges", [])
        return {"matches": len(edges), "verdict": "malicious" if edges else "unknown",
                "observables": [e["node"] for e in edges]}


@register
class Shodan(Connector):
    manifest = Manifest(
        "shodan", "Shodan", "intel", "REST API", ["action"], "API key",
        [F("url", "API URL", "url", default="https://api.shodan.io"), F("api_key", "API key", "password", secret=True)],
        ["enrich"], ["IP lookup returns"],
        setup_hint="API key from account.shodan.io. Only IP indicators are supported.",
    )

    def test(self) -> list[CheckResult]:
        self.json("GET", "/api-info", params={"key": self.secrets.get("api_key", "")})
        return [CheckResult("IP lookup returns", True)]

    def enrich(self, indicator: str, itype: str) -> dict[str, Any]:
        if itype != "ip":
            raise ConnectorError("Shodan only supports IP indicators")
        d = self.json("GET", f"/shodan/host/{indicator}", params={"key": self.secrets.get("api_key", "")})
        ports = d.get("ports", [])
        vulns = d.get("vulns", [])
        return {
            "ports": ports, "vulns": vulns, "os": d.get("os"), "org": d.get("org"),
            "isp": d.get("isp"), "country": d.get("country_code"),
            "verdict": "suspicious" if vulns else "unknown",
        }


# ----------------------------------------------------------------------------- Ops / ticketing / case
@register
class Grafana(Connector):
    manifest = Manifest(
        "grafana", "Grafana", "ops", "REST API", ["pull"], "Service account token (Bearer)",
        [URL, F("api_key", "Service account token", "password", secret=True), CA],
        ["status"], ["Health check returns"],
        setup_hint="Create a service-account token in Grafana (Administration → Service accounts) with Viewer scope.",
    )

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/api/health", headers=_bearer(self))
        if d.get("database") != "ok":
            raise ConnectorError("database not reported healthy")
        return [CheckResult("Health check returns", True, f"version {d.get('version', '?')}")]


@register
class Zammad(Connector):
    manifest = Manifest(
        "zammad", "Zammad", "notify", "REST API v1", ["two-way"], "API token",
        [URL, F("api_token", "API token", "password", secret=True), F("group", "Default group", default="Users"),
         F("default_customer", "Default customer email", required=False), CA],
        ["notify"], ["Current user returns"],
        setup_hint="Generate a personal API token under your Zammad profile → Token Access.",
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Token token={self.secrets.get('api_token', '')}"}

    def test(self) -> list[CheckResult]:
        d = self.json("GET", "/api/v1/users/me", headers=self._h())
        if "id" not in d:
            raise ConnectorError("unexpected response shape")
        return [CheckResult("Current user returns", True)]

    def notify(self, subject: str, body: str, address: str) -> None:
        customer = address or self.cfg.get("default_customer")
        self.json("POST", "/api/v1/tickets", headers=self._h(), json={
            "title": subject[:200], "group": self.cfg.get("group", "Users"), "customer": customer,
            "article": {"subject": subject[:200], "body": body, "type": "note", "internal": False},
        })


@register
class CustomTool(Connector):
    manifest = Manifest(
        "custom", "Custom tool", "ops", "Webhook (generic JSON)", ["push"], "Webhook secret (HMAC or Bearer, set after creation)",
        [F("description", "What this tool is", "textarea", required=False, help="Notes for other analysts; not sent anywhere.")],
        ["webhook"], ["Webhook endpoint ready"], webhook=True,
        setup_hint="Use this for any tool without a built-in connector. A webhook URL and secret are issued once you create it; "
                    "point the tool's outbound webhook/alert feed at that URL. Accepted JSON keys: title, severity, description, "
                    "host, src_ip, dst_ip, username, rule_id, mitre (list), time (ISO-8601). Unrecognised payloads are still "
                    "stored and visible in the tool's raw event log for mapping later.",
    )

    def test(self) -> list[CheckResult]:
        return [CheckResult("Webhook endpoint ready", True)]

    def parse_webhook(self, payload: dict[str, Any]) -> list[NormAlert]:
        sev = str(payload.get("severity", "low")).lower()
        if sev not in {"info", "low", "medium", "high", "critical"}:
            sev = "low"
        return [NormAlert(
            source_id=str(payload.get("id") or payload.get("source_id") or uuid.uuid4().hex[:24]),
            title=str(payload.get("title", "Custom tool alert"))[:300],
            severity=sev, time=_parse_ts(payload.get("time")) if payload.get("time") else None,
            description=str(payload.get("description", ""))[:2000], rule_id=str(payload.get("rule_id", "")),
            mitre=list(payload.get("mitre") or []), host=str(payload.get("host", "")), src_ip=str(payload.get("src_ip", "")),
            dst_ip=str(payload.get("dst_ip", "")), username=str(payload.get("username", "")), raw=payload,
        )]


# ----------------------------------------------------------------------------- Attack simulation / BAS
@register
class Caldera(Connector):
    manifest = Manifest(
        "caldera", "MITRE Caldera", "response", "REST API v2", ["pull", "action"], "API key",
        [F("url", "Base URL", "url", help="http://caldera:8888 for the Caldera bundled with the platform (docker compose profile `caldera`); otherwise https:// on an approved internal network"),
         F("api_key", "API key", "password", secret=True, help="api_key_red from Caldera's conf/local.yml"), F("group", "Default agent group", default="red")],
        ["action", "poll_findings"], ["API reachable"],
        setup_hint="Bundled Caldera: start it with the `caldera` compose profile, then use http://caldera:8888 and the api_key_red from its conf/local.yml. "
                   "Starting an adversary needs two approvals; stopping an operation runs at once.",
    )

    def request(self, method: str, path: str = "", *, url: str | None = None, **kw: Any) -> httpx.Response:
        """The bundled Caldera is reached over plain HTTP on the private Docker network, like Keycloak's admin API.
        Only that exact address is exempt from the HTTPS-only egress policy; any other URL goes through it."""
        internal = get_settings().caldera_internal_url.rstrip("/")
        target = url or f"{self.base_url()}{path}"
        if internal and self.base_url() == internal and (target == internal or target.startswith(internal + "/")):
            try:
                return self.client().request(method, target, **kw)
            except httpx.HTTPError as e:
                raise ConnectorError(f"request failed: {type(e).__name__}") from e
        return super().request(method, path, url=url, **kw)

    def _h(self) -> dict[str, str]:
        return {"KEY": self.secrets.get("api_key", ""), "Content-Type": "application/json"}

    def test(self) -> list[CheckResult]:
        self.json("GET", "/api/v2/health", headers=self._h())
        return [CheckResult("API reachable", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        if action_key == "run_adversary":
            body = {
                "name": params.get("operation_name", f"sim-{uuid.uuid4().hex[:8]}"),
                "adversary": {"adversary_id": params["adversary_id"]},
                "group": (targets[0] if targets else "") or params.get("group") or self.cfg.get("group", "red"),  # the target is the agent group
                "auto_close": True, "jitter": "2/8",
            }
            d = self.json("POST", "/api/v2/operations", headers=self._h(), json=body)
            return {"operation_id": d.get("id"), "name": d.get("name"), "state": d.get("state")}
        if action_key == "stop_operation":
            op_id = params.get("operation_id") or (targets[0] if targets else "")
            d = self.json("PATCH", f"/api/v2/operations/{op_id}", headers=self._h(), json={"state": "cleanup"})
            return {"operation_id": op_id, "state": d.get("state")}
        raise ConnectorError(f"unsupported action: {action_key}")

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        ops = self.json("GET", "/api/v2/operations", headers=self._h())
        findings: list[dict[str, Any]] = []
        for op in (ops if isinstance(ops, list) else []):
            op_id = op.get("id", "")
            if op.get("state") != "finished":
                continue
            for link in op.get("chain", []):
                findings.append({
                    "id": f"caldera-{op_id}-{link.get('id', '')}",
                    "operation": op.get("name"), "operation_id": op_id,
                    "technique_id": link.get("ability", {}).get("technique_id", ""),
                    "technique_name": link.get("ability", {}).get("technique_name", ""),
                    "tactic": link.get("ability", {}).get("tactic", ""),
                    "status": "success" if link.get("status", -1) == 0 else "failed",
                    "host": link.get("host", ""), "pid": link.get("pid"),
                    "visibility": link.get("visibility", {}).get("score", 0),
                })
        return PollResult(findings=findings, checkpoint=checkpoint)


@register
class AtomicRedTeam(Connector):
    manifest = Manifest(
        "atomic_red_team", "Atomic Red Team", "response", "Invoke-AtomicTest via API", ["pull", "action"], "API key",
        [URL, F("api_key", "API key", "password", secret=True)],
        ["action", "poll_findings"], ["API reachable"],
        setup_hint="Requires an Atomic Red Team execution server (invoke-atomicredteam wrapper). Supports running individual techniques and collecting results.",
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.secrets.get('api_key', '')}", "Content-Type": "application/json"}

    def test(self) -> list[CheckResult]:
        self.json("GET", "/api/health", headers=self._h())
        return [CheckResult("API reachable", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        if action_key == "run_atomic":
            body = {
                "technique_id": params["technique_id"],
                "test_numbers": params.get("test_numbers", []),
                "hostname": targets[0] if targets else "",
                "cleanup": params.get("cleanup", True),
            }
            d = self.json("POST", "/api/execute", headers=self._h(), json=body)
            return {"execution_id": d.get("id"), "technique_id": params["technique_id"], "status": d.get("status")}
        if action_key == "cleanup_atomic":
            d = self.json("POST", f"/api/cleanup/{params.get('execution_id', '')}", headers=self._h())
            return {"status": d.get("status", "cleaned")}
        raise ConnectorError(f"unsupported action: {action_key}")

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        d = self.json("GET", "/api/results", headers=self._h(), params={"limit": limit})
        findings = []
        for r in (d if isinstance(d, list) else d.get("results", [])):
            findings.append({
                "id": f"art-{r.get('id', '')}",
                "technique_id": r.get("technique_id", ""),
                "technique_name": r.get("technique_name", ""),
                "test_name": r.get("test_name", ""),
                "status": r.get("status", "unknown"),
                "hostname": r.get("hostname", ""),
                "output": str(r.get("output", ""))[:2000],
                "detected": r.get("detected", False),
                "detection_time_seconds": r.get("detection_time_seconds"),
            })
        return PollResult(findings=findings, checkpoint=checkpoint)


@register
class AttackSimulator(Connector):
    manifest = Manifest(
        "attack_simulator", "Custom BAS", "response", "REST API", ["pull", "action"], "API key",
        [URL, F("api_key", "API key", "password", secret=True), F("platform_name", "Platform name", default="BAS")],
        ["action", "poll_findings"], ["API reachable"],
        setup_hint="Generic Breach and Attack Simulation connector. Works with SafeBreach, AttackIQ, Picus, or any BAS with a REST API.",
    )

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.secrets.get('api_key', '')}", "Content-Type": "application/json"}

    def test(self) -> list[CheckResult]:
        self.json("GET", "/api/v1/status", headers=self._h())
        return [CheckResult("API reachable", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        if action_key == "run_simulation":
            body = {"scenario_id": params.get("scenario_id"), "targets": targets, "options": params.get("options", {})}
            d = self.json("POST", "/api/v1/simulations/run", headers=self._h(), json=body)
            return {"simulation_id": d.get("id"), "status": d.get("status")}
        if action_key == "stop_simulation":
            sim_id = params.get("simulation_id") or (targets[0] if targets else "")
            d = self.json("POST", f"/api/v1/simulations/{sim_id}/stop", headers=self._h())
            return {"simulation_id": sim_id, "status": d.get("status")}
        raise ConnectorError(f"unsupported action: {action_key}")

    def poll(self, checkpoint: dict[str, Any], limit: int = 500) -> PollResult:
        d = self.json("GET", "/api/v1/simulations/results", headers=self._h(), params={"limit": limit})
        findings = []
        for r in (d if isinstance(d, list) else d.get("results", [])):
            findings.append({
                "id": f"bas-{r.get('id', '')}",
                "simulation_id": r.get("simulation_id", ""),
                "scenario": r.get("scenario_name", ""),
                "technique_id": r.get("technique_id", ""),
                "attack_type": r.get("attack_type", ""),
                "status": r.get("status", "unknown"),
                "detected": r.get("detected", False),
                "blocked": r.get("blocked", False),
                "detection_coverage": r.get("detection_coverage", 0),
                "mean_time_to_detect": r.get("mttd_seconds"),
            })
        return PollResult(findings=findings, checkpoint=checkpoint)
