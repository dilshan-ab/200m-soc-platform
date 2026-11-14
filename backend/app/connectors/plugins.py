"""Tool plugins. Each declares a manifest and implements the capabilities it advertises."""
from __future__ import annotations

import base64
import smtplib
import uuid
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

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
        q: dict[str, Any] = {"range": {"timestamp": {"gte": ts}}} if ts else {"match_all": {}}
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


@register
class Velociraptor(Connector):
    manifest = Manifest(
        "velociraptor", "Velociraptor", "response", "gRPC API", ["pull", "action"], "API client certificate (YAML)",
        [F("api_config", "API client config (portal_api.yaml)", "file", secret=True), F("allowed_artifacts", "Allowed artifacts", "list", required=False)],
        ["action"], ["SELECT * FROM info() returns"],
    )

    def _query(self, vql: str) -> list[dict[str, Any]]:
        try:
            import pyvelociraptor  # type: ignore[import-not-found]  # noqa: F401
        except ImportError as e:
            raise ConnectorError("pyvelociraptor is not installed on this node") from e
        raise ConnectorError("gRPC channel not available in this environment")  # pragma: no cover

    def test(self) -> list[CheckResult]:
        self._query("SELECT * FROM info()")
        return [CheckResult("SELECT * FROM info() returns", True)]

    def execute(self, action_key: str, targets: list[str], params: dict[str, Any]) -> dict[str, Any]:
        allowed = set(self.cfg.get("allowed_artifacts") or [])
        if action_key == "collect_artifact" and params.get("artifact") not in allowed:
            raise ConnectorError("artifact not on allow-list")
        vql = {"isolate_host": "quarantine", "release_host": "unquarantine", "kill_process": "kill", "collect_artifact": "collect"}.get(action_key)
        if vql is None:
            raise ConnectorError(f"unsupported action {action_key}")
        self._query(f"/* {vql} */")
        return {}  # pragma: no cover


@register
class OpenVas(Connector):
    manifest = Manifest(
        "openvas", "OpenVAS / GVM", "vuln", "GMP (python-gvm)", ["pull", "action"], "GVM user",
        [F("host", "Host or socket path"), F("port", "Port", "number", required=False, default=9390), F("username", "User"),
         F("password", "Password", "password", secret=True), F("allowed_scan_configs", "Allowed scan configs", "list", required=False)],
        ["poll_findings", "action"], ["Version + task list returned"],
    )

    def _gmp(self) -> Any:
        try:
            from gvm.connections import TLSConnection  # type: ignore[import-not-found]  # noqa: F401
        except ImportError as e:
            raise ConnectorError("python-gvm is not installed on this node") from e
        raise ConnectorError("GMP connection unavailable in this environment")  # pragma: no cover

    def test(self) -> list[CheckResult]:
        self._gmp()
        return []  # pragma: no cover


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
