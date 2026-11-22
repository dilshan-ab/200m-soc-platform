"""Velociraptor and OpenVAS/GVM connectors, exercised against the real pyvelociraptor / python-gvm libraries
with the network layer faked (no live servers). Skipped when the optional `connectors` extra is not installed."""
from __future__ import annotations

import json
import re
import ssl
from contextlib import contextmanager
from datetime import timedelta

import pytest
import yaml

from app import db as dbmod
from app.connectors.base import ConnectorError, get_connector_cls
from app.models import Asset, Finding, utcnow
from tests.helpers import mk_tool

grpc = pytest.importorskip("grpc")
pytest.importorskip("pyvelociraptor")
pytest.importorskip("gvm")
from pyvelociraptor import api_pb2  # noqa: E402

# --------------------------------------------------------------------------- Velociraptor
API_CONFIG = yaml.safe_dump({"ca_certificate": "CA", "client_cert": "CERT", "client_private_key": "KEY", "api_connection_string": "10.0.0.5:8001"})


class FakeRpcError(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.UNAVAILABLE


@pytest.fixture
def velo(monkeypatch):
    """Patch the gRPC layer; `calls` records every VQLCollectorArgs sent."""
    state = {"calls": [], "clients": [], "flow": {"Flow": {"flow_id": "F.123"}}, "fail": False}

    class Stub:
        def __init__(self, channel):
            pass

        def Query(self, request, timeout=None):  # noqa: N802
            state["calls"].append(request)
            if state["fail"]:
                raise FakeRpcError()
            vql = request.Query[0].VQL
            rows = state["clients"] if "FROM clients" in vql else [state["flow"]] if "collect_client" in vql else [{"Hostname": "velo-server"}]
            return iter([api_pb2.VQLResponse(Response=json.dumps(rows))])

    @contextmanager
    def channel(*a, **k):
        yield object()

    monkeypatch.setattr(grpc, "secure_channel", lambda *a, **k: channel())
    monkeypatch.setattr("pyvelociraptor.api_pb2_grpc.APIStub", Stub)
    return state


def _velo(cfg=None, secrets=None):
    return get_connector_cls("velociraptor")({"allowed_artifacts": ["Windows.System.Pslist"], **(cfg or {})}, secrets if secrets is not None else {"api_config": API_CONFIG})


def _env(call):
    return {e.key: e.value for e in call.env}


def test_velociraptor_test_connection(velo):
    res = _velo().test()
    assert res[0].ok and res[0].detail == "velo-server"
    assert velo["calls"][0].Query[0].VQL == "SELECT * FROM info()"


def test_isolate_and_release_use_env_not_interpolation(velo):
    velo["clients"] = [{"client_id": "C.abc", "os": "windows", "hostname": "WS-01", "fqdn": "ws-01.corp.local"}]
    out = _velo().execute("isolate_host", ["ws-01"], {})
    assert out == {"hosts": {"ws-01": {"client_id": "C.abc", "flow_id": "F.123"}}}
    search, collect = velo["calls"]
    assert _env(search) == {"Search": "host:ws-01"} and "ws-01" not in search.Query[0].VQL
    env = _env(collect)
    assert env["ClientId"] == "C.abc" and env["Artifact"] == "Windows.Remediation.Quarantine" and json.loads(env["ArtifactParams"]) == {"RemovePolicy": "N"}
    assert "C.abc" not in collect.Query[0].VQL
    velo["calls"].clear()
    _velo().execute("release_host", ["ws-01"], {})
    assert json.loads(_env(velo["calls"][1])["ArtifactParams"]) == {"RemovePolicy": "Y"}


def test_collect_artifact_passes_params(velo):
    velo["clients"] = [{"client_id": "C.abc", "os": "linux", "hostname": "web1", "fqdn": ""}]
    _velo().execute("collect_artifact", ["web1"], {"artifact": "Windows.System.Pslist", "artifact_params": {"ProcessRegex": "evil"}})
    env = _env(velo["calls"][1])
    assert env["Artifact"] == "Windows.System.Pslist" and json.loads(env["ArtifactParams"]) == {"ProcessRegex": "evil"}


@pytest.mark.parametrize("clients,match", [
    ([], "no Velociraptor client found"),
    ([{"client_id": "C.1", "os": "windows", "hostname": "dup"}, {"client_id": "C.2", "os": "windows", "hostname": "DUP"}], "refusing to guess"),
    ([{"client_id": "C.1", "os": "darwin", "hostname": "dup"}], "not supported for darwin"),
])
def test_isolate_refuses_bad_matches(velo, clients, match):
    velo["clients"] = clients
    with pytest.raises(ConnectorError, match=match):
        _velo().execute("isolate_host", ["dup"], {})


def test_velociraptor_input_validation_happens_before_network(velo):
    with pytest.raises(ConnectorError, match="invalid host name"):
        _velo().execute("isolate_host", ['x"; SELECT * FROM info() --'], {})
    with pytest.raises(ConnectorError, match="allow-list"):
        _velo().execute("collect_artifact", ["h"], {"artifact": "Generic.Client.Shell"})
    with pytest.raises(ConnectorError, match="invalid artifact name"):
        _velo({"allowed_artifacts": ["bad name"]}).execute("collect_artifact", ["h"], {"artifact": "bad name"})
    with pytest.raises(ConnectorError, match="kill_process is not supported"):
        _velo().execute("kill_process", ["h"], {})
    assert velo["calls"] == []


def test_velociraptor_config_egress_and_transport_errors(velo):
    with pytest.raises(ConnectorError, match="missing: ca_certificate"):
        _velo(secrets={"api_config": yaml.safe_dump({"client_cert": "x", "client_private_key": "y", "api_connection_string": "10.0.0.5:8001"})}).test()
    with pytest.raises(ConnectorError, match="egress policy"):
        _velo(secrets={"api_config": yaml.safe_dump({**yaml.safe_load(API_CONFIG), "api_connection_string": "8.8.8.8:8001"})}).test()
    velo["fail"] = True
    with pytest.raises(ConnectorError, match="^request failed: UNAVAILABLE"):  # response engine maps this to outcome_unknown
        _velo().test()


def test_velociraptor_partial_failure_reports_both(velo):
    velo["clients"] = [{"client_id": "C.1", "os": "windows", "hostname": "good"}]
    with pytest.raises(ConnectorError, match=r"failed for missing: no Velociraptor client found.*succeeded for good"):
        _velo().execute("isolate_host", ["good", "missing"], {})


# --------------------------------------------------------------------------- OpenVAS / GVM
def _resp(tag, status="200", inner="", **attrs):
    extra = "".join(f' {k}="{v}"' for k, v in attrs.items())
    return f'<{tag}_response status="{status}" status_text="OK"{extra}>{inner}</{tag}_response>'


RESULT = """<result id="r1"><name>OpenSSL flaw</name><modification_time>{ts}</modification_time>
<host>10.1.1.5<asset asset_id="a"/><hostname>srv-01</hostname></host><port>443/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>x</name><refs><ref type="url" id="http://x"/><ref type="cve" id="CVE-2024-1111"/></refs></nvt>
<severity>9.8</severity><threat>Critical</threat></result>"""
RESULT2 = """<result id="r2"><name>Weak cipher</name><modification_time>{ts}</modification_time><host>10.1.1.6</host><port>general/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.2"><refs/></nvt><severity>4.3</severity></result>"""


@pytest.fixture
def gvm(monkeypatch):
    """A fake gvmd behind the real python-gvm GMP class. `sent` logs command tags; `replies` maps tag -> XML."""
    from gvm.connections import GvmConnection  # noqa: F401  (typing protocol)

    state: dict = {"sent": [], "replies": {
        "get_version": _resp("get_version", inner="<version>22.7</version>"),
        "authenticate": _resp("authenticate"),
        "get_tasks": _resp("get_tasks", inner="<task/><task_count>7</task_count>"),
    }}

    class FakeConn:
        def __init__(self):
            self.last = ""

        def connect(self):
            pass

        def disconnect(self):
            pass

        def finish_send(self):
            pass

        def send(self, data):
            tag = re.match(r"<(\w+)", data.decode()).group(1)
            state["sent"].append((tag, data.decode()))
            self.last = tag

        def read(self):
            return state["replies"][self.last].encode()

    monkeypatch.setattr(get_connector_cls("openvas"), "_connection", lambda self: FakeConn())
    return state


def _gvm(cfg=None, secrets=None):
    return get_connector_cls("openvas")({"host": "10.0.0.9", "username": "u", "allowed_scan_configs": ["Full and fast"], **(cfg or {})}, secrets or {"password": "pw"})


def test_openvas_test_connection_and_auth_failure(gvm):
    res = _gvm().test()
    assert res[0].ok and "GMP 22.7" in res[0].detail and "7 tasks" in res[0].detail
    assert [t for t, _ in gvm["sent"]][:2] == ["get_version", "authenticate"]
    gvm["replies"]["authenticate"] = _resp("authenticate", status="400")
    with pytest.raises(ConnectorError, match="authentication failed"):
        _gvm().test()


def test_openvas_poll_normalises_and_checkpoints(gvm):
    now = utcnow()
    gvm["replies"]["get_results"] = _resp("get_results", inner=RESULT.format(ts=now.isoformat()) + RESULT2.format(ts=(now - timedelta(hours=1)).isoformat()))
    res = _gvm().poll({})
    by_id = {f["vuln_id"]: f for f in res.findings}
    f = by_id["CVE-2024-1111"]
    assert (f["severity"], f["cvss"], f["ip"], f["hostname"], f["component"]) == ("critical", 9.8, "10.1.1.5", "srv-01", "443/tcp")
    assert by_id["1.3.6.1.4.1.25623.1.0.2"]["severity"] == "medium"  # no CVE, falls back to the NVT oid
    assert res.checkpoint["last_modified"].startswith(now.isoformat()[:19])
    assert _gvm().poll(res.checkpoint).findings == []  # nothing newer than the checkpoint


def test_openvas_run_scan_creates_target_task_and_starts(gvm):
    gvm["replies"].update({
        "get_configs": _resp("get_configs", inner='<config id="cfg-1"><name>Full and fast</name></config><config id="cfg-2"><name>Other</name></config>'),
        "get_scanners": _resp("get_scanners", inner='<scanner id="sc-1"><name>CVE</name></scanner><scanner id="sc-2"><name>OpenVAS Default</name></scanner>'),
        "get_port_lists": _resp("get_port_lists", inner='<port_list id="pl-1"><name>All IANA assigned TCP</name></port_list>'),
        "create_target": _resp("create_target", status="201", id="tg-1"),
        "create_task": _resp("create_task", status="201", id="tk-1"),
        "start_task": _resp("start_task", status="202", inner="<report_id>rep-1</report_id>"),
    })
    out = _gvm().execute("run_scan", ["10.1.1.5", "10.2.0.0/24", "srv-02.corp.local"], {"scan_config": "Full and fast"})
    assert out == {"task_id": "tk-1", "target_id": "tg-1", "report_id": "rep-1", "scan_config": "Full and fast"}
    sent = dict(gvm["sent"])
    assert "sc-2" in sent["create_task"] and "cfg-1" in sent["create_task"] and "tg-1" in sent["create_task"]  # picked "OpenVAS Default", not the first scanner
    assert "10.2.0.0/24" in sent["create_target"] and "pl-1" in sent["create_target"]


def test_openvas_run_scan_cleans_up_when_task_creation_fails(gvm):
    gvm["replies"].update({
        "get_configs": _resp("get_configs", inner='<config id="cfg-1"><name>Full and fast</name></config>'),
        "get_scanners": _resp("get_scanners", inner='<scanner id="sc-1"><name>OpenVAS Default</name></scanner>'),
        "get_port_lists": _resp("get_port_lists", inner='<port_list id="pl-1"><name>All IANA assigned TCP</name></port_list>'),
        "create_target": _resp("create_target", status="201", id="tg-1"),
        "create_task": _resp("create_task", status="400"),
        "delete_target": _resp("delete_target"),
    })
    with pytest.raises(ConnectorError):
        _gvm().execute("run_scan", ["10.1.1.5"], {"scan_config": "Full and fast"})
    assert "delete_target" in [t for t, _ in gvm["sent"]]


def test_openvas_run_scan_validation_happens_before_network(gvm):
    for params, targets, match in [
        ({"scan_config": "Discovery"}, ["10.1.1.5"], "allow-list"),
        ({"scan_config": "Full and fast"}, [], "scan targets"),
        ({"scan_config": "Full and fast"}, ["10.1.1.5; rm -rf /"], "invalid scan target"),
        ({"scan_config": "Full and fast"}, [f"10.0.0.{i}" for i in range(65)], "scan targets"),
    ]:
        with pytest.raises(ConnectorError, match=match):
            _gvm().execute("run_scan", targets, params)
    with pytest.raises(ConnectorError, match="unsupported"):
        _gvm().execute("stop_scan", ["x"], {})
    assert gvm["sent"] == []


def test_openvas_tls_is_verified_against_pinned_ca(monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from gvm.connections import TLSConnection, UnixSocketConnection

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gvm-ca")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(utcnow() - timedelta(days=1)).not_valid_after(utcnow() + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    c = get_connector_cls("openvas")({"host": "10.0.0.9", "port": 9390, "ca_cert": pem}, {})
    conn = c._connection()
    assert isinstance(conn, TLSConnection)
    sock = conn._new_socket()
    try:
        assert sock.context.verify_mode == ssl.CERT_REQUIRED and sock.context.minimum_version >= ssl.TLSVersion.TLSv1_2
    finally:
        sock.close()
    with pytest.raises(ConnectorError, match="CA certificate is required"):
        get_connector_cls("openvas")({"host": "10.0.0.9"}, {})._connection()
    with pytest.raises(ConnectorError, match="egress policy"):
        get_connector_cls("openvas")({"host": "8.8.8.8", "ca_cert": pem}, {})._connection()
    assert isinstance(get_connector_cls("openvas")({"host": "/run/gvmd/gvmd.sock"}, {})._connection(), UnixSocketConnection)


# --------------------------------------------------------------------------- findings ingest
def _asset(name, ips=(), client_id=None, hostname=""):
    with dbmod.session_scope() as db:
        a = Asset(name=name, hostname=hostname or name, ips=list(ips), client_id=client_id)
        db.add(a)
        db.flush()
        return a.id


def _finding(**kw):
    base = {"vuln_id": "CVE-2024-1111", "title": "OpenSSL flaw", "severity": "critical", "cvss": 9.8, "component": "443/tcp", "ip": "10.1.1.5", "hostname": ""}
    return {**base, **kw}


def test_upsert_findings_matches_by_hostname_or_ip_and_refreshes(clients):
    from app.models import Tool
    from app.services import ingest

    by_host = _asset("srv-01", client_id=clients[0])
    by_ip = _asset("db-01", ips=["10.1.1.5"], client_id=clients[0])
    tool_id = mk_tool("openvas", "GVM", cfg={"host": "10.0.0.9"})
    with dbmod.session_scope() as db:
        tool = db.get(Tool, tool_id)
        n = ingest.upsert_findings(db, tool, [_finding(hostname="srv-01", ip=""), _finding(), _finding(ip="10.9.9.9"), {"technique_id": "T1059"}])
    assert n == 2  # unknown host and non-vuln items skipped
    with dbmod.session_scope() as db:
        rows = {f.asset_id: f for f in db.query(Finding).all()}
        assert set(rows) == {by_host, by_ip} and rows[by_ip].sources == ["openvas"] and rows[by_ip].client_id == clients[0]
        rows[by_ip].status = "remediated"
    with dbmod.session_scope() as db:
        tool = db.get(Tool, tool_id)
        ingest.upsert_findings(db, tool, [_finding(severity="high", cvss=7.5, title="OpenSSL flaw v2")])
    with dbmod.session_scope() as db:
        f = db.query(Finding).filter(Finding.asset_id == by_ip).one()
        assert (f.status, f.severity, f.cvss, f.title) == ("open", "high", 7.5, "OpenSSL flaw v2")  # re-seen after remediation reopens it
        assert db.query(Finding).count() == 2  # updated in place, not duplicated


def test_upsert_findings_respects_tool_client_scope(clients):
    from app.models import Tool
    from app.services import ingest

    _asset("other-tenant", ips=["10.1.1.5"], client_id=clients[1])
    tool_id = mk_tool("openvas", "GVM scoped", cfg={"host": "10.0.0.9", "client_id": clients[0]})
    with dbmod.session_scope() as db:
        assert ingest.upsert_findings(db, db.get(Tool, tool_id), [_finding()]) == 0
        assert db.query(Finding).count() == 0


def test_poll_tool_ingests_findings_end_to_end(gvm, clients):
    from app.models import Tool
    from app.services import polling

    _asset("srv-01", ips=["10.1.1.5"], client_id=clients[0])
    gvm["replies"]["get_results"] = _resp("get_results", inner=RESULT.format(ts=utcnow().isoformat()))
    tool_id = mk_tool("openvas", "GVM poll", cfg={"host": "10.0.0.9", "username": "u"}, secrets={"password": "pw"})
    with dbmod.session_scope() as db:
        out = polling.poll_tool(db, db.get(Tool, tool_id))
    assert out["ok"] and out["findings"] == 1
    with dbmod.session_scope() as db:
        f = db.query(Finding).one()
        assert f.vuln_id == "CVE-2024-1111" and f.severity == "critical" and f.component == "443/tcp"
        assert db.get(Tool, tool_id).state.checkpoint["last_modified"]


def test_openvas_manifest_exposes_ca_field():
    assert any(f.name == "ca_cert" for f in get_connector_cls("openvas").manifest.fields)
