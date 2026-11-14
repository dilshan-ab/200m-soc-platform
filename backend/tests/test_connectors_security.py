from __future__ import annotations

import httpx
import pytest

from app import security
from app.connectors.base import ConnectorError, get_connector_cls
from app.security import SecurityError, validate_egress_url
from tests.helpers import jresp, mock_http


@pytest.mark.parametrize("url", [
    "http://wazuh.corp.local:9200",  # plain http
    "https://169.254.169.254/latest/meta-data",  # cloud metadata
    "https://127.0.0.1:9200",
    "https://8.8.8.8/",  # public literal
    "https://user:pw@wazuh.corp.local/",  # credentials in URL
    "ftp://wazuh.corp.local/",
    "file:///etc/passwd",
    "https:///nohost",
])
def test_egress_blocks_unsafe_urls(url):
    with pytest.raises(SecurityError):
        validate_egress_url(url)


def test_egress_allows_internal(monkeypatch):
    assert validate_egress_url("https://wazuh.corp.local:9200/x")
    assert validate_egress_url("https://10.1.2.3:9200")
    monkeypatch.setattr(security, "_default_resolve", lambda h: ["8.8.8.8"])
    with pytest.raises(SecurityError):
        validate_egress_url("https://evil.example.com")  # not an approved domain, resolves public
    monkeypatch.setattr(security, "_default_resolve", lambda h: ["169.254.169.254"])
    with pytest.raises(SecurityError):
        validate_egress_url("https://sneaky.corp.local")  # approved suffix but DNS points at metadata


def test_connector_requests_pass_through_egress_policy():
    mock_http(lambda r: jresp({}))
    c = get_connector_cls("thehive")({"url": "https://169.254.169.254"}, {"api_key": "k"})
    with pytest.raises(ConnectorError, match="egress"):
        c.test()


def test_connectors_report_errors_without_leaking_secrets():
    mock_http(lambda r: httpx.Response(401, text="bad key SECRETVALUE"))
    c = get_connector_cls("cortex")({"url": "https://cortex.corp.local"}, {"api_key": "SECRETVALUE"})
    with pytest.raises(ConnectorError) as e:
        c.test()
    assert "SECRETVALUE" not in str(e.value)


def test_thehive_create_case_and_misp_enrich():
    seen = {}

    def handler(r: httpx.Request):
        seen[r.url.path] = r.headers.get("authorization")
        if r.url.path == "/api/v1/case":
            return jresp({"_id": "~123"})
        return jresp({"response": {"Attribute": [{"event_id": "7"}, {"event_id": "7"}]}})

    mock_http(handler)
    th = get_connector_cls("thehive")({"url": "https://hive.corp.local"}, {"api_key": "k1"})
    assert th.create_case({"title": "t", "severity": "high"}) == "~123"
    assert seen["/api/v1/case"] == "Bearer k1"
    mp = get_connector_cls("misp")({"url": "https://misp.corp.local"}, {"auth_key": "mk"})
    r = mp.enrich("1.2.3.4", "ip")
    assert r["verdict"] == "malicious" and r["events"] == ["7"]


def test_action_allowlists_enforced():
    mock_http(lambda r: jresp({}))
    with pytest.raises(ConnectorError, match="allow-list"):
        get_connector_cls("opsi")({"url": "https://opsi.corp.local", "allowed_products": ["a"]}, {"password": "p"}).execute("deploy_patch", ["h"], {"product": "evil"})
    with pytest.raises(ConnectorError, match="not exposed"):
        get_connector_cls("shuffle")({"url": "https://s.corp.local", "exposed_workflows": ["wf1"]}, {"api_key": "k"}).execute("run_playbook", ["h"], {"workflow": "wf2"})
    with pytest.raises(ConnectorError, match="allow-list"):
        get_connector_cls("bareos")({"url": "https://b.corp.local", "allowed_jobs": ["j"]}, {"password": "p"}).execute("run_backup", [], {"job": "other"})
    with pytest.raises(ConnectorError, match="allow-list"):
        get_connector_cls("velociraptor")({"allowed_artifacts": ["Windows.Sys.Pslist"]}, {}).execute("collect_artifact", ["h"], {"artifact": "Generic.Client.Shell"})


def test_slack_rejects_non_slack_urls():
    c = get_connector_cls("slack")({}, {"webhook_url": "https://attacker.example/steal"})
    with pytest.raises(ConnectorError):
        c.notify("s", "b", "")


def test_all_manifests_complete():
    from app.connectors.base import all_manifests

    ms = all_manifests()
    assert len(ms) == 28
    for m in ms:
        assert m.fields and m.test_checks is not None and m.link_method and m.direction
        assert all(not (f.secret and f.default) for f in m.fields)
