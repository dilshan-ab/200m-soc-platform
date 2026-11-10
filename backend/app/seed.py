"""Default data (SLA, templates, retention, runbook guides) and an optional demo dataset (non-production only)."""
from __future__ import annotations

import random
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import (
    Alert,
    Asset,
    BackupJob,
    CaseTemplate,
    Client,
    ClientMembership,
    ControlResult,
    Finding,
    RetentionPolicy,
    Runbook,
    Server,
    User,
    utcnow,
)
from .security import hash_password, new_totp_secret
from .sla import active_policy

TEMPLATES = [
    ("Malware / EDR detection", "high", ["Isolate host (request approval)", "Collect triage artifacts", "Identify patient zero and spread", "Eradicate and verify clean", "Restore and monitor 72h", "Lessons learned"]),
    ("Phishing", "medium", ["Retrieve and analyse message", "Search mailboxes for same sender/URL", "Block sender/URL/domain", "Reset affected credentials", "User notification"]),
    ("Brute force / account compromise", "high", ["Confirm source and success of logins", "Block source IP (request approval)", "Force password reset and revoke sessions", "Review account activity", "Close and document"]),
    ("Vulnerability exploitation", "high", ["Confirm affected assets", "Apply mitigation or patch (request approval)", "Rescan to verify", "Document exception if not patched"]),
    ("Server outage", "critical", ["Confirm outage cause", "Notify stakeholders", "Restore service", "Verify monitoring recovered", "Post-incident review"]),
]
GUIDES = ["alert-triage", "false-positive-tuning", "malware-response", "phishing-response", "account-compromise", "vulnerability-management", "server-down", "backup-restore-test", "onboarding-a-server"]


def seed_defaults(db: Session) -> None:
    active_policy(db)
    for name, sev, tasks in TEMPLATES:
        if db.execute(select(CaseTemplate.id).where(CaseTemplate.name == name)).first() is None:
            db.add(CaseTemplate(name=name, severity=sev, description=name, tasks=[{"title": t, "required": True} for t in tasks]))
    for ds, days in (("alerts", 90), ("cases", 365), ("audit", 365), ("raw_events", 90), ("reports", 90)):
        if db.execute(select(RetentionPolicy.id).where(RetentionPolicy.dataset == ds)).first() is None:
            db.add(RetentionPolicy(dataset=ds, days=days))
    for slug in GUIDES:
        if db.execute(select(Runbook.id).where(Runbook.slug == slug)).first() is None:
            title = slug.replace("-", " ").title()
            db.add(Runbook(slug=slug, title=title, kind="guide", status="published", body=f"# {title}\n\nOperator guide. Edit this runbook to match your procedure.", created_by="system"))
    db.flush()


def seed_demo(db: Session) -> dict[str, str]:
    """Populate demo data and dev users. Returns TOTP secrets for the dev logins."""
    s = get_settings()
    if s.environment == "production":
        raise RuntimeError("demo seed is disabled in production")
    seed_defaults(db)
    secrets: dict[str, str] = {}
    if db.execute(select(func.count()).select_from(User)).scalar_one() == 0 and s.auth_mode == "dev":
        for email, role, allc in (("admin@demo.local", "admin", True), ("admin2@demo.local", "admin", True), ("l2@demo.local", "l2", True), ("l1@demo.local", "l1", False), ("viewer@demo.local", "viewer", False)):
            sec = new_totp_secret()
            db.add(User(subject=f"dev:{email}", email=email, name=email.split("@")[0].upper(), role=role, all_clients=allc, password_hash=hash_password("Demo-Passw0rd!"), totp_secret=sec))
            secrets[email] = sec
        db.flush()
    if db.execute(select(func.count()).select_from(Client)).scalar_one() == 0:
        c1, c2 = Client(name="Contoso BPO", code="CONTOSO"), Client(name="Fabrikam Support", code="FABRIKAM")
        db.add_all([c1, c2])
        db.flush()
        l1 = db.execute(select(User).where(User.email == "l1@demo.local")).scalar_one_or_none()
        if l1:
            db.add(ClientMembership(user_id=l1.id, client_id=c1.id))
        srvs = [Server(name="Server 1 (Detection)", host="10.0.0.11", role="soc_core", criticality="critical", os="Ubuntu 24.04", status="up", coverage={"wazuh_agent": True, "uptime_kuma": True, "prometheus_exporter": True}),
                Server(name="Server 2 (Response)", host="10.0.0.12", role="soc_core", criticality="critical", os="Ubuntu 24.04", status="up", coverage={"wazuh_agent": True, "uptime_kuma": True}),
                Server(name="PM-Tool", host="10.0.1.21", role="monitored", criticality="high", os="Ubuntu 22.04", status="up", client_id=c1.id, coverage={"wazuh_agent": True, "uptime_kuma": True, "bareos_job": True}),
                Server(name="Sys200", host="10.0.1.22", role="monitored", criticality="medium", os="Windows Server 2022", status="degraded", client_id=c2.id, coverage={"wazuh_agent": True})]
        db.add_all(srvs)
        rnd = random.Random(7)
        assets = []
        for i in range(24):
            cl = c1 if i % 2 == 0 else c2
            assets.append(Asset(name=f"ws-{i:03d}", hostname=f"ws-{i:03d}", ips=[f"10.20.{i // 8}.{10 + i}"], os="Windows 11", kind="workstation", agent_id=f"{i + 1:03d}", agent_status="active" if i % 7 else "disconnected", client_id=cl.id, department=["Support", "Billing", "IT"][i % 3], last_seen=utcnow() - timedelta(minutes=rnd.randint(1, 90)), sca_score=rnd.uniform(55, 95)))
        db.add_all(assets)
        db.flush()
        titles = [("Multiple authentication failures", "5710", "medium"), ("Possible ransomware activity", "92200", "critical"), ("Rootkit detection", "510", "high"), ("Suspicious process spawned", "100210", "high"), ("File integrity change", "550", "low"), ("Port scan detected", "40101", "medium")]
        sla = active_policy(db)
        for i in range(60):
            t, rid, sev = titles[i % len(titles)]
            a = assets[i % len(assets)]
            now = utcnow() - timedelta(minutes=rnd.randint(1, 60 * 48))
            al = Alert(source="wazuh_indexer", source_id=f"demo-{i}", time=now, first_seen=now, last_seen=now, severity=sev, title=t, rule_id=rid, host=a.name, src_ip=f"203.0.113.{rnd.randint(2, 250)}", mitre=["T1110"] if rid == "5710" else [], client_id=a.client_id, asset_id=a.id, status=rnd.choice(["new", "new", "acknowledged", "investigating", "resolved"]), dedup_key=f"demo-{i}", sla_policy_version=sla.version)
            from .sla import due_dates

            al.ack_due, al.resolve_due = due_dates(sla, sev, now)
            db.add(al)
        for i, a in enumerate(assets[:10]):
            db.add(Finding(asset_id=a.id, vuln_id=f"CVE-2024-{1000 + i}", title="Outdated component", severity=["critical", "high", "medium"][i % 3], cvss=9.8 - i * 0.7, component="openssl", client_id=a.client_id, sources=["openvas"]))
        for fw in ("pci_dss", "iso27001", "cis"):
            for j in range(8):
                db.add(ControlResult(framework=fw, control_id=f"{fw}-{j + 1}", title=f"Control {j + 1}", status="pass" if j % 4 else "fail", client_id=c1.id))
        for name, comp in (("PostgreSQL nightly", "postgres"), ("Vault snapshot", "vault"), ("Config", "config")):
            db.add(BackupJob(name=name, component=comp, last_status="success", last_success_at=utcnow() - timedelta(hours=6)))
    db.flush()
    return secrets
