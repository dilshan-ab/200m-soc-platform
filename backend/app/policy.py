"""Authorization policy: roles, capabilities, severities, response action catalogue."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s: str) -> int:
    try:
        return SEVERITIES.index(s)
    except ValueError:
        return 0


ROLES = ["viewer", "l1", "l2", "admin", "superadmin"]

# capability -> minimum role
CAPABILITIES: dict[str, str] = {
    "alerts.read": "viewer",
    "alerts.triage": "l1",
    "alerts.tune": "l2",
    "alerts.delete": "admin",
    "cases.read": "viewer",
    "cases.write": "l1",
    "cases.close": "l2",
    "assets.read": "viewer",
    "assets.write": "l2",
    "servers.read": "viewer",
    "servers.write": "admin",
    "vulns.read": "viewer",
    "vulns.write": "l2",
    "compliance.read": "viewer",
    "compliance.write": "l2",
    "intel.read": "l1",
    "intel.enrich": "l1",
    "hunts.read": "l2",
    "hunts.request": "l2",
    "response.read": "l1",
    "response.request": "l1",
    "response.approve": "l2",
    "response.approve_critical": "admin",
    "reports.read": "viewer",
    "reports.generate": "l1",
    "reports.schedule": "admin",
    "automation.read": "l2",
    "automation.write": "admin",
    "notifications.write": "admin",
    "runbooks.read": "viewer",
    "runbooks.write": "l2",
    "playbooks.read": "l1",
    "playbooks.write": "l2",
    "playbooks.execute": "l1",
    "correlation.read": "l1",
    "correlation.write": "l2",
    "incidents.read": "viewer",
    "incidents.write": "l1",
    "integrations.read": "l2",
    "integrations.write": "admin",
    "admin.users": "admin",
    "users.provision": "superadmin",  # create users/admins, change roles, enable/disable accounts
    "admin.settings": "admin",
    "admin.audit": "admin",
    "admin.backups": "admin",
    "admin.tokens": "l1",
    "metrics.read": "l1",
    "detections.read": "viewer",
    "detections.write": "l2",
    "evidence.read": "l1",
    "evidence.write": "l1",
    "ueba.read": "l1",
    "ueba.write": "l2",
    "copilot.read": "l1",
    "copilot.write": "l2",
    "simulation.read": "l2",
    "simulation.write": "admin",
    "notebooks.read": "l1",
    "notebooks.write": "l1",
    "threat_intel.read": "l1",
    "threat_intel.write": "l2",
    "threat_intel.admin": "admin",
    "handoff.read": "l1",
    "handoff.write": "l1",
    "warroom.read": "l1",
    "warroom.write": "l1",
    "warroom.manage": "l2",
    "clients.read": "l1",
    "clients.write": "admin",
    "clients.manage_members": "admin",
    "mssp.view": "l2",
}


def role_rank(role: str) -> int:
    return ROLES.index(role) if role in ROLES else -1


_role_overrides: dict[str, list[str]] | None = None


def set_role_overrides(overrides: dict[str, list[str]] | None) -> None:
    global _role_overrides
    _role_overrides = overrides


def get_role_overrides() -> dict[str, list[str]] | None:
    return _role_overrides


def role_capabilities(role: str) -> list[str]:
    if role == "superadmin":  # explicit, unconditional: never gated by overrides or a missed rank entry
        return list(CAPABILITIES)
    if _role_overrides and role in _role_overrides:
        return _role_overrides[role]
    rank = role_rank(role)
    return [cap for cap, min_role in CAPABILITIES.items() if rank >= role_rank(min_role)]


def has_capability(role: str, grants: list[str] | None, cap: str, denied: list[str] | None = None) -> bool:
    need = CAPABILITIES.get(cap)
    if need is None:
        return False
    if role == "superadmin":  # explicit, unconditional: superadmin can always do anything in the system
        return True
    if cap in (denied or []):  # a per-user restriction always wins over the role default or a grant
        return False
    if cap in (grants or []):
        return True
    if _role_overrides and role in _role_overrides:
        return cap in _role_overrides[role]
    return role_rank(role) >= role_rank(need)


@dataclass(frozen=True)
class ActionSpec:
    key: str
    label: str
    system: str  # connector type that executes it
    capability: str = "response.request"
    reversible: bool = False
    risk: str = "medium"  # low|medium|high|critical
    approvals: int = 1
    target_kind: str = "host"  # host|ip|indicator|vuln
    params: list[str] = field(default_factory=list)


ACTIONS: dict[str, ActionSpec] = {a.key: a for a in [
    ActionSpec("block_ip", "Block IP on firewall (Wazuh active response)", "wazuh_manager", reversible=True, risk="medium", target_kind="ip"),
    ActionSpec("unblock_ip", "Remove IP block", "wazuh_manager", reversible=False, risk="low", target_kind="ip"),
    ActionSpec("isolate_host", "Network-isolate host (Velociraptor quarantine)", "velociraptor", reversible=True, risk="high", approvals=1),
    ActionSpec("release_host", "Release host from isolation", "velociraptor", risk="medium"),
    ActionSpec("kill_process", "Kill process on host", "velociraptor", reversible=False, risk="high"),
    ActionSpec("collect_artifact", "Collect forensic artifact", "velociraptor", risk="low", target_kind="host", params=["artifact"]),
    ActionSpec("run_scan", "Run vulnerability scan", "openvas", risk="low", params=["scan_config"]),
    ActionSpec("deploy_patch", "Deploy patch via OPSI", "opsi", reversible=False, risk="high", params=["product"]),
    ActionSpec("run_backup", "Run backup job", "bareos", risk="low", params=["job"]),
    ActionSpec("run_playbook", "Run Shuffle playbook", "shuffle", risk="medium", params=["workflow"]),
    ActionSpec("restart_agent", "Restart Wazuh agent", "wazuh_manager", risk="low"),
    ActionSpec("disable_account", "Disable user account", "wazuh_manager", reversible=True, risk="critical", approvals=2, capability="response.request", target_kind="user"),
    ActionSpec("run_adversary", "Run Caldera adversary emulation", "caldera", risk="high", approvals=2, capability="simulation.write", target_kind="host", params=["adversary_id", "operation_name"]),
    ActionSpec("run_atomic", "Run Atomic Red Team test", "atomic_red_team", risk="high", approvals=2, capability="simulation.write", target_kind="host", params=["technique_id", "test_numbers"]),
    ActionSpec("run_simulation", "Run BAS simulation scenario", "attack_simulator", risk="high", approvals=2, capability="simulation.write", target_kind="host", params=["scenario_id"]),
    ActionSpec("stop_simulation", "Stop running simulation", "attack_simulator", risk="low", capability="simulation.write", target_kind="host", params=["simulation_id"]),
]}

# Targets that may never be the object of an automated or requested response action.
DEFAULT_PROTECTED = ["127.0.0.1", "::1"]
MAX_TARGETS_PER_ACTION = {"low": 50, "medium": 10, "high": 3, "critical": 1}
