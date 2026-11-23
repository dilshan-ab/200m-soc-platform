"""The SOC platform's RBAC expressed as Keycloak objects: groups per role, and one client role per permission.

SOC stays the source of truth for what a role may do (policy.py plus any saved permission matrix). Keycloak mirrors
it so the groups' role mappings read like any other Keycloak ACL. Group membership still decides which SOC role a
user signs in with; editing the mirrored permissions in Keycloak does not change what SOC allows.
"""
from __future__ import annotations

from ..policy import CAPABILITIES, role_capabilities

CLIENT_ID = "soc-platform"

# SOC role -> group name. superadmin has a group for listing its permissions, but SOC never puts anyone in it.
GROUP_NAMES = {"superadmin": "SOC Super Admins", "admin": "SOC Admins", "l1": "SOC Analysts", "l2": "SOC L2 Analysts", "viewer": "SOC Viewers"}
GROUP_PARENT = {"l2": "l1"}  # SOC L2 Analysts is a subgroup of SOC Analysts and inherits its mappings
LEGACY_GROUP_NAMES = {"l1": "SOC L1 Analysts"}  # first version of the groups; renamed in place so members are kept
GROUP_ORDER = ("superadmin", "admin", "l1", "l2", "viewer")  # parents before children


def group_permissions() -> dict[str, list[str]]:
    """Permissions shown on each role's group. A subgroup inherits its parent's mappings, so it lists only what it adds."""
    full = {role: sorted(role_capabilities(role)) for role in GROUP_ORDER}
    out = dict(full)
    for child, parent in GROUP_PARENT.items():
        inherited = set(full[parent])
        out[child] = [c for c in full[child] if c not in inherited]
    return out


def describe(cap: str) -> str:
    area, _, action = cap.partition(".")
    return f"{area.replace('_', ' ').title()}: {action.replace('_', ' ') or 'access'} (default minimum role: {CAPABILITIES.get(cap, '?')})"


def all_permissions() -> list[str]:
    return sorted({c for caps in group_permissions().values() for c in caps})


def realm_groups() -> list[dict[str, object]]:
    """Group definitions for the realm import (new installs), in Keycloak's import format."""
    perms = group_permissions()

    def group(role: str) -> dict[str, object]:
        g: dict[str, object] = {"name": GROUP_NAMES[role], "realmRoles": [role], "clientRoles": {CLIENT_ID: perms[role]}}
        kids = [c for c, p in GROUP_PARENT.items() if p == role]
        if kids:
            g["subGroups"] = [group(k) for k in kids]
        return g

    return [group(r) for r in GROUP_ORDER if r not in GROUP_PARENT]


def realm_client_roles() -> list[dict[str, str]]:
    return [{"name": c, "description": describe(c)} for c in all_permissions()]
