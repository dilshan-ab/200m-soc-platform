"""The SOC platform's RBAC expressed as Keycloak objects: groups per role, and one client role per permission.

SOC stays the source of truth for what a role may do (policy.py plus any saved permission matrix). Keycloak mirrors
it so the groups' role mappings read like any other Keycloak ACL. Group membership still decides which SOC role a
user signs in with; editing the mirrored permissions in Keycloak does not change what SOC allows.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..policy import CAPABILITIES, role_capabilities

CLIENT_ID = "soc-platform"

@dataclass(frozen=True)
class GroupSpec:
    name: str
    role: str  # the realm role the group maps to (what sets the user's SOC role at sign-in)
    parent: str | None = None  # key of the parent group; a subgroup inherits the parent's mappings
    delta: bool = False  # list only the permissions this group adds over its parent


# group key -> spec, parents before children. superadmin has a group for listing its permissions, but SOC never puts anyone in it.
GROUPS: dict[str, GroupSpec] = {
    "superadmin": GroupSpec("SOC Super Admins", "superadmin"),
    "admin": GroupSpec("SOC Admins", "admin"),
    "analysts": GroupSpec("SOC Analysts", "l1"),
    "l1": GroupSpec("SOC L1 Analysts", "l1", parent="analysts"),
    "l2": GroupSpec("SOC L2 Analysts", "l2", parent="analysts", delta=True),
    "viewer": GroupSpec("SOC Viewers", "viewer"),
}
ASSIGNABLE_KEYS = ("viewer", "l1", "l2", "admin")  # the groups SOC puts users in: key == the SOC role it assigns


def keys_for_role(role: str) -> list[str]:
    return [k for k, g in GROUPS.items() if g.role == role]


def group_permissions() -> dict[str, list[str]]:
    """Permissions shown on each group (by group key). A group marked `delta` lists only what it adds over its parent."""
    out: dict[str, list[str]] = {}
    for key, spec in GROUPS.items():
        caps = sorted(role_capabilities(spec.role))
        if spec.delta and spec.parent:
            inherited = set(role_capabilities(GROUPS[spec.parent].role))
            caps = [c for c in caps if c not in inherited]
        out[key] = caps
    return out


def describe(cap: str) -> str:
    area, _, action = cap.partition(".")
    return f"{area.replace('_', ' ').title()}: {action.replace('_', ' ') or 'access'} (default minimum role: {CAPABILITIES.get(cap, '?')})"


def all_permissions() -> list[str]:
    return sorted({c for caps in group_permissions().values() for c in caps})


def realm_groups() -> list[dict[str, object]]:
    """Group definitions for the realm import (new installs), in Keycloak's import format."""
    perms = group_permissions()

    def group(key: str) -> dict[str, object]:
        spec = GROUPS[key]
        g: dict[str, object] = {"name": spec.name, "realmRoles": [spec.role], "clientRoles": {CLIENT_ID: perms[key]}}
        kids = [k for k, c in GROUPS.items() if c.parent == key]
        if kids:
            g["subGroups"] = [group(k) for k in kids]
        return g

    return [group(k) for k, spec in GROUPS.items() if spec.parent is None]


def realm_client_roles() -> list[dict[str, str]]:
    return [{"name": c, "description": describe(c)} for c in all_permissions()]
