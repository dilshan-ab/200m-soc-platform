"""Keycloak Admin API client (service account) used by administrators to provision users.

The service-account client `soc-admin` only holds the realm-management roles it needs
(view-users, manage-users, view-realm). Passwords are passed straight through and never logged.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

import httpx

from .config import get_settings
from .services import keycloak_acl

ASSIGNABLE_ROLES = ("viewer", "l1", "l2", "admin")  # `superadmin` is never assignable from the app


class KcError(Exception):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def configured() -> bool:
    s = get_settings()
    return bool(s.kc_admin_url and s.kc_admin_client_secret)


def _base() -> str:
    return get_settings().kc_admin_url.rstrip("/")


def _token(client: httpx.Client) -> str:
    s = get_settings()
    try:
        r = client.post(
            f"{_base()}/realms/{s.kc_realm}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": s.kc_admin_client_id, "client_secret": s.kc_admin_client_secret},
            timeout=10,
        )
    except httpx.HTTPError as e:
        raise KcError(f"Keycloak unreachable: {type(e).__name__}") from None
    if r.status_code != 200:
        raise KcError("Keycloak rejected the service account credentials")
    return str(r.json()["access_token"])


def _call(client: httpx.Client, method: str, path: str, **kw: Any) -> httpx.Response:
    s = get_settings()
    tok = _token(client)
    try:
        return client.request(method, f"{_base()}/admin/realms/{s.kc_realm}{path}", headers={"Authorization": f"Bearer {tok}"}, timeout=10, **kw)
    except httpx.HTTPError as e:
        raise KcError(f"Keycloak unreachable: {type(e).__name__}") from None


def _role_rep(client: httpx.Client, role: str) -> dict[str, Any]:
    if role not in ASSIGNABLE_ROLES:
        raise KcError("role cannot be assigned here", 400)
    r = _call(client, "GET", f"/roles/{role}")
    if r.status_code != 200:
        raise KcError(f"realm role '{role}' is missing in Keycloak")
    return dict(r.json())


def find_user_id(client: httpx.Client, email: str) -> str | None:
    # Legacy SOC records may retain the original username after the email is edited in Keycloak.
    for field in ("email", "username"):
        r = _call(client, "GET", "/users", params={field: email, "exact": "true"})
        if r.status_code != 200:
            raise KcError("could not look up the user in Keycloak")
        rows = r.json()
        if len(rows) > 1:
            raise KcError("multiple Keycloak accounts match this email; resolve duplicates in Keycloak", 409)
        if rows:
            return str(rows[0]["id"])
    return None


def _user(client: httpx.Client, email: str, expected_uid: str | None = None) -> dict[str, Any]:
    # A linked account is addressed only by subject. Never fall back to a different account
    # that has acquired the old email if the original identity was deleted or changed.
    uid = expected_uid or find_user_id(client, email)
    if not uid:
        raise KcError("user not found in Keycloak; restore the account there, or use Create in Keycloak for an older local SOC account", 404)
    r = _call(client, "GET", f"/users/{quote(uid, safe='')}")
    if r.status_code == 404:
        raise KcError("linked user not found in Keycloak; restore the original account or check the configured realm", 404)
    if r.status_code != 200:
        raise KcError("could not read the Keycloak account; check service account permissions")
    user = dict(r.json())
    if user.get("id") != uid:
        raise KcError("Keycloak account does not match the linked SOC identity", 409)
    return user


# Privileges are granted through Keycloak groups: each SOC role has a group that maps to the realm role (which is
# what sets the user's SOC role at sign-in) and to client roles that list that role's permissions (see
# services/keycloak_acl.py). `superadmin` has a group for completeness, but SOC never adds anyone to it: that stays
# a deliberate assignment in Keycloak.
GROUP_NAMES = keycloak_acl.GROUP_NAMES
GROUP_PARENT = keycloak_acl.GROUP_PARENT


def _walk(groups: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for g in groups:
        yield g
        yield from _walk(list(g.get("subGroups") or []))


def _find_group(client: httpx.Client, name: str) -> dict[str, Any] | None:
    """A group by exact name anywhere in the tree (subgroups included): {id, name, path}."""
    r = _call(client, "GET", "/groups", params={"search": name, "exact": "true"})
    if r.status_code != 200:
        raise KcError("could not list groups in Keycloak; check service account permissions")
    return next((g for g in _walk(list(r.json())) if g.get("name") == name), None)


def _group_id(client: httpx.Client, name: str) -> str | None:
    g = _find_group(client, name)
    return str(g["id"]) if g else None


def _realm_role(client: httpx.Client, role: str) -> dict[str, Any]:
    r = _call(client, "GET", f"/roles/{quote(role, safe='')}")
    if r.status_code != 200:
        raise KcError(f"realm role '{role}' is missing in Keycloak")
    return dict(r.json())


def _create_group(client: httpx.Client, name: str, parent_id: str | None) -> str:
    path = f"/groups/{quote(parent_id, safe='')}/children" if parent_id else "/groups"
    r = _call(client, "POST", path, json={"name": name})
    if r.status_code not in (201, 409):
        raise KcError(f"could not create group '{name}' in Keycloak (HTTP {r.status_code}); check service account permissions")
    gid = r.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1] if r.status_code == 201 else ""
    gid = gid or _group_id(client, name) or ""
    if not gid:
        raise KcError(f"Keycloak created group '{name}' but did not return its ID")
    return gid


def ensure_groups(client: httpx.Client) -> tuple[dict[str, str], list[str]]:
    """Create or tidy the SOC role groups and make sure each maps to its realm role. Idempotent.
    A group from the first version ("SOC L1 Analysts") is renamed in place and the L2 group is moved under it, so members keep their access.
    Returns ({role: group_id}, [names of groups created])."""
    ids: dict[str, str] = {}
    created: list[str] = []
    for role in keycloak_acl.GROUP_ORDER:
        name = GROUP_NAMES[role]
        parent_id = ids[GROUP_PARENT[role]] if role in GROUP_PARENT else None
        g = _find_group(client, name)
        legacy = keycloak_acl.LEGACY_GROUP_NAMES.get(role)
        if g is None and legacy:
            old = _find_group(client, legacy)
            if old is not None:  # rename in place
                cur = _call(client, "GET", f"/groups/{quote(str(old['id']), safe='')}")
                if cur.status_code != 200:
                    raise KcError(f"could not read group '{legacy}'")
                put = _call(client, "PUT", f"/groups/{quote(str(old['id']), safe='')}", json={**cur.json(), "name": name})
                if put.status_code not in (200, 204):
                    raise KcError(f"could not rename group '{legacy}' to '{name}'")
                g = old
        if g is None:
            gid = _create_group(client, name, parent_id)
            created.append(name)
        else:
            gid = str(g["id"])
            if parent_id and g.get("path") != f"{_path_of(client, parent_id)}/{name}":  # exists but not under its parent yet
                mv = _call(client, "POST", f"/groups/{quote(parent_id, safe='')}/children", json={"id": gid, "name": name})
                if mv.status_code not in (200, 201, 204):
                    raise KcError(f"could not move group '{name}' under its parent")
        rep = _realm_role(client, role)
        cur_map = _call(client, "GET", f"/groups/{quote(gid, safe='')}/role-mappings/realm")
        if cur_map.status_code != 200:
            raise KcError(f"could not read the roles of group '{name}'")
        if not any(x.get("name") == role for x in cur_map.json()):
            m = _call(client, "POST", f"/groups/{quote(gid, safe='')}/role-mappings/realm", json=[rep])
            if m.status_code not in (200, 204):
                raise KcError(f"could not map group '{name}' to the {role} role")
        ids[role] = gid
    return ids, created


def _path_of(client: httpx.Client, group_id: str) -> str:
    r = _call(client, "GET", f"/groups/{quote(group_id, safe='')}")
    if r.status_code != 200:
        raise KcError("could not read a group in Keycloak")
    return str(r.json().get("path") or "")


def sync_acl(client: httpx.Client, group_ids: dict[str, str]) -> dict[str, int]:
    """Mirror SOC's RBAC into Keycloak: one client role per permission on the soc-platform client, mapped onto each role's
    group. Needs the service account to hold manage-clients and view-clients. Returns counts of what changed."""
    r = _call(client, "GET", "/clients", params={"clientId": keycloak_acl.CLIENT_ID})
    if r.status_code != 200 or not r.json():
        raise KcError(f"could not find the '{keycloak_acl.CLIENT_ID}' client in Keycloak; the soc-admin service account needs the view-clients role")
    cu = quote(str(r.json()[0]["id"]), safe="")
    existing = {str(x["name"]): x for x in _paged(client, f"/clients/{cu}/roles", "client roles")}
    created = updated = 0
    for cap in keycloak_acl.all_permissions():
        desc = keycloak_acl.describe(cap)
        if cap not in existing:
            c = _call(client, "POST", f"/clients/{cu}/roles", json={"name": cap, "description": desc})
            if c.status_code not in (201, 409):
                raise KcError(f"could not create permission '{cap}' in Keycloak (HTTP {c.status_code}); the soc-admin service account needs the manage-clients role")
            created += 1
        elif existing[cap].get("description") != desc:
            u = _call(client, "PUT", f"/clients/{cu}/roles/{quote(cap, safe='')}", json={"name": cap, "description": desc})
            if u.status_code not in (200, 204):
                raise KcError(f"could not update permission '{cap}' in Keycloak")
            updated += 1
    if created:
        existing = {str(x["name"]): x for x in _paged(client, f"/clients/{cu}/roles", "client roles")}
    perms = keycloak_acl.group_permissions()
    added = removed = 0
    for role, gid in group_ids.items():
        want = set(perms.get(role, []))
        path = f"/groups/{quote(gid, safe='')}/role-mappings/clients/{cu}"
        cur = _call(client, "GET", path)
        if cur.status_code != 200:
            raise KcError(f"could not read the permissions of group '{GROUP_NAMES[role]}'")
        have = {str(x["name"]): x for x in cur.json()}
        add = [existing[c] for c in sorted(want - set(have)) if c in existing]
        drop = [have[c] for c in sorted(set(have) - want)]  # a permission SOC no longer grants this role
        if add:
            a = _call(client, "POST", path, json=add)
            if a.status_code not in (200, 204):
                raise KcError(f"could not map permissions onto group '{GROUP_NAMES[role]}'")
            added += len(add)
        if drop:
            d = _call(client, "DELETE", path, json=drop)
            if d.status_code not in (200, 204):
                raise KcError(f"could not remove permissions from group '{GROUP_NAMES[role]}'")
            removed += len(drop)
    return {"permissions_created": created, "permissions_updated": updated, "mappings_added": added, "mappings_removed": removed}


def _put_in_group(client: httpx.Client, uid: str, role: str, group_ids: dict[str, str]) -> None:
    """Make the user a member of the group for `role` and of no other assignable SOC role group (never touches the super admin group)."""
    mine = _call(client, "GET", f"/users/{quote(uid, safe='')}/groups")
    if mine.status_code != 200:
        raise KcError("could not read the user's Keycloak groups")
    member_of = {str(g["id"]) for g in mine.json()}
    for other_role in ASSIGNABLE_ROLES:
        gid = group_ids.get(other_role)
        if other_role != role and gid in member_of:
            d = _call(client, "DELETE", f"/users/{quote(uid, safe='')}/groups/{quote(str(gid), safe='')}")
            if d.status_code not in (200, 204):
                raise KcError("could not remove the user from their previous group")
    if group_ids[role] not in member_of:
        a = _call(client, "PUT", f"/users/{quote(uid, safe='')}/groups/{quote(group_ids[role], safe='')}")
        if a.status_code not in (200, 204):
            raise KcError("could not add the user to the group")


def create_user(client: httpx.Client, email: str, name: str, role: str, password: str) -> str:
    rep = _role_rep(client, role)
    first, _, last = name.strip().partition(" ")
    require_verify = get_settings().oidc_require_email_verification
    required_actions = (["VERIFY_EMAIL"] if require_verify else []) + ["UPDATE_PASSWORD", "CONFIGURE_TOTP"]
    body = {
        "username": email, "email": email, "emailVerified": not require_verify, "enabled": True,
        "firstName": first or email.split("@")[0], "lastName": last,
        "credentials": [{"type": "password", "value": password, "temporary": True}],  # user must change it at first login
        "requiredActions": required_actions,
    }
    r = _call(client, "POST", "/users", json=body)
    if r.status_code == 409:
        raise KcError("a Keycloak user with this email already exists", 409)
    if r.status_code == 400:
        raise KcError("Keycloak rejected the request (check the password policy)", 400)
    if r.status_code != 201:
        raise KcError(f"Keycloak error {r.status_code}")
    uid = r.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1] or find_user_id(client, email)
    if not uid:
        raise KcError("Keycloak created the user but did not return an account ID")
    try:  # privileges come from the role's group; fall back to a direct role if groups cannot be managed
        ids, _ = ensure_groups(client)
        _put_in_group(client, uid, role, ids)
        return uid
    except KcError:
        pass
    m = _call(client, "POST", f"/users/{quote(uid, safe='')}/role-mappings/realm", json=[rep])
    if m.status_code not in (200, 204):
        _call(client, "DELETE", f"/users/{quote(uid, safe='')}")  # do not leave a role-less account behind
        raise KcError("could not assign the role in Keycloak")
    return uid


def set_role(client: httpx.Client, email: str, role: str, expected_uid: str | None = None) -> None:
    rep = _role_rep(client, role)
    uid = _user(client, email, expected_uid)["id"]
    cur = _call(client, "GET", f"/users/{quote(uid, safe='')}/role-mappings/realm")
    if cur.status_code != 200:
        raise KcError("could not read the user's Keycloak roles")
    direct = [x for x in cur.json() if x.get("name") in ASSIGNABLE_ROLES]
    via_group = False
    try:  # privileges come from the role's group; fall back to a direct role if groups cannot be managed
        ids, _ = ensure_groups(client)
        _put_in_group(client, uid, role, ids)
        via_group = True
    except KcError:
        pass
    # With a group, every direct SOC role is dropped: a leftover one would keep overriding the group if they are later moved in Keycloak.
    stale = direct if via_group else [x for x in direct if x.get("name") != role]
    if stale:
        removed = _call(client, "DELETE", f"/users/{quote(uid, safe='')}/role-mappings/realm", json=stale)
        if removed.status_code not in (200, 204):
            raise KcError("could not remove the previous Keycloak role")
    if not via_group:
        m = _call(client, "POST", f"/users/{quote(uid, safe='')}/role-mappings/realm", json=[rep])
        if m.status_code not in (200, 204):
            raise KcError("could not assign the role in Keycloak")


def set_enabled(client: httpx.Client, email: str, enabled: bool, expected_uid: str | None = None) -> None:
    uid = _user(client, email, expected_uid)["id"]
    r = _call(client, "PUT", f"/users/{quote(uid, safe='')}", json={"enabled": enabled})
    if r.status_code not in (200, 204):
        raise KcError("could not update the user in Keycloak")
    if not enabled:
        _call(client, "POST", f"/users/{quote(uid, safe='')}/logout")  # end live SSO sessions


def reset_password(client: httpx.Client, email: str, password: str, expected_uid: str | None = None) -> str:
    uid = _user(client, email, expected_uid)["id"]
    r = _call(client, "POST", f"/users/{quote(uid, safe='')}/logout")
    if r.status_code not in (200, 204):
        raise KcError("could not end Keycloak sessions; password was not changed")
    r = _call(client, "PUT", f"/users/{quote(uid, safe='')}/reset-password", json={"type": "password", "value": password, "temporary": True})
    if r.status_code == 400:
        raise KcError("Keycloak rejected the password; check the realm password policy", 400)
    if r.status_code not in (200, 204):
        raise KcError(f"could not reset the password in Keycloak (HTTP {r.status_code}); check service account user-management permissions")
    return uid


def set_profile(client: httpx.Client, old_email: str, name: str, email: str, expected_uid: str | None = None) -> str:
    user = _user(client, old_email, expected_uid)
    uid = user["id"]
    first, _, last = name.strip().partition(" ")
    body: dict[str, Any] = {"firstName": first, "lastName": last, "email": email}
    if email != user.get("email"):
        body["emailVerified"] = False
    r = _call(client, "PUT", f"/users/{quote(uid, safe='')}", json=body)
    if r.status_code == 409:
        raise KcError("email already exists in Keycloak", 409)
    if r.status_code == 400:
        raise KcError("Keycloak rejected the profile; check the realm user profile rules", 400)
    if r.status_code not in (200, 204):
        raise KcError("could not update the profile in Keycloak")
    return str(uid)


def delete_user(client: httpx.Client, uid: str) -> bool:
    """Delete a Keycloak account by its ID. Returns False when it was already gone (so a retry after a partial failure succeeds)."""
    r = _call(client, "DELETE", f"/users/{quote(uid, safe='')}")
    if r.status_code == 404:
        return False
    if r.status_code not in (200, 204):
        raise KcError(f"could not delete the user in Keycloak (HTTP {r.status_code}); check service account user-management permissions")
    return True


def _paged(client: httpx.Client, path: str, what: str, page: int = 100, limit: int = 20000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while len(rows) < limit:
        r = _call(client, "GET", path, params={"first": len(rows), "max": page})
        if r.status_code != 200:
            raise KcError(f"could not list {what} in Keycloak; check service account permissions")
        batch = list(r.json())
        rows.extend(batch)
        if len(batch) < page:
            return rows
    raise KcError(f"too many {what} in Keycloak to sync")


def list_users(client: httpx.Client) -> list[dict[str, Any]]:
    """Every Keycloak user with its highest SOC realm role: [{id, email, name, enabled, role}] (role may be '' or 'superadmin')."""
    ranks = (*ASSIGNABLE_ROLES, "superadmin")
    role_of: dict[str, str] = {}
    for role in ranks:  # ascending, so a later (higher) role overwrites an earlier one
        for u in _paged(client, f"/roles/{quote(role, safe='')}/users", f"users with role {role}"):
            role_of[str(u["id"])] = role
        gid = _group_id(client, GROUP_NAMES[role]) if role in GROUP_NAMES else None
        if gid:  # members of the role's group hold the role through the group
            for u in _paged(client, f"/groups/{quote(gid, safe='')}/members", f"members of {GROUP_NAMES[role]}"):
                role_of[str(u["id"])] = role
    out = []
    for u in _paged(client, "/users", "users"):
        uid = str(u["id"])
        out.append({
            "id": uid, "email": str(u.get("email") or "").strip().lower(), "enabled": bool(u.get("enabled", True)), "role": role_of.get(uid, ""),
            "name": " ".join(x for x in (u.get("firstName"), u.get("lastName")) if x).strip(),
        })
    return out
