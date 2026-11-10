"""Keycloak Admin API client (service account) used by the super admin to provision users.

The service-account client `soc-admin` only holds the realm-management roles it needs
(view-users, manage-users, view-realm). Passwords are passed straight through and never logged.
"""
from __future__ import annotations

from typing import Any

import httpx

from .config import get_settings

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
    r = _call(client, "GET", "/users", params={"email": email, "exact": "true"})
    if r.status_code != 200:
        raise KcError("could not look up the user in Keycloak")
    rows = r.json()
    return str(rows[0]["id"]) if rows else None


def create_user(client: httpx.Client, email: str, name: str, role: str, password: str) -> str:
    rep = _role_rep(client, role)
    first, _, last = name.strip().partition(" ")
    body = {
        "username": email, "email": email, "emailVerified": True, "enabled": True,
        "firstName": first or email.split("@")[0], "lastName": last,
        "credentials": [{"type": "password", "value": password, "temporary": True}],  # user must change it at first login
        "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"],
    }
    r = _call(client, "POST", "/users", json=body)
    if r.status_code == 409:
        raise KcError("a Keycloak user with this email already exists", 409)
    if r.status_code == 400:
        raise KcError("Keycloak rejected the request (check the password policy)", 400)
    if r.status_code != 201:
        raise KcError(f"Keycloak error {r.status_code}")
    uid = r.headers.get("location", "").rsplit("/", 1)[-1] or find_user_id(client, email) or ""
    m = _call(client, "POST", f"/users/{uid}/role-mappings/realm", json=[rep])
    if m.status_code not in (200, 204):
        _call(client, "DELETE", f"/users/{uid}")  # do not leave a role-less account behind
        raise KcError("could not assign the role in Keycloak")
    return uid


def set_role(client: httpx.Client, email: str, role: str) -> None:
    rep = _role_rep(client, role)
    uid = find_user_id(client, email)
    if uid is None:
        raise KcError("user not found in Keycloak", 404)
    cur = _call(client, "GET", f"/users/{uid}/role-mappings/realm")
    old = [x for x in cur.json() if x.get("name") in ASSIGNABLE_ROLES and x.get("name") != role]
    if old:
        _call(client, "DELETE", f"/users/{uid}/role-mappings/realm", json=old)
    m = _call(client, "POST", f"/users/{uid}/role-mappings/realm", json=[rep])
    if m.status_code not in (200, 204):
        raise KcError("could not assign the role in Keycloak")


def set_enabled(client: httpx.Client, email: str, enabled: bool) -> None:
    uid = find_user_id(client, email)
    if uid is None:
        raise KcError("user not found in Keycloak", 404)
    r = _call(client, "PUT", f"/users/{uid}", json={"enabled": enabled})
    if r.status_code not in (200, 204):
        raise KcError("could not update the user in Keycloak")
    if not enabled:
        _call(client, "POST", f"/users/{uid}/logout")  # end live SSO sessions
