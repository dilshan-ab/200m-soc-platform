"""Keycloak Admin API client (service account) used by administrators to provision users.

The service-account client `soc-admin` only holds the realm-management roles it needs
(view-users, manage-users, view-realm). Passwords are passed straight through and never logged.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

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
    old = [x for x in cur.json() if x.get("name") in ASSIGNABLE_ROLES and x.get("name") != role]
    if old:
        removed = _call(client, "DELETE", f"/users/{quote(uid, safe='')}/role-mappings/realm", json=old)
        if removed.status_code not in (200, 204):
            raise KcError("could not remove the previous Keycloak role")
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
