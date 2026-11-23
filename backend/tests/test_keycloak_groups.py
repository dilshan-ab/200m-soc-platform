"""SOC role groups in Keycloak: creation, membership on create/role change, and sync reading group-derived roles."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app import db as dbmod
from app import keycloak_admin as kc
from app.api import auth as auth_api
from app.config import reset_settings_cache
from app.models import User

KC = "http://keycloak:8080"
PASSWORD = "Str0ng-Passw0rd!x"
SOC_ROLES = ("viewer", "l1", "l2", "admin", "superadmin")
GROUPS = {"SOC Admins": "admin", "SOC L2 Analysts": "l2", "SOC L1 Analysts": "l1", "SOC Viewers": "viewer"}


class GroupKeycloak:
    """Keycloak admin API with users, realm roles and groups (group role mappings, membership, effective roles)."""

    def __init__(self):
        self.users: dict[str, dict] = {}
        self.direct: dict[str, set[str]] = {}  # user id -> directly mapped realm roles
        self.groups: dict[str, dict] = {}  # group id -> {"name", "roles": set, "members": set}
        self.calls: list[tuple[str, str]] = []
        self.deny_groups = False  # service account may not touch groups at all
        self.deny_group_writes = False  # ...or may read them but not create/map them
        self.n = 0

    # ---- helpers
    def add_user(self, email, direct=(), groups=(), enabled=True):
        self.n += 1
        uid = f"kc-{self.n}"
        self.users[uid] = {"id": uid, "email": email, "username": email, "enabled": enabled, "firstName": email.split("@")[0], "lastName": ""}
        self.direct[uid] = set(direct)
        for g in groups:
            self.group_id(g) or self.add_group(g, GROUPS[g])
            self.groups[self.group_id(g)]["members"].add(uid)
        return uid

    def add_group(self, name, role=None):
        self.n += 1
        gid = f"g-{self.n}"
        self.groups[gid] = {"name": name, "roles": {role} if role else set(), "members": set()}
        return gid

    def group_id(self, name):
        return next((g for g, v in self.groups.items() if v["name"] == name), None)

    def effective(self, uid) -> set[str]:
        return self.direct.get(uid, set()) | {r for g in self.groups.values() if uid in g["members"] for r in g["roles"]}

    def member_groups(self, uid) -> set[str]:
        return {g["name"] for g in self.groups.values() if uid in g["members"]}

    # ---- the HTTP surface
    def handler(self, req: httpx.Request) -> httpx.Response:  # noqa: C901
        m, p, q = req.method, req.url.path.split("/admin/realms/soc", 1)[-1], req.url.params
        self.calls.append((m, p))
        if "openid-connect/token" in req.url.path:
            return httpx.Response(200, json={"access_token": "tok"})
        first, mx = int(q.get("first", 0)), int(q.get("max", 100))
        body = __import__("json").loads(req.content) if req.content else None
        parts = p.strip("/").split("/")
        if parts[0] == "groups" and (self.deny_groups or (self.deny_group_writes and m != "GET")):
            return httpx.Response(403)
        if parts[0] == "roles":
            if len(parts) == 2:
                return httpx.Response(200, json={"id": f"role-{parts[1]}", "name": parts[1]}) if parts[1] in SOC_ROLES else httpx.Response(404)
            ids = sorted(u for u, r in self.direct.items() if parts[1] in r)
            return httpx.Response(200, json=[self.users[i] for i in ids[first:first + mx]])
        if parts[0] == "groups":
            if len(parts) == 1 and m == "GET":
                return httpx.Response(200, json=[{"id": g, "name": v["name"]} for g, v in self.groups.items() if v["name"] == q.get("search")])
            if len(parts) == 1 and m == "POST":
                if self.group_id(body["name"]):
                    return httpx.Response(409)
                return httpx.Response(201, headers={"location": f"{KC}/admin/realms/soc/groups/{self.add_group(body['name'])}"})
            g = self.groups.get(parts[1])
            if g is None:
                return httpx.Response(404)
            if parts[2:] == ["role-mappings", "realm"]:
                if m == "GET":
                    return httpx.Response(200, json=[{"id": f"role-{r}", "name": r} for r in g["roles"]])
                g["roles"].update(r["name"] for r in body)
                return httpx.Response(204)
            if parts[2:] == ["members"]:
                return httpx.Response(200, json=[self.users[u] for u in sorted(g["members"])[first:first + mx]])
        if parts[0] == "users":
            if len(parts) == 1 and m == "GET":
                found = [u for u in self.users.values() if q.get("email") in (None, u["email"]) and q.get("username") in (None, u["username"])]
                return httpx.Response(200, json=found if ("email" in q or "username" in q) else list(self.users.values())[first:first + mx])
            if len(parts) == 1 and m == "POST":
                uid = self.add_user(body["email"], enabled=body.get("enabled", True))
                return httpx.Response(201, headers={"location": f"{KC}/admin/realms/soc/users/{uid}"})
            uid = parts[1]
            if uid not in self.users:
                return httpx.Response(404)
            rest = parts[2:]
            if not rest:
                if m == "GET":
                    return httpx.Response(200, json=self.users[uid])
                if m == "DELETE":
                    del self.users[uid]
                    return httpx.Response(204)
                self.users[uid].update(body)
                return httpx.Response(204)
            if rest == ["role-mappings", "realm"]:
                if m == "GET":
                    return httpx.Response(200, json=[{"id": f"role-{r}", "name": r} for r in self.direct[uid]])
                names = {r["name"] for r in body}
                self.direct[uid] = (self.direct[uid] | names) if m == "POST" else (self.direct[uid] - names)
                return httpx.Response(204)
            if rest == ["groups"]:
                return httpx.Response(200, json=[{"id": g, "name": v["name"]} for g, v in self.groups.items() if uid in v["members"]])
            if rest[0] == "groups" and len(rest) == 2:
                self.groups[rest[1]]["members"].add(uid) if m == "PUT" else self.groups[rest[1]]["members"].discard(uid)
                return httpx.Response(204)
            if rest == ["logout"]:
                return httpx.Response(204)
        return httpx.Response(404)


@pytest.fixture()
def kcg(monkeypatch):
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_KC_ADMIN_URL": KC, "SOC_KC_ADMIN_CLIENT_SECRET": "svc", "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "c", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    fake = GroupKeycloak()
    auth_api.set_http(httpx.Client(transport=httpx.MockTransport(fake.handler)))
    yield fake
    auth_api.set_http(None)


def _client(fake):
    return httpx.Client(transport=httpx.MockTransport(fake.handler))


def _soc_user(email, subject, role="viewer"):
    with dbmod.session_scope() as db:
        u = User(subject=subject, email=email, name=email.split("@")[0], role=role)
        db.add(u)
        db.flush()
        return u.id


# --------------------------------------------------------------------------- ensure_groups
def test_ensure_groups_creates_each_role_group_mapped_to_its_role(kcg):
    ids, created = kc.ensure_groups(_client(kcg))
    assert sorted(created) == sorted(GROUPS) and set(ids) == {"admin", "l2", "l1", "viewer"}
    assert {kcg.groups[g]["name"]: kcg.groups[g]["roles"] for g in ids.values()} == {name: {role} for name, role in GROUPS.items()}
    assert not any("superadmin" in v["roles"] for v in kcg.groups.values())  # superadmin has no group on purpose


def test_ensure_groups_is_idempotent_and_repairs_a_missing_mapping(kcg):
    kcg.add_group("SOC Admins")  # exists but is mapped to nothing
    _, created = kc.ensure_groups(_client(kcg))
    assert "SOC Admins" not in created and kcg.groups[kcg.group_id("SOC Admins")]["roles"] == {"admin"}
    n = len(kcg.groups)
    assert kc.ensure_groups(_client(kcg))[1] == [] and len(kcg.groups) == n


# --------------------------------------------------------------------------- create / change role through SOC
def test_new_user_joins_the_role_group_without_a_direct_role(superadmin, kcg):
    r = superadmin.post("/api/admin/users", {"email": "ana@t.local", "name": "Ana A", "role": "l2", "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = next(u for u, v in kcg.users.items() if v["email"] == "ana@t.local")
    assert kcg.member_groups(uid) == {"SOC L2 Analysts"} and kcg.direct[uid] == set() and kcg.effective(uid) == {"l2"}


def test_new_user_falls_back_to_a_direct_role_when_groups_are_denied(superadmin, kcg):
    kcg.deny_groups = True
    r = superadmin.post("/api/admin/users", {"email": "bo@t.local", "name": "Bo B", "role": "l1", "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = next(u for u, v in kcg.users.items() if v["email"] == "bo@t.local")
    assert kcg.direct[uid] == {"l1"} and kcg.member_groups(uid) == set()


def test_role_change_moves_group_and_removes_direct_roles(superadmin, kcg):
    uid = kcg.add_user("cy@t.local", direct={"viewer"}, groups=["SOC Viewers"])
    soc_id = _soc_user("cy@t.local", uid)
    r = superadmin.patch(f"/api/admin/users/{soc_id}", {"role": "admin"})
    assert r.status_code == 200, r.text
    assert kcg.member_groups(uid) == {"SOC Admins"} and kcg.direct[uid] == set() and kcg.effective(uid) == {"admin"}


def test_role_change_without_group_access_keeps_the_direct_role_behaviour(superadmin, kcg):
    uid = kcg.add_user("di@t.local", direct={"viewer"})
    soc_id = _soc_user("di@t.local", uid)
    kcg.deny_groups = True
    assert superadmin.patch(f"/api/admin/users/{soc_id}", {"role": "l2"}).status_code == 200
    assert kcg.direct[uid] == {"l2"} and kcg.member_groups(uid) == set()


# --------------------------------------------------------------------------- sync reads group-derived roles
def test_sync_creates_groups_once_and_imports_group_only_users(superadmin, kcg):
    kcg.add_user("via-group@t.local", groups=["SOC L2 Analysts"])  # privileges only through the group
    kcg.add_user("both@t.local", direct={"viewer"}, groups=["SOC Admins"])  # highest of direct and group wins
    kcg.add_user("nothing@t.local")
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert sorted(out["imported"]) == ["both@t.local", "via-group@t.local"] and out["groups_error"] == ""
    assert {s["email"] for s in out["skipped"]} == {"nothing@t.local"}
    assert set(out["groups_created"]) == set(GROUPS) - {"SOC L2 Analysts", "SOC Admins"}  # the two that already existed are not re-created
    with dbmod.session_scope() as db:
        roles = {u.email: u.role for u in db.execute(select(User)).scalars()}
    assert roles["via-group@t.local"] == "l2" and roles["both@t.local"] == "admin"
    assert superadmin.post("/api/admin/users/sync", {}).json()["groups_created"] == []


def test_sync_still_runs_and_reports_when_groups_cannot_be_created(superadmin, kcg):
    kcg.add_user("plain@t.local", direct={"l1"})
    kcg.deny_group_writes = True  # can read groups, cannot create them
    r = superadmin.post("/api/admin/users/sync", {})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["imported"] == ["plain@t.local"] and out["groups_created"] == [] and "could not create group" in out["groups_error"]
    assert not kcg.groups


def test_sync_fails_clearly_rather_than_misreading_roles_when_groups_cannot_be_read(superadmin, kcg):
    kcg.add_user("via-group@t.local", groups=["SOC L2 Analysts"])
    kcg.deny_groups = True
    r = superadmin.post("/api/admin/users/sync", {})
    assert r.status_code == 502 and "groups" in r.text
    with dbmod.session_scope() as db:
        assert db.execute(select(User).where(User.email == "via-group@t.local")).first() is None  # nothing imported with a wrong role


def test_listing_users_pages_through_group_members(kcg):
    for i in range(130):
        kcg.add_user(f"m{i}@t.local", groups=["SOC Viewers"])
    rows = kc.list_users(_client(kcg))
    assert len(rows) == 130 and {r["role"] for r in rows} == {"viewer"}
