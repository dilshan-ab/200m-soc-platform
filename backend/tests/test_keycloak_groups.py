"""SOC role groups in Keycloak: layout, migration, the RBAC permission mirror, membership on create/role change, sync."""
from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from app import db as dbmod
from app import keycloak_admin as kc
from app.api import auth as auth_api
from app.config import reset_settings_cache
from app.models import User
from app.policy import CAPABILITIES, role_capabilities, set_role_overrides
from app.services import keycloak_acl as acl

KC = "http://keycloak:8080"
PASSWORD = "Str0ng-Passw0rd!x"
SOC_ROLES = ("viewer", "l1", "l2", "admin", "superadmin")
G = acl.GROUP_NAMES


class GroupKeycloak:
    """Keycloak admin API: users, realm roles, nested groups with realm + client role mappings, and the soc-platform client."""

    def __init__(self):
        self.users: dict[str, dict] = {}
        self.direct: dict[str, set[str]] = {}
        self.groups: dict[str, dict] = {}  # id -> {name, parent, roles, client_roles, members}
        self.client_roles: dict[str, dict] = {}  # name -> {id, name, description}
        self.calls: list[tuple[str, str]] = []
        self.deny_groups = False  # no access to groups at all
        self.deny_group_writes = False  # read-only on groups
        self.deny_client_roles = False  # cannot create client roles (no manage-clients)
        self.deny_client_list = False  # cannot even read clients (no view-clients)
        self.client_id = "soc-platform"
        self.sa_roles: list[str] | None = None  # realm-management roles held by the soc-admin service account (None = not readable)
        self.client_exists = True
        self.deny_group_put = False  # cannot edit groups (attributes)
        self.n = 0

    def _id(self, prefix):
        self.n += 1
        return f"{prefix}-{self.n}"

    # ---- state helpers
    def add_user(self, email, direct=(), groups=(), enabled=True):
        uid = self._id("kc")
        self.users[uid] = {"id": uid, "email": email, "username": email, "enabled": enabled, "firstName": email.split("@")[0], "lastName": ""}
        self.direct[uid] = set(direct)
        for name in groups:
            (self.gid(name) or self.add_group(name)) and self.groups[self.gid(name)]["members"].add(uid)
        return uid

    def add_group(self, name, role=None, parent=None):
        gid = self._id("g")
        self.groups[gid] = {"name": name, "parent": parent, "roles": {role} if role else set(), "client_roles": set(), "members": set(), "attrs": {}}
        return gid

    def gid(self, name):
        return next((g for g, v in self.groups.items() if v["name"] == name), None)

    def path(self, gid):
        g = self.groups[gid]
        return (self.path(g["parent"]) if g["parent"] else "") + "/" + g["name"]

    def effective(self, uid) -> set[str]:
        out = set(self.direct.get(uid, set()))
        for gid, g in self.groups.items():
            if uid in g["members"]:
                cur = gid
                while cur:  # a member inherits the mappings of every ancestor group
                    out |= self.groups[cur]["roles"]
                    cur = self.groups[cur]["parent"]
        return out

    def member_groups(self, uid) -> set[str]:
        return {g["name"] for g in self.groups.values() if uid in g["members"]}

    def rep(self, gid):
        return {"id": gid, "name": self.groups[gid]["name"], "path": self.path(gid)}

    def tree(self, gid):
        return {**self.rep(gid), "subGroups": [self.tree(c) for c, v in self.groups.items() if v["parent"] == gid]}

    # ---- HTTP
    def handler(self, req: httpx.Request) -> httpx.Response:  # noqa: C901
        m, p, q = req.method, req.url.path.split("/admin/realms/soc", 1)[-1], req.url.params
        self.calls.append((m, p))
        if "openid-connect/token" in req.url.path:
            return httpx.Response(200, json={"access_token": "tok"})
        first, mx = int(q.get("first", 0)), int(q.get("max", 100))
        body = json.loads(req.content) if req.content else None
        parts = p.strip("/").split("/")
        if parts[0] == "groups" and (self.deny_groups or (self.deny_group_writes and m != "GET")):
            return httpx.Response(403)
        if parts[0] == "roles":
            if len(parts) == 2:
                return httpx.Response(200, json={"id": f"role-{parts[1]}", "name": parts[1]}) if parts[1] in SOC_ROLES else httpx.Response(404)
            ids = sorted(u for u, r in self.direct.items() if parts[1] in r)
            return httpx.Response(200, json=[self.users[i] for i in ids[first:first + mx]])
        if parts[0] == "clients":
            return self._clients(m, parts, q, body, first, mx)
        if parts[0] == "groups":
            return self._groups(m, parts, q, body, first, mx)
        if parts[0] == "users":
            return self._users(m, parts, q, body, first, mx)
        return httpx.Response(404)

    def _clients(self, m, parts, q, body, first, mx):
        if len(parts) == 1:
            if self.deny_client_list:
                return httpx.Response(403)
            return httpx.Response(200, json=[{"id": "cu-1", "clientId": self.client_id}] if self.client_exists and q.get("clientId") == self.client_id else [])
        if parts[1] != "cu-1" or parts[2] != "roles":
            return httpx.Response(404)
        if len(parts) == 3 and m == "GET":
            return httpx.Response(200, json=sorted(self.client_roles.values(), key=lambda r: r["name"])[first:first + mx])
        if len(parts) == 3 and m == "POST":
            if self.deny_client_roles:
                return httpx.Response(403)
            if body["name"] in self.client_roles:
                return httpx.Response(409)
            self.client_roles[body["name"]] = {"id": self._id("cr"), **body}
            return httpx.Response(201)
        if len(parts) == 4 and m == "PUT":
            self.client_roles[parts[3]].update(body)
            return httpx.Response(204)
        return httpx.Response(404)

    def _groups(self, m, parts, q, body, first, mx):
        if len(parts) == 1 and m == "GET":
            hits = {g for g, v in self.groups.items() if v["name"] == q.get("search")}
            roots = {self._root(g) for g in hits}
            return httpx.Response(200, json=[self._prune(self.tree(r), hits) for r in sorted(roots)])
        if len(parts) == 1 and m == "POST":
            return self._create(body["name"], None)
        g = self.groups.get(parts[1])
        if g is None:
            return httpx.Response(404)
        rest = parts[2:]
        if not rest:
            if m == "GET":
                return httpx.Response(200, json={**self.rep(parts[1]), "attributes": g["attrs"]})
            if self.deny_group_put:
                return httpx.Response(403)
            g["name"] = body["name"]  # PUT
            g["attrs"] = body.get("attributes", g["attrs"])
            return httpx.Response(204)
        if rest == ["children"] and m == "POST":
            if "id" in body:  # move an existing group under this one
                self.groups[body["id"]]["parent"] = parts[1]
                return httpx.Response(204)
            return self._create(body["name"], parts[1])
        if rest == ["role-mappings", "realm"]:
            if m == "GET":
                return httpx.Response(200, json=[{"id": f"role-{r}", "name": r} for r in g["roles"]])
            g["roles"].update(r["name"] for r in body)
            return httpx.Response(204)
        if rest[:2] == ["role-mappings", "clients"]:
            if m == "GET":
                return httpx.Response(200, json=[self.client_roles[n] for n in sorted(g["client_roles"])])
            names = {r["name"] for r in body}
            g["client_roles"] = (g["client_roles"] | names) if m == "POST" else (g["client_roles"] - names)
            return httpx.Response(204)
        if rest == ["members"]:
            return httpx.Response(200, json=[self.users[u] for u in sorted(g["members"])[first:first + mx]])
        return httpx.Response(404)

    def _root(self, gid):
        while self.groups[gid]["parent"]:
            gid = self.groups[gid]["parent"]
        return gid

    def _prune(self, node, hits):
        kids = [self._prune(k, hits) for k in node["subGroups"]]
        node["subGroups"] = [k for k in kids if k["id"] in hits or k["subGroups"]]
        return node

    def _create(self, name, parent):
        if any(v["name"] == name and v["parent"] == parent for v in self.groups.values()):
            return httpx.Response(409)
        return httpx.Response(201, headers={"location": f"{KC}/admin/realms/soc/groups/{self.add_group(name, parent=parent)}"})

    def _users(self, m, parts, q, body, first, mx):
        if q.get("username") == "service-account-soc-admin":  # service accounts are not in the normal user list
            return httpx.Response(200, json=[{"id": "sa-1"}] if self.sa_roles is not None else [])
        if parts[:3] == ["users", "sa-1", "role-mappings"]:
            return httpx.Response(200, json={"clientMappings": {"realm-management": {"mappings": [{"name": r} for r in self.sa_roles or []]}}})
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
            return httpx.Response(200, json=[self.rep(g) for g, v in self.groups.items() if uid in v["members"]])
        if rest[0] == "groups" and len(rest) == 2:
            self.groups[rest[1]]["members"].add(uid) if m == "PUT" else self.groups[rest[1]]["members"].discard(uid)
            return httpx.Response(204)
        if rest == ["logout"]:
            return httpx.Response(204)
        return httpx.Response(404)


@pytest.fixture()
def kcg(monkeypatch):
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_KC_ADMIN_URL": KC, "SOC_KC_ADMIN_CLIENT_SECRET": "svc", "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "soc-platform", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    fake = GroupKeycloak()
    auth_api.set_http(httpx.Client(transport=httpx.MockTransport(fake.handler)))
    yield fake
    auth_api.set_http(None)
    set_role_overrides(None)


def _client(fake):
    return httpx.Client(transport=httpx.MockTransport(fake.handler))


def _soc_user(email, subject, role="viewer"):
    with dbmod.session_scope() as db:
        u = User(subject=subject, email=email, name=email.split("@")[0], role=role)
        db.add(u)
        db.flush()
        return u.id


# --------------------------------------------------------------------------- layout
def test_ensure_groups_builds_the_hierarchy_and_maps_realm_roles(kcg):
    ids, created = kc.ensure_groups(_client(kcg))
    assert sorted(created) == sorted(G.values()) and set(ids) == set(G)
    assert kcg.path(ids["l2"]) == "/SOC Analysts/SOC L2 Analysts" and kcg.path(ids["admin"]) == "/SOC Admins"
    assert {kcg.groups[ids[r]]["name"]: kcg.groups[ids[r]]["roles"] for r in G} == {name: {role} for role, name in G.items()}
    n = len(kcg.groups)
    assert kc.ensure_groups(_client(kcg))[1] == [] and len(kcg.groups) == n  # idempotent


def test_first_version_groups_are_migrated_in_place_keeping_members(kcg):
    l1 = kcg.add_group("SOC L1 Analysts", "l1")
    l2 = kcg.add_group("SOC L2 Analysts", "l2")  # top level in the first version
    u1, u2 = kcg.add_user("a@t.local"), kcg.add_user("b@t.local")
    kcg.groups[l1]["members"].add(u1)
    kcg.groups[l2]["members"].add(u2)
    ids, created = kc.ensure_groups(_client(kcg))
    assert ids["l1"] == l1 and ids["l2"] == l2  # same groups, not copies
    assert "SOC Analysts" not in created and "SOC L2 Analysts" not in created
    assert kcg.groups[l1]["name"] == "SOC Analysts" and kcg.path(l2) == "/SOC Analysts/SOC L2 Analysts"
    assert kcg.effective(u1) == {"l1"} and kcg.effective(u2) == {"l1", "l2"}  # the L2 member inherits Analysts' role
    assert kcg.gid("SOC L1 Analysts") is None


# --------------------------------------------------------------------------- permission mirror
def test_permissions_are_mirrored_as_client_roles_on_each_group(kcg):
    ids, _ = kc.ensure_groups(_client(kcg))
    out = kc.sync_acl(_client(kcg), ids)
    assert out["permissions_created"] == len(CAPABILITIES) and set(kcg.client_roles) == set(CAPABILITIES)
    assert kcg.client_roles["alerts.triage"]["description"] == "Alerts: triage (default minimum role: l1)"
    mapped = {r: kcg.groups[ids[r]]["client_roles"] for r in G}
    assert mapped["viewer"] == set(role_capabilities("viewer")) and mapped["l1"] == set(role_capabilities("l1"))
    assert mapped["l2"] == set(role_capabilities("l2")) - set(role_capabilities("l1"))  # the child lists only what it adds
    assert mapped["admin"] == set(CAPABILITIES) == mapped["superadmin"]
    assert "alerts.delete" not in mapped["l2"] and "alerts.delete" in mapped["admin"]
    again = kc.sync_acl(_client(kcg), ids)
    assert again == {"permissions_created": 0, "permissions_updated": 0, "mappings_added": 0, "mappings_removed": 0}  # idempotent


def test_mirror_follows_changes_to_the_soc_permission_matrix(kcg):
    ids, _ = kc.ensure_groups(_client(kcg))
    kc.sync_acl(_client(kcg), ids)
    base = set(role_capabilities("viewer"))
    set_role_overrides({"viewer": sorted(base - {"alerts.read"}) + ["cases.close"]})
    out = kc.sync_acl(_client(kcg), ids)
    assert out["mappings_added"] >= 1 and out["mappings_removed"] >= 1
    viewer = kcg.groups[ids["viewer"]]["client_roles"]
    assert "alerts.read" not in viewer and "cases.close" in viewer


def test_mirror_reports_missing_service_account_permission(kcg):
    ids, _ = kc.ensure_groups(_client(kcg))
    kcg.deny_client_roles = True
    with pytest.raises(kc.KcError, match="manage-clients"):
        kc.sync_acl(_client(kcg), ids)


# --------------------------------------------------------------------------- membership through SOC
@pytest.mark.parametrize("role,group", [("l1", "SOC Analysts"), ("l2", "SOC L2 Analysts"), ("admin", "SOC Admins"), ("viewer", "SOC Viewers")])
def test_new_user_joins_the_role_group_without_a_direct_role(superadmin, kcg, role, group):
    r = superadmin.post("/api/admin/users", {"email": f"{role}@t.local", "name": "Ana A", "role": role, "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = next(u for u, v in kcg.users.items() if v["email"] == f"{role}@t.local")
    assert kcg.member_groups(uid) == {group} and kcg.direct[uid] == set() and role in kcg.effective(uid)


def test_new_user_falls_back_to_a_direct_role_when_groups_are_denied(superadmin, kcg):
    kcg.deny_groups = True
    r = superadmin.post("/api/admin/users", {"email": "bo@t.local", "name": "Bo B", "role": "l1", "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = next(u for u, v in kcg.users.items() if v["email"] == "bo@t.local")
    assert kcg.direct[uid] == {"l1"} and kcg.member_groups(uid) == set()


def test_role_change_moves_between_groups_and_removes_direct_roles(superadmin, kcg):
    uid = kcg.add_user("cy@t.local", direct={"viewer"}, groups=["SOC Viewers"])
    soc_id = _soc_user("cy@t.local", uid)
    assert superadmin.patch(f"/api/admin/users/{soc_id}", {"role": "l2"}).status_code == 200
    assert kcg.member_groups(uid) == {"SOC L2 Analysts"} and kcg.direct[uid] == set() and kcg.effective(uid) == {"l1", "l2"}
    assert superadmin.patch(f"/api/admin/users/{soc_id}", {"role": "l1"}).status_code == 200
    assert kcg.member_groups(uid) == {"SOC Analysts"} and kcg.effective(uid) == {"l1"}


def test_role_change_without_group_access_keeps_the_direct_role_behaviour(superadmin, kcg):
    uid = kcg.add_user("di@t.local", direct={"viewer"})
    soc_id = _soc_user("di@t.local", uid)
    kcg.deny_groups = True
    assert superadmin.patch(f"/api/admin/users/{soc_id}", {"role": "l2"}).status_code == 200
    assert kcg.direct[uid] == {"l2"} and kcg.member_groups(uid) == set()


def test_soc_never_adds_or_removes_anyone_from_the_super_admin_group(kcg):
    ids, _ = kc.ensure_groups(_client(kcg))
    owner = kcg.add_user("owner@t.local", groups=[G["superadmin"]])
    kc._put_in_group(_client(kcg), owner, "viewer", ids)
    assert kcg.member_groups(owner) == {G["superadmin"], G["viewer"]}  # membership in the owner group is left alone


# --------------------------------------------------------------------------- sync
def test_sync_creates_groups_mirrors_permissions_and_reads_group_roles(superadmin, kcg):
    kcg.add_user("via-group@t.local", groups=["SOC Analysts"])
    kcg.add_user("l2-member@t.local", groups=["SOC L2 Analysts"])
    kcg.add_user("both@t.local", direct={"viewer"}, groups=["SOC Admins"])
    kcg.add_user("nothing@t.local")
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert sorted(out["imported"]) == ["both@t.local", "l2-member@t.local", "via-group@t.local"] and out["groups_error"] == "" and out["acl_error"] == ""
    assert out["acl"]["permissions_created"] == len(CAPABILITIES) and out["realm"] == "soc" and out["keycloak_users"] == 4
    assert {s["email"] for s in out["skipped"]} == {"nothing@t.local"}
    with dbmod.session_scope() as db:
        roles = {u.email: u.role for u in db.execute(select(User)).scalars()}
    assert roles["via-group@t.local"] == "l1" and roles["l2-member@t.local"] == "l2" and roles["both@t.local"] == "admin"
    again = superadmin.post("/api/admin/users/sync", {}).json()
    assert again["groups_created"] == [] and again["acl"]["permissions_created"] == 0 and again["acl"]["mappings_added"] == 0


def test_sync_lists_permissions_as_group_attributes_when_client_roles_are_not_allowed(superadmin, kcg):
    kcg.add_user("plain@t.local", direct={"l1"})
    kcg.deny_client_list = True  # the service account has no view-clients
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["imported"] == ["plain@t.local"] and out["acl_mode"] == "attributes" and out["acl_error"] == "" and out["acl"]["groups_updated"] == len(G)
    viewer = kcg.groups[kcg.gid("SOC Viewers")]["attrs"]
    assert viewer["soc_role"] == ["viewer"] and viewer["soc_permissions"] == sorted(role_capabilities("viewer"))
    l2 = kcg.groups[kcg.gid("SOC L2 Analysts")]["attrs"]
    assert l2["soc_inherits"] == ["SOC Analysts"] and "alerts.triage" not in l2["soc_permissions"]  # a subgroup lists only what it adds
    assert not kcg.client_roles
    again = superadmin.post("/api/admin/users/sync", {}).json()
    assert again["acl_mode"] == "attributes" and again["acl"]["groups_updated"] == 0  # idempotent


def test_attributes_fallback_is_also_used_when_creating_client_roles_is_not_allowed(superadmin, kcg):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.deny_client_roles = True  # can read clients but not create roles (view-clients without manage-clients)
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "attributes" and out["acl_error"] == ""


def test_acl_error_when_neither_client_roles_nor_attributes_are_allowed(superadmin, kcg):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.deny_client_list = True
    kcg.deny_group_put = True
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "" and "not allowed to edit groups" in out["acl_error"] and out["groups_error"] == ""


def test_an_empty_client_search_is_treated_as_not_visible_and_falls_back(superadmin, kcg):
    """Keycloak answers an empty list, not a 403, when the service account may not view the client; SOC signs in through that client, so it exists."""
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.client_exists = False
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "attributes" and out["acl_error"] == "" and out["acl"]["groups_updated"] == len(G)
    with pytest.raises(kc.KcForbidden, match="cannot see the 'soc-platform' client"):
        kc.sync_acl(_client(kcg), kc.ensure_groups(_client(kcg))[0])


def test_the_configured_client_id_is_the_one_that_gets_the_permissions(superadmin, kcg, monkeypatch):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.client_id = "custom-app"
    monkeypatch.setenv("SOC_OIDC_CLIENT_ID", "custom-app")
    reset_settings_cache()
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "roles" and out["acl_error"] == "" and set(kcg.client_roles) == set(CAPABILITIES)


def test_sync_still_runs_and_reports_when_groups_cannot_be_created(superadmin, kcg):
    kcg.add_user("plain@t.local", direct={"l1"})
    kcg.deny_group_writes = True
    r = superadmin.post("/api/admin/users/sync", {})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["imported"] == ["plain@t.local"] and out["groups_created"] == [] and "could not create group" in out["groups_error"] and not kcg.groups


def test_sync_fails_clearly_rather_than_misreading_roles_when_groups_cannot_be_read(superadmin, kcg):
    kcg.add_user("via-group@t.local", groups=["SOC L2 Analysts"])
    kcg.deny_groups = True
    r = superadmin.post("/api/admin/users/sync", {})
    assert r.status_code == 502 and "groups" in r.text
    with dbmod.session_scope() as db:
        assert db.execute(select(User).where(User.email == "via-group@t.local")).first() is None


def test_saving_the_permission_matrix_updates_keycloak(superadmin, kcg):
    matrix = {r: sorted(role_capabilities(r)) for r in ("viewer", "l1", "l2", "admin")}
    matrix["viewer"] = [c for c in matrix["viewer"] if c != "alerts.read"]
    r = superadmin.put("/api/admin/permissions", {"matrix": matrix})
    assert r.status_code == 200 and r.json()["keycloak_acl"] == "synced (roles)", r.text
    assert "alerts.read" not in kcg.groups[kcg.gid("SOC Viewers")]["client_roles"]
    kcg.deny_groups = True
    matrix["viewer"].append("alerts.read")
    r = superadmin.put("/api/admin/permissions", {"matrix": matrix})
    assert r.status_code == 200 and r.json()["keycloak_acl"].startswith("not synced")  # saving the matrix never fails because of Keycloak


def test_listing_users_reads_nested_and_super_admin_groups(kcg):
    for i in range(130):
        kcg.add_user(f"m{i}@t.local", groups=["SOC Viewers"])
    kc.ensure_groups(_client(kcg))
    kcg.groups[kcg.gid("SOC L2 Analysts")]["members"].add(kcg.add_user("l2@t.local"))
    kcg.groups[kcg.gid("SOC Super Admins")]["members"].add(kcg.add_user("owner@t.local"))
    rows = {r["email"]: r["role"] for r in kc.list_users(_client(kcg))}
    assert len(rows) == 132 and rows["m0@t.local"] == "viewer" and rows["l2@t.local"] == "l2" and rows["owner@t.local"] == "superadmin"


# --------------------------------------------------------------------------- new installs
def test_realm_import_matches_the_rbac_definition():
    """deploy/keycloak/soc-realm.json must list exactly the groups and permissions policy.py defines (regenerate it if this fails)."""
    realm = json.load(open("../deploy/keycloak/soc-realm.json"))
    assert realm["groups"] == acl.realm_groups()
    assert realm["roles"]["client"][acl.CLIENT_ID] == acl.realm_client_roles()


# --------------------------------------------------------------------------- sync diagnostics
def test_sync_reports_which_service_account_roles_are_missing_for_role_mappings(superadmin, kcg):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.deny_client_list = True  # attributes mode: the roles are not there yet
    kcg.sa_roles = ["manage-users", "view-users", "view-clients"]
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "attributes"
    assert out["access"] == {"roles": ["manage-users", "view-clients", "view-users"], "missing_for_role_mappings": ["manage-clients"]}


def test_realm_admin_counts_as_having_everything(superadmin, kcg):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.deny_client_list = True
    kcg.sa_roles = ["realm-admin"]
    assert superadmin.post("/api/admin/users/sync", {}).json()["access"]["missing_for_role_mappings"] == []


def test_access_is_omitted_when_keycloak_will_not_say_and_when_roles_are_mirrored(superadmin, kcg):
    kcg.add_user("u@t.local", direct={"l1"})
    kcg.deny_client_list = True
    assert superadmin.post("/api/admin/users/sync", {}).json()["access"] is None  # sa_roles is None: unreadable, sync unaffected
    kcg.deny_client_list = False
    kcg.sa_roles = ["manage-clients", "view-clients"]
    out = superadmin.post("/api/admin/users/sync", {}).json()
    assert out["acl_mode"] == "roles" and out["access"] is None  # nothing to diagnose


def test_sync_lists_soc_accounts_that_were_never_created_in_keycloak(superadmin, kcg):
    kcg.add_user("linked@t.local", direct={"l1"})
    kcg.add_user("placeholder@t.local", direct={"viewer"})  # exists in Keycloak: gets linked by this sync, so it is not "unlinked"
    with dbmod.session_scope() as db:
        db.add(User(subject="pending:never@t.local", email="never@t.local", role="viewer"))
        db.add(User(subject="dev:old@t.local", email="old@t.local", role="l1"))
        db.add(User(subject="pending:off@t.local", email="off@t.local", role="viewer", active=False))
        db.add(User(subject="deleted:gone", email="deleted-x@deleted.invalid", role="viewer", active=False))
        db.add(User(subject="pending:placeholder@t.local", email="placeholder@t.local", role="viewer"))
    out = superadmin.post("/api/admin/users/sync", {}).json()
    # (the test's own sign-in account is a local dev: account too, so it is listed as well)
    assert {"never@t.local", "old@t.local"} <= set(out["unlinked"]) and out["linked"] == ["placeholder@t.local"]
    assert not {"off@t.local", "placeholder@t.local", "deleted-x@deleted.invalid", "linked@t.local"} & set(out["unlinked"])  # disabled, just linked, deleted and linked ones are not listed
