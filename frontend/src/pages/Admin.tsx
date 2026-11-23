import { useQuery } from '@tanstack/react-query';
import { useMemo, useRef, useState } from 'react';
import { Summary } from '../components/manage';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, SearchBox, useToast } from '../components/ui';
import { del, get, patch, post, put, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { SEVERITIES, ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';

const TABS = [
  ['users', 'Users', 'admin.users'], ['permissions', 'Permissions', 'admin.users'], ['audit', 'Audit log', 'admin.audit'], ['sla', 'SLA', 'admin.settings'],
  ['retention', 'Retention & settings', 'admin.settings'], ['health', 'Health & backups', 'admin.settings'], ['tokens', 'API tokens', 'admin.tokens'],
] as const;

export default function Admin() {
  const { can } = useAuth();
  const tabs = TABS.filter((t) => can(t[2]));
  const [tab, setTab] = useState<string>(tabs[0]?.[0] ?? 'tokens');
  return (
    <>
      <PageHead title="Administration" sub="Users, audit, policies and platform health. Sensitive changes ask you to confirm with MFA." />
      <div className="tabs" role="tablist">{tabs.map(([k, label]) => <button key={k} role="tab" aria-selected={tab === k} className={`tab${tab === k ? ' active' : ''}`} onClick={() => setTab(k)}>{label}</button>)}</div>
      {tab === 'users' && <Users />}
      {tab === 'permissions' && <Permissions />}
      {tab === 'audit' && <Audit />}
      {tab === 'sla' && <Sla />}
      {tab === 'retention' && <Retention />}
      {tab === 'health' && <Health />}
      {tab === 'tokens' && <Tokens />}
    </>
  );
}

function Users() {
  const { me, can } = useAuth();
  const toast = useToast();
  const users = useQuery({ queryKey: ['users'], queryFn: () => get<any[]>('/api/admin/users') });
  const authConfig = useQuery({ queryKey: ['auth-config'], queryFn: () => get<{ auth_mode: string; user_provisioning: boolean }>('/api/auth/config') });
  const provisioning = authConfig.data?.user_provisioning ?? false;
  const canProvision = can('users.provision') && provisioning;
  const clients = useQuery({ queryKey: ['clients'], queryFn: () => get<any[]>('/api/clients') });
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: () => get<any[]>('/api/admin/sessions') });
  const [add, setAdd] = useState(false);
  const [edit, setEdit] = useState<any>(null);
  const [passwordUser, setPasswordUser] = useState<any>(null);
  const [deleteTarget, setDeleteTarget] = useState<any>(null);
  const [syncing, setSyncing] = useState(false);
  const [uq, setUq] = useState('');
  const [ur, setUr] = useState('');
  const revoke = useAct((id: string) => post(`/api/admin/users/${id}/revoke-sessions`), ['users', 'sessions'], 'Sessions revoked');
  const setActive = useAct((a: { id: string; active: boolean }) => patch(`/api/admin/users/${a.id}`, { active: a.active }), ['users'], 'User updated');
  const oidc = me?.auth_mode === 'oidc';
  const rows = (users.data ?? []).filter((u: any) => (!uq.trim() || `${u.email} ${u.name}`.toLowerCase().includes(uq.trim().toLowerCase())) && (!ur || (ur === 'disabled' ? !u.active : u.role === ur)));
  return (
    <>
      <div className="row" style={{ marginBottom: 8 }}><h2>Users</h2><span className="spacer" />
        {!oidc && <span style={{ color: 'var(--muted)' }}>Development mode: users and passwords are local to SOC; they are not created in Keycloak.</span>}
        {oidc && <span style={{ color: 'var(--muted)' }}>{provisioning ? 'Account profiles, roles and passwords are synced with Keycloak.' : 'Accounts and roles are managed in your identity provider; users appear here after their first sign-in.'}</span>}
        {canProvision && oidc && <button className="btn small" onClick={() => setSyncing(true)}>Sync with Keycloak</button>}
        {canProvision && <button className="btn small" onClick={() => setAdd(true)}>Add user</button>}</div>
      {users.data && (
        <>
          <Summary items={[
            { label: 'Users', value: users.data.length, onClick: () => setUr(''), active: !ur },
            { label: 'Active', value: users.data.filter((u: any) => u.active).length, tone: 'ok' },
            { label: 'Disabled', value: users.data.filter((u: any) => !u.active).length, tone: users.data.some((u: any) => !u.active) ? 'warn' : 'ok', onClick: () => setUr(ur === 'disabled' ? '' : 'disabled'), active: ur === 'disabled' },
            ...['admin', 'l2', 'l1', 'viewer'].map((r) => ({ label: r === 'admin' ? 'Admins' : r === 'viewer' ? 'Viewers' : r.toUpperCase(), value: users.data.filter((u: any) => u.role === r).length, onClick: () => setUr(ur === r ? '' : r), active: ur === r })),
          ]} />
          <div className="filters"><SearchBox value={uq} onChange={setUq} placeholder="Search users…" label="Search users" /></div>
        </>
      )}
      {users.isLoading ? <Loading /> : users.error ? <ErrorBox error={users.error} /> : rows.length === 0 ? <Empty>No users match these filters.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Scope</th><th>Last login</th><th>State</th><th /></tr></thead>
          <tbody>{rows.map((u) => <tr key={u.id}><td>{u.email}{oidc && u.identity_status === 'local' && <small className="block">Local account · needs Keycloak provisioning</small>}</td><td>{u.name}</td><td>{u.role}</td><td>{u.all_clients ? 'All clients' : `${u.client_ids.length} client(s)`}</td><td>{ago(u.last_login_at)}</td><td>{u.active ? 'Active' : 'Disabled'}</td>
            <td className="row">{canProvision && u.id !== me?.id && u.role !== 'superadmin' && <button className="btn small" onClick={() => setPasswordUser(u)}>Reset password</button>}
              {u.id !== me?.id && u.role !== 'superadmin' && <button className="btn small" onClick={() => setEdit(u)}>Edit</button>}{(u.role !== 'superadmin' || me?.role === 'superadmin') && <button className="btn small" onClick={() => revoke.mutate(u.id)}>Sign out everywhere</button>}
              {u.id !== me?.id && u.role !== 'superadmin' && <button className="btn small" onClick={() => setActive.mutate({ id: u.id, active: !u.active })}>{u.active ? 'Disable' : 'Enable'}</button>}
              {canProvision && u.id !== me?.id && u.role !== 'superadmin' && <button className="btn small danger" onClick={() => setDeleteTarget(u)}>Delete</button>}</td></tr>)}</tbody></table></div>
      )}
      <h2 style={{ margin: '22px 0 8px' }}>Active sessions</h2>
      {sessions.data && sessions.data.length ? <div className="table-wrap"><table><thead><tr><th>User</th><th>IP</th><th>Started</th><th>Last seen</th></tr></thead><tbody>{sessions.data.map((s) => <tr key={s.id}><td>{s.user}</td><td className="mono">{s.ip}</td><td>{ago(s.created_at)}</td><td>{ago(s.last_seen_at)}</td></tr>)}</tbody></table></div> : <Empty>No active sessions.</Empty>}
      {add && <AddUser oidc={oidc} clients={clients.data ?? []} onClose={() => setAdd(false)} onSecret={(s) => toast(`Authenticator secret (shown once): ${s}`)} />}
      {passwordUser && <UserPassword u={passwordUser} oidc={oidc} onClose={() => setPasswordUser(null)} />}
      {deleteTarget && <DeleteUser u={deleteTarget} oidc={oidc} onClose={() => setDeleteTarget(null)} />}
      {syncing && <SyncKeycloak onClose={() => setSyncing(false)} />}
      {edit && <EditUser u={edit} canChangeRole={canProvision} clients={clients.data ?? []} onClose={() => setEdit(null)} />}
    </>
  );
}

function ClientPicker({ clients, sel, all, onSel, onAll }: { clients: any[]; sel: string[]; all: boolean; onSel: (s: string[]) => void; onAll: (b: boolean) => void }) {
  return (
    <fieldset><legend>Client access</legend>
      <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={all} onChange={(e) => onAll(e.target.checked)} /> All clients (full access)</label>
      {!all && clients.map((c) => <label key={c.id} className="row" style={{ gap: 6 }}><input type="checkbox" checked={sel.includes(c.id)} onChange={() => onSel(sel.includes(c.id) ? sel.filter((x) => x !== c.id) : [...sel, c.id])} /> {c.name}</label>)}
    </fieldset>
  );
}

function AddUser({ oidc, clients, onClose, onSecret }: { oidc: boolean; clients: any[]; onClose: () => void; onSecret: (s: string) => void }) {
  const [v, setV] = useState({ email: '', name: '', role: 'viewer', password: '', all_clients: false, client_ids: [] as string[] });
  const [secret, setSecret] = useState<string | null>(null);
  const m = useAct(() => post('/api/admin/users', v), ['users'], 'User created', (r) => { if (r.totp_secret) { setSecret(r.totp_secret); onSecret(r.totp_secret); } else onClose(); });
  if (secret) return <Modal title="User created" onClose={onClose}><div className="notice"><b>Authenticator secret (shown once)</b><div className="mono wrap">{secret}</div><p>Give this to the user over a secure channel to enrol their authenticator app.</p></div><button className="btn primary" onClick={onClose}>Done</button></Modal>;
  return (
    <Modal title="Add user" onClose={onClose}>
      <Field label="Email" id="ue"><input id="ue" type="email" value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} /></Field>
      <Field label="Name" id="un"><input id="un" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Role" id="ur" hint="Administrators can create users and other administrators directly."><select id="ur" value={v.role} onChange={(e) => setV({ ...v, role: e.target.value })}>{['viewer', 'l1', 'l2', 'admin'].map((r) => <option key={r}>{r}</option>)}</select></Field>
      <Field label={oidc ? "Temporary password (12+ chars, upper, lower, digit)" : "Initial password (12+ chars, upper, lower, digit)"} id="up"><input id="up" type="password" autoComplete="new-password" value={v.password} onChange={(e) => setV({ ...v, password: e.target.value })} /></Field>
      <ClientPicker clients={clients} sel={v.client_ids} all={v.all_clients} onSel={(s) => setV({ ...v, client_ids: s })} onAll={(b) => setV({ ...v, all_clients: b })} />
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !v.email.includes('@') || v.password.length < 12} onClick={() => m.mutate(undefined)}>Create</button>
    </Modal>
  );
}

function DeleteUser({ u, oidc, onClose }: { u: any; oidc: boolean; onClose: () => void }) {
  const toast = useToast();
  const [confirm, setConfirm] = useState('');
  const linked = oidc && u.identity_status === 'linked';
  const m = useAct(() => del<{ keycloak: string }>(`/api/admin/users/${u.id}`), ['users', 'sessions'], undefined, (r) => {
    toast(`${u.email} deleted${r.keycloak === 'deleted' ? ' from SOC and Keycloak' : r.keycloak === 'already_gone' ? ' (it was already gone from Keycloak)' : ''}`);
    onClose();
  });
  return <Modal title={`Delete ${u.email}`} onClose={() => { if (!m.isPending) onClose(); }}>
    <p>{linked ? 'This removes the account from Keycloak and from SOC.' : oidc ? 'This removes the SOC account. It has no linked Keycloak account, so Keycloak is not changed.' : 'This removes the local SOC account.'} They are signed out immediately and their open alerts, cases and tasks are unassigned. Past requests, approvals and the audit log are kept.</p>
    <Field label={`Type ${u.email} to confirm`} id="del-confirm"><input id="del-confirm" autoFocus value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={u.email} /></Field>
    {m.error && <ErrorBox error={m.error} />}
    <div className="row">
      <button className="btn" disabled={m.isPending} onClick={onClose}>Cancel</button>
      <button className="btn danger" disabled={m.isPending || confirm.trim().toLowerCase() !== u.email.toLowerCase()} onClick={() => m.mutate(undefined)}>{m.isPending ? 'Deleting…' : 'Delete account'}</button>
    </div>
  </Modal>;
}

type SyncResult = { imported: string[]; linked: string[]; updated: string[]; skipped: { email: string; reason: string }[]; removed: string[]; orphans: string[]; groups_created: string[]; groups_error: string };

function SyncKeycloak({ onClose }: { onClose: () => void }) {
  const [result, setResult] = useState<SyncResult | null>(null);
  const run = useAct((prune: boolean) => post<SyncResult>('/api/admin/users/sync', { prune }), ['users', 'sessions'], undefined, (r: SyncResult) => setResult(r));
  const list = (label: string, items: string[]) => items.length > 0 && <p><b>{label} ({items.length}):</b> {items.join(', ')}</p>;
  return <Modal title="Sync with Keycloak" onClose={() => { if (!run.isPending) onClose(); }}>
    <p>Imports users created in Keycloak, links local placeholders, and takes name, role and enabled state from Keycloak. It also creates the SOC role groups there (SOC Admins, SOC L2 Analysts, SOC L1 Analysts, SOC Viewers) if they are missing: adding a user to a group is what grants that role. Accounts deleted in Keycloak are listed first and only removed from SOC when you confirm.</p>
    {run.error && <ErrorBox error={run.error} />}
    {result && <div className="notice">
      {!result.imported.length && !result.linked.length && !result.updated.length && !result.removed.length && !result.orphans.length && !result.groups_created.length && <p>Already in sync.</p>}
      {list('Groups created in Keycloak', result.groups_created)}
      {result.groups_error && <p><b>Groups not created:</b> {result.groups_error}</p>}
      {list('Imported', result.imported)}{list('Linked', result.linked)}{list('Updated', result.updated)}{list('Removed from SOC', result.removed)}
      {list('Skipped', result.skipped.map((s) => `${s.email} (${s.reason})`))}
      {result.orphans.length > 0 && <p><b>No longer in Keycloak ({result.orphans.length}):</b> {result.orphans.join(', ')}</p>}
    </div>}
    <div className="row">
      <button className="btn" disabled={run.isPending} onClick={onClose}>Close</button>
      <button className="btn primary" disabled={run.isPending} onClick={() => run.mutate(false)}>{run.isPending ? 'Syncing…' : result ? 'Sync again' : 'Sync now'}</button>
      {result && result.orphans.length > 0 && <button className="btn danger" disabled={run.isPending} onClick={() => run.mutate(true)}>Remove {result.orphans.length} from SOC</button>}
    </div>
  </Modal>;
}

function UserPassword({ u, oidc, onClose }: { u: any; oidc: boolean; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [provision, setProvision] = useState(false);
  const m = useAct(() => post(`/api/admin/users/${u.id}/${provision ? 'provision' : 'password'}`, { password }), ['users', 'sessions'], provision ? 'User created in Keycloak' : 'Password reset; existing sessions ended', onClose);
  const valid = password.length >= 12 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password) && password === confirm;
  return <Modal title={`${provision ? 'Create in Keycloak' : 'Reset password'}: ${u.email}`} onClose={onClose}>
    <p>{oidc ? 'Set a temporary password. The user must change it at their next Keycloak sign-in. Existing SOC sessions will end.' : 'Set a new local SOC password. Existing sessions will end; authenticator enrolment stays unchanged.'}</p>
    {oidc && ['local', 'pending'].includes(u.identity_status) && <label className="row"><input type="checkbox" checked={provision} disabled={m.isPending} onChange={(e) => setProvision(e.target.checked)} /> Create in Keycloak (if this account does not exist there yet)</label>}
    <form onSubmit={(e) => { e.preventDefault(); if (valid && !m.isPending) m.mutate(undefined); }}>
      <Field label={oidc ? 'Temporary password' : 'New password'} id="reset-password" hint="At least 12 characters, with uppercase, lowercase and a digit."><input id="reset-password" type="password" autoComplete="new-password" maxLength={256} value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      <Field label="Confirm password" id="confirm-password"><input id="confirm-password" type="password" autoComplete="new-password" maxLength={256} value={confirm} onChange={(e) => setConfirm(e.target.value)} /></Field>
      {confirm && password !== confirm && <p role="status">Passwords do not match.</p>}
      {m.error && <ErrorBox error={m.error} />}
      <button type="submit" className="btn primary" disabled={!valid || m.isPending}>{m.isPending ? 'Saving…' : provision ? 'Create in Keycloak' : 'Reset password'}</button>
    </form>
  </Modal>;
}

function EditUser({ u, canChangeRole, clients, onClose }: { u: any; canChangeRole: boolean; clients: any[]; onClose: () => void }) {
  const toast = useToast();
  const [v, setV] = useState({ name: u.name, email: u.email, role: u.role, all_clients: u.all_clients, client_ids: u.client_ids as string[] });
  const m = useAct(() => patch(`/api/admin/users/${u.id}`, { name: v.name, ...(v.email.trim().toLowerCase() !== u.email ? { email: v.email } : {}), ...(!canChangeRole || v.role === u.role ? {} : { role: v.role }), all_clients: v.all_clients, client_ids: v.client_ids }), ['users', 'approvals'], undefined, (r) => { toast(r.pending_approval ? 'Admin promotion sent for second-admin approval' : 'User updated'); onClose(); });
  return (
    <Modal title={`Edit ${u.email}`} onClose={onClose}>
      <Field label="Email" id="ee"><input id="ee" type="email" disabled={!canChangeRole} value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} /></Field>
      <Field label="Name" id="en"><input id="en" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Role" id="er"><select id="er" disabled={!canChangeRole} value={v.role} onChange={(e) => setV({ ...v, role: e.target.value })}>{['viewer', 'l1', 'l2', 'admin'].map((r) => <option key={r}>{r}</option>)}</select></Field>
      <ClientPicker clients={clients} sel={v.client_ids} all={v.all_clients} onSel={(s) => setV({ ...v, client_ids: s })} onAll={(b) => setV({ ...v, all_clients: b })} />
      <p style={{ color: 'var(--muted)', fontSize: 13 }}>Per-user permission overrides are managed on the <strong>Permissions</strong> tab.</p>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)} onClick={() => m.mutate(undefined)} style={{ marginTop: 12 }}>Save</button>
    </Modal>
  );
}

const initials = (n: string) => n.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join('');

function Permissions() {
  const { can, me } = useAuth();
  const toast = useToast();
  const editable = can('users.provision');
  const users = useQuery({ queryKey: ['users'], queryFn: () => get<any[]>('/api/admin/users') });
  const perms = useQuery({ queryKey: ['permissions'], queryFn: () => get<any>('/api/admin/permissions') });
  const [uq, setUq] = useState('');
  const [selId, setSelId] = useState<string | null>(null);
  const list = (users.data ?? []).filter((u) => u.role !== 'superadmin' && u.id !== me?.id && (!uq || `${u.email} ${u.name}`.toLowerCase().includes(uq.toLowerCase())));
  const sel = list.find((u) => u.id === selId) ?? list[0] ?? null;

  const [grants, setGrants] = useState<string[]>([]);
  const [denied, setDenied] = useState<string[]>([]);
  const loadedFor = useRef<string | null>(null);
  if (sel && loadedFor.current !== sel.id) {
    loadedFor.current = sel.id;
    setGrants(sel.grants || []);
    setDenied(sel.denied || []);
  }

  const dirty = sel && (JSON.stringify([...grants].sort()) !== JSON.stringify([...(sel.grants || [])].sort()) || JSON.stringify([...denied].sort()) !== JSON.stringify([...(sel.denied || [])].sort()));
  const save = useAct(() => patch(`/api/admin/users/${sel.id}`, { grants, denied }), ['users'], 'Permissions updated', () => toast('Permissions updated'));

  const roleCaps = useMemo(() => (sel && perms.data ? new Set(perms.data.matrix[sel.role] || []) : new Set<string>()), [perms.data, sel]);
  const groups = useMemo(() => {
    if (!perms.data) return {};
    const g: Record<string, string[]> = {};
    for (const cap of perms.data.capabilities as string[]) {
      const [ns] = cap.split('.');
      (g[ns] ??= []).push(cap);
    }
    return g;
  }, [perms.data]);

  function cycle(cap: string) {
    if (!editable) return;
    const isGranted = grants.includes(cap);
    const isDenied = denied.includes(cap);
    if (!isGranted && !isDenied) {
      // role default -> force on (if not already from role) or force off
      if (roleCaps.has(cap)) setDenied([...denied, cap]);
      else setGrants([...grants, cap]);
    } else if (isGranted) {
      setGrants(grants.filter((c) => c !== cap));
    } else {
      setDenied(denied.filter((c) => c !== cap));
    }
  }

  return (
    <>
      <div className="row" style={{ marginBottom: 8, alignItems: 'flex-start' }}>
        <h2 style={{ margin: 0 }}>Permissions</h2>
        <span className="spacer" />
        {!editable && <span style={{ color: 'var(--muted)', fontSize: 13 }}>View only — user management permission is required to change permissions.</span>}
      </div>
      {(users.isLoading || perms.isLoading) ? <Loading /> : (users.error || perms.error) ? <ErrorBox error={users.error || perms.error} /> : (
        <div className="grid" style={{ gridTemplateColumns: 'minmax(220px, 280px) 1fr', gap: 18, alignItems: 'start' }}>
          <div>
            <div style={{ marginBottom: 10 }}><SearchBox value={uq} onChange={setUq} placeholder="Name or email…" label="Find a user" /></div>
            <ul className="perm-user-list">
              {list.map((u) => (
                <li key={u.id}>
                  <button type="button" className="perm-user" aria-pressed={sel?.id === u.id} onClick={() => setSelId(u.id)}>
                    <span className="avatar">{initials(u.name || u.email)}</span>
                    <span className="perm-user-meta">
                      <strong>{u.name || u.email}</strong>
                      <small>{titleCase(u.role)}{u.id === me?.id ? ' · you' : ''}{(u.grants?.length || u.denied?.length) ? ' · customised' : ''}</small>
                    </span>
                  </button>
                </li>
              ))}
              {list.length === 0 && <li className="empty">{uq ? 'No users match.' : 'No users found.'}</li>}
            </ul>
          </div>
          <div>
            {!sel && list.length === 0 && <Empty>{uq ? 'No users match your search.' : 'Invite or create a user to assign permissions.'}</Empty>}
            {sel && (
              <>
                <p style={{ color: 'var(--muted)', margin: '0 0 8px' }}>
                  <strong>{sel.name || sel.email}</strong> — base role <strong>{sel.role}</strong>.
                  {editable ? ' Click a capability to grant or restrict it for this user only.' : ''}
                  {dirty && <span style={{ color: 'var(--accent)', marginLeft: 8 }}>Unsaved changes</span>}
                </p>
                <div className="table-wrap" style={{ maxHeight: 460, overflowY: 'auto' }}>
                  <table style={{ fontSize: 13 }}>
                    <thead>
                      <tr>
                        <th style={{ position: 'sticky', top: 0, background: 'var(--bg)', zIndex: 2, minWidth: 200 }}>Capability</th>
                        <th style={{ position: 'sticky', top: 0, background: 'var(--bg)', zIndex: 2, width: 140 }}>State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(groups).map(([ns, caps]) => (
                        <>
                          <tr key={`hdr-${ns}`}><td colSpan={2} style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: 11, color: 'var(--muted)', paddingTop: 12, borderBottom: '1px solid var(--border)' }}>{ns}</td></tr>
                          {caps.map((cap) => {
                            const fromRole = roleCaps.has(cap);
                            const isGranted = grants.includes(cap);
                            const isDenied = denied.includes(cap);
                            const state = isDenied ? 'denied' : isGranted ? 'granted' : fromRole ? 'role' : 'none';
                            const label = { denied: 'Denied', granted: 'Granted (extra)', role: `Via ${sel.role} role`, none: 'Not available' }[state];
                            return (
                              <tr key={cap}>
                                <td className="mono" style={{ fontSize: 12 }}>{cap}</td>
                                <td>
                                  <button
                                    type="button" className="btn small" disabled={!editable} onClick={() => cycle(cap)}
                                    style={{ color: state === 'denied' ? 'var(--danger, #c0392b)' : state === 'granted' ? 'var(--accent)' : undefined, width: '100%' }}
                                  >
                                    {label}
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
                {save.error && <ErrorBox error={save.error} />}
                {editable && <button className="btn primary" disabled={!dirty || save.isPending} onClick={() => save.mutate(undefined)} style={{ marginTop: 12 }}>Save permissions</button>}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function Audit() {
  const [page, setPage] = useState(1);
  const [f, setF] = useState({ action: '', actor: '', outcome: '' });
  const q = useQuery({ queryKey: ['audit', f, page], queryFn: () => get<Page<any>>('/api/admin/audit', { ...f, page, limit: 100 }) });
  const [verify, setVerify] = useState<any>(null);
  const v = useAct(() => get('/api/admin/audit/verify'), [], undefined, setVerify);
  const upd = (k: string, x: string) => { setF({ ...f, [k]: x }); setPage(1); };
  return (
    <>
      <div className="filters">
        <input placeholder="Action prefix (e.g. tool.)" aria-label="Action" value={f.action} onChange={(e) => upd('action', e.target.value)} />
        <input placeholder="Actor" aria-label="Actor" value={f.actor} onChange={(e) => upd('actor', e.target.value)} />
        <select aria-label="Outcome" value={f.outcome} onChange={(e) => upd('outcome', e.target.value)}><option value="">Any outcome</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option></select>
        <span className="spacer" />
        <button className="btn small" onClick={() => v.mutate(undefined)} disabled={v.isPending}>Verify integrity</button>
        <a className="btn small" href="/api/admin/audit/export" download>Export CSV</a>
      </div>
      {verify && <div className={verify.ok ? 'notice' : 'error'} role="status">{verify.ok ? `Audit chain verified: ${verify.checked} entries intact.` : `Chain broken at entry ${verify.broken_at}.`}</div>}
      {v.error && <ErrorBox error={v.error} />}
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No audit entries.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th><th>IP</th></tr></thead>
            <tbody>{q.data!.items.map((e) => <tr key={e.id}><td>{when(e.ts)}</td><td>{e.actor}</td><td className="mono">{e.action}</td><td className="mono wrap">{e.resource_type ? `${e.resource_type}:${String(e.resource_id ?? '').slice(0, 8)}` : '—'}</td><td>{e.outcome}</td><td className="mono">{e.ip}</td></tr>)}</tbody></table></div>
          <Pager page={page} limit={100} total={q.data!.total} set={setPage} />
        </>
      )}
    </>
  );
}

function Sla() {
  const q = useQuery({ queryKey: ['sla'], queryFn: () => get<any>('/api/admin/sla') });
  const [t, setT] = useState<Record<string, Record<string, number>> | null>(null);
  const [note, setNote] = useState('');
  const save = useAct(() => put('/api/admin/sla', { targets: t, note }), ['sla'], 'New SLA version saved', () => { setT(null); setNote(''); });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const cur = t ?? q.data.targets;
  const keys = Object.keys(cur[SEVERITIES[0]] ?? { ack_minutes: 0, resolve_minutes: 0 });
  const set = (sev: string, k: string, n: number) => setT({ ...cur, [sev]: { ...cur[sev], [k]: n } });
  return (
    <>
      <p>Active policy v{q.data.version}. Changes create a new version; existing items keep their original deadlines.</p>
      <div className="table-wrap"><table><thead><tr><th>Severity</th>{keys.map((k) => <th key={k}>{titleCase(k)}</th>)}</tr></thead>
        <tbody>{SEVERITIES.map((s) => <tr key={s}><td>{s}</td>{keys.map((k) => <td key={k}><input type="number" min={1} aria-label={`${s} ${k}`} style={{ width: 100 }} value={cur[s]?.[k] ?? ''} onChange={(e) => set(s, k, Number(e.target.value))} /></td>)}</tr>)}</tbody></table></div>
      <div className="row" style={{ marginTop: 10 }}><input placeholder="Reason for change" aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn primary" disabled={!t || save.isPending} onClick={() => save.mutate(undefined)}>Save new version</button></div>
      {save.error && <ErrorBox error={save.error} />}
      <h3 style={{ marginTop: 18 }}>History</h3>
      <div className="table-wrap"><table><thead><tr><th>Version</th><th>Effective</th><th>By</th><th>Note</th><th /></tr></thead><tbody>{q.data.history.map((h: any) => <tr key={h.version}><td>v{h.version}</td><td>{when(h.effective_from)}</td><td>{h.created_by}</td><td className="wrap">{h.note}</td><td>{h.active && 'Active'}</td></tr>)}</tbody></table></div>
    </>
  );
}

const SETTING_LABELS: Record<string, string> = { alert_dedup_minutes: 'Alert de-duplication window (minutes)', approval_window_minutes: 'Approval validity window (minutes)', response_max_per_hour: 'Response actions allowed per hour' };

function Retention() {
  const toast = useToast();
  const ret = useQuery({ queryKey: ['retention'], queryFn: () => get<any[]>('/api/admin/retention') });
  const st = useQuery({ queryKey: ['settings'], queryFn: () => get<Record<string, number>>('/api/admin/settings') });
  const [draft, setDraft] = useState<Record<string, number>>({});
  const saveSettings = useAct(() => put('/api/admin/settings', { values: draft }), ['settings'], 'Settings saved', () => setDraft({}));
  const saveRet = useAct((a: { dataset: string; days: number; legal_hold: boolean }) => put('/api/admin/retention', a), ['retention', 'approvals'], undefined, (r) => toast(r.pending_approval ? 'Reduction sent for second-admin approval' : 'Retention updated'));
  return (
    <>
      <h2 style={{ marginBottom: 8 }}>Retention</h2>
      {ret.isLoading ? <Loading /> : ret.error ? <ErrorBox error={ret.error} /> : (
        <div className="table-wrap"><table><thead><tr><th>Dataset</th><th>Days</th><th>Minimum</th><th>Legal hold</th><th /></tr></thead>
          <tbody>{ret.data!.map((r) => <RetRow key={r.dataset} r={r} onSave={(days, hold) => saveRet.mutate({ dataset: r.dataset, days, legal_hold: hold })} />)}</tbody></table></div>
      )}
      {saveRet.error && <ErrorBox error={saveRet.error} />}
      <p style={{ color: 'var(--muted)' }}>Reducing retention or lifting a legal hold needs a second administrator to approve.</p>
      <h2 style={{ margin: '22px 0 8px' }}>Operational settings</h2>
      {st.data && Object.keys(SETTING_LABELS).map((k) => <Field key={k} label={SETTING_LABELS[k]} id={`s-${k}`}><input id={`s-${k}`} type="number" value={draft[k] ?? st.data![k] ?? ''} onChange={(e) => setDraft({ ...draft, [k]: Number(e.target.value) })} /></Field>)}
      {saveSettings.error && <ErrorBox error={saveSettings.error} />}
      <button className="btn primary" disabled={!Object.keys(draft).length || saveSettings.isPending} onClick={() => saveSettings.mutate(undefined)}>Save settings</button>
    </>
  );
}

function RetRow({ r, onSave }: { r: any; onSave: (days: number, hold: boolean) => void }) {
  const [days, setDays] = useState<number>(r.days);
  const [hold, setHold] = useState<boolean>(r.legal_hold);
  return <tr><td>{titleCase(r.dataset)}</td><td><input type="number" aria-label={`${r.dataset} days`} min={r.min_days} style={{ width: 90 }} value={days} onChange={(e) => setDays(Number(e.target.value))} /></td><td>{r.min_days}</td><td><input type="checkbox" aria-label={`${r.dataset} legal hold`} checked={hold} onChange={(e) => setHold(e.target.checked)} /></td><td><button className="btn small" disabled={days === r.days && hold === r.legal_hold} onClick={() => onSave(days, hold)}>Save</button></td></tr>;
}

function Health() {
  const h = useQuery({ queryKey: ['health'], queryFn: () => get<any>('/api/admin/health'), refetchInterval: 15000 });
  const bk = useQuery({ queryKey: ['backups'], queryFn: () => get<any[]>('/api/admin/backups') });
  const [add, setAdd] = useState(false);
  const verified = useAct((id: string) => post(`/api/admin/backups/${id}/report`, { status: 'success', verified: true }), ['backups'], 'Restore test recorded');
  const row = (label: string, val: string) => <tr key={label}><td>{label}</td><td><span className={`badge ${val === 'ok' || val === 'enabled' ? 'st-ok' : val === 'not configured' || val === 'disabled' ? 'st-degraded' : 'st-down'}`}>{val}</span></td></tr>;
  return (
    <>
      <h2 style={{ marginBottom: 8 }}>Platform health</h2>
      {h.isLoading ? <Loading /> : h.error ? <ErrorBox error={h.error} /> : (
        <div className="table-wrap"><table><tbody>
          {row('API', h.data.api)}{row('Database', h.data.database)}{row('Redis', h.data.redis)}{row('Background workers', h.data.workers)}
          <tr><td>Outbox</td><td>{h.data.outbox.pending} pending · {h.data.outbox.dead} dead-lettered · oldest {h.data.outbox.oldest_pending_seconds}s</td></tr>
          <tr><td>Integrations</td><td>{h.data.integrations.enabled} enabled · {h.data.integrations.failing} failing</td></tr>
        </tbody></table></div>
      )}
      <div className="row" style={{ margin: '22px 0 8px' }}><h2>Platform backups</h2><span className="spacer" /><button className="btn small" onClick={() => setAdd(true)}>Register backup job</button></div>
      {bk.data && bk.data.length ? <div className="table-wrap"><table><thead><tr><th>Name</th><th>Component</th><th>Last result</th><th>Last success</th><th>Last restore test</th><th /></tr></thead><tbody>{bk.data.map((b) => <tr key={b.id}><td>{b.name}</td><td>{b.component}</td><td>{b.last_status ?? '—'}</td><td>{ago(b.last_success_at)}</td><td>{ago(b.last_verified_at)}</td><td><button className="btn small" onClick={() => verified.mutate(b.id)}>Mark restore verified</button></td></tr>)}</tbody></table></div> : <Empty>No backup jobs registered. Bareos reports results to this platform.</Empty>}
      {add && <AddBackup onClose={() => setAdd(false)} />}
    </>
  );
}

function AddBackup({ onClose }: { onClose: () => void }) {
  const [v, setV] = useState({ name: '', component: 'postgres' });
  const m = useAct(() => post('/api/admin/backups', v), ['backups'], 'Backup job registered', onClose);
  return (
    <Modal title="Register backup job" onClose={onClose}>
      <Field label="Name" id="bn"><input id="bn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Component" id="bc"><select id="bc" value={v.component} onChange={(e) => setV({ ...v, component: e.target.value })}>{['postgres', 'vault', 'config', 'reports', 'search'].map((c) => <option key={c}>{c}</option>)}</select></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2} onClick={() => m.mutate(undefined)}>Register</button>
    </Modal>
  );
}

function Tokens() {
  const { me } = useAuth();
  const q = useQuery({ queryKey: ['tokens'], queryFn: () => get<any[]>('/api/tokens') });
  const [add, setAdd] = useState(false);
  const [raw, setRaw] = useState<string | null>(null);
  const revoke = useAct((id: string) => del(`/api/tokens/${id}`), ['tokens'], 'Token revoked');
  return (
    <>
      <div className="row" style={{ marginBottom: 8 }}><h2>Personal API tokens</h2><span className="spacer" /><button className="btn small" onClick={() => setAdd(true)}>Create token</button></div>
      <p style={{ color: 'var(--muted)' }}>Tokens carry only the scopes you pick, expire within 90 days and are shown once. Maximum 5 active.</p>
      {raw && <div className="notice"><b>Your new token (shown once)</b><div className="mono wrap">{raw}</div></div>}
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.length === 0 ? <Empty>No tokens.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Expires</th><th>Last used</th><th /></tr></thead><tbody>{q.data!.map((t) => <tr key={t.id}><td>{t.name}</td><td className="mono">{t.prefix}…</td><td className="wrap">{t.scopes.join(', ')}</td><td>{when(t.expires_at)}</td><td>{ago(t.last_used_at)}</td><td>{t.revoked ? 'Revoked' : <button className="btn small danger" onClick={() => revoke.mutate(t.id)}>Revoke</button>}</td></tr>)}</tbody></table></div>
      )}
      {add && <AddToken caps={me?.capabilities ?? []} onClose={() => setAdd(false)} onRaw={(r) => { setRaw(r); setAdd(false); }} />}
    </>
  );
}

function AddToken({ caps, onClose, onRaw }: { caps: string[]; onClose: () => void; onRaw: (r: string) => void }) {
  const [v, setV] = useState({ name: '', scopes: [] as string[], days: 30 });
  const m = useAct(() => post('/api/tokens', v), ['tokens'], 'Token created', (r) => onRaw(r.token));
  return (
    <Modal title="Create API token" onClose={onClose} wide>
      <Field label="Name" id="tn"><input id="tn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Expires in (days, max 90)" id="td"><input id="td" type="number" min={1} max={90} value={v.days} onChange={(e) => setV({ ...v, days: Number(e.target.value) })} /></Field>
      <fieldset><legend>Scopes</legend><div className="grid cols-4">{caps.map((c) => <label key={c} className="row" style={{ gap: 6 }}><input type="checkbox" checked={v.scopes.includes(c)} onChange={() => setV({ ...v, scopes: v.scopes.includes(c) ? v.scopes.filter((x) => x !== c) : [...v.scopes, c] })} /> {c}</label>)}</div></fieldset>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2 || !v.scopes.length || v.days < 1 || v.days > 90} onClick={() => m.mutate(undefined)}>Create</button>
    </Modal>
  );
}
