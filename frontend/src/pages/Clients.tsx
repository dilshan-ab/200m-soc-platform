import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Building2, CheckCircle2, Plus, Settings, UserMinus, UserPlus, XCircle } from 'lucide-react';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead } from '../components/ui';
import { del, get, patch, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type ClientRow = { id: string; name: string; code: string; kind: string; owner: string };
type ClientDetail = ClientRow & { logo_url: string; brand_color: string; timezone: string; contact_email: string; tier: string; active: boolean; report_recipients: string[]; created_at: string };
type DashboardRow = { id: string; name: string; code: string; tier: string; brand_color: string; open_alerts: number; critical_alerts: number; sla_breached: number; open_cases: number; last_activity: string | null; health: 'healthy' | 'warning' | 'critical' };
type Dashboard = { total_clients: number; healthy: number; warning: number; critical: number; total_open_alerts: number; total_sla_breached: number; clients: DashboardRow[] };

const HEALTH_META = { healthy: { icon: CheckCircle2, color: 'var(--ok)', label: 'Healthy' }, warning: { icon: AlertTriangle, color: 'var(--warn)', label: 'Needs attention' }, critical: { icon: XCircle, color: 'var(--bad)', label: 'Critical' } };

export default function Clients() {
  const { me, can } = useAuth();
  const mssp = useQuery({ queryKey: ['mssp-dashboard'], queryFn: () => get<Dashboard>('/api/clients/mssp/dashboard'), enabled: can('mssp.view') && !!me?.all_clients, refetchInterval: REFRESH_MS });
  const [tab, setTab] = useState<'overview' | 'manage'>(can('mssp.view') && me?.all_clients ? 'overview' : 'manage');
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <>
      <PageHead title="Clients & MSSP" sub="Manage tenants, branding and membership — and watch every client's posture from one view." eyebrow="WORKSPACE" />
      {can('mssp.view') && me?.all_clients && (
        <div className="tabs" style={{ marginBottom: 16 }}>
          <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>MSSP Overview</button>
          <button className={tab === 'manage' ? 'active' : ''} onClick={() => setTab('manage')}>Manage Clients</button>
        </div>
      )}
      {tab === 'overview' ? (
        mssp.isLoading ? <Loading /> : mssp.error ? <ErrorBox error={mssp.error} /> : mssp.data && (
          <>
            <div className="kpi-row" style={{ marginBottom: 16 }}>
              <div className="kpi"><Building2 size={18} /><div><strong>{mssp.data.total_clients}</strong><small>Clients</small></div></div>
              <div className="kpi"><CheckCircle2 size={18} style={{ color: 'var(--ok)' }} /><div><strong>{mssp.data.healthy}</strong><small>Healthy</small></div></div>
              <div className="kpi"><AlertTriangle size={18} style={{ color: 'var(--warn)' }} /><div><strong>{mssp.data.warning}</strong><small>Needs attention</small></div></div>
              <div className="kpi"><XCircle size={18} style={{ color: 'var(--bad)' }} /><div><strong>{mssp.data.critical}</strong><small>Critical</small></div></div>
              <div className="kpi"><div><strong>{mssp.data.total_sla_breached}</strong><small>SLA breaches (all clients)</small></div></div>
            </div>
            {mssp.data.clients.length === 0 ? <Empty>No clients yet.</Empty> : (
              <div className="mssp-grid">{mssp.data.clients.map((c) => {
                const meta = HEALTH_META[c.health];
                return (
                  <button key={c.id} type="button" className={`card tenant-card health-${c.health}`} onClick={() => setSelected(c.id)} style={{ padding: 16 }}>
                    <div className="row" style={{ justifyContent: 'space-between' }}>
                      <span className="row" style={{ gap: 8 }}>{c.brand_color && <span className="brand-swatch" style={{ background: c.brand_color }} />}<strong>{c.name}</strong></span>
                      <meta.icon size={16} style={{ color: meta.color }} />
                    </div>
                    <div className="row" style={{ gap: 6 }}><span className="badge">{c.code}</span><span className="badge">{titleCase(c.tier)}</span></div>
                    <div className="tenant-card-stats">
                      <div><strong>{c.open_alerts}</strong><small>OPEN ALERTS</small></div>
                      <div><strong style={{ color: c.critical_alerts ? 'var(--bad)' : undefined }}>{c.critical_alerts}</strong><small>CRITICAL</small></div>
                      <div><strong>{c.open_cases}</strong><small>OPEN CASES</small></div>
                      <div><strong style={{ color: c.sla_breached ? 'var(--warn)' : undefined }}>{c.sla_breached}</strong><small>SLA BREACHED</small></div>
                    </div>
                    <small style={{ color: 'var(--muted)' }}>Last activity {c.last_activity ? ago(c.last_activity) : 'never'}</small>
                  </button>
                );
              })}</div>
            )}
          </>
        )
      ) : <ManagePanel onSelect={setSelected} />}
      {selected && <ClientDrawer id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function ManagePanel({ onSelect }: { onSelect: (id: string) => void }) {
  const { can } = useAuth();
  const list = useQuery({ queryKey: ['clients'], queryFn: () => get<ClientRow[]>('/api/clients') });
  const [creating, setCreating] = useState(false);

  if (list.isLoading) return <Loading />;
  if (list.error) return <ErrorBox error={list.error} />;
  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}><span className="spacer" />{can('clients.write') && <button className="btn small primary" onClick={() => setCreating(true)}><Plus size={14} /> New client</button>}</div>
      {list.data!.length === 0 ? <Empty>No clients yet.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Code</th><th>Kind</th><th>Owner</th><th /></tr></thead>
            <tbody>{list.data!.map((c) => (
              <tr key={c.id}><td>{c.name}</td><td className="mono">{c.code}</td><td>{titleCase(c.kind)}</td><td>{c.owner || '—'}</td>
                <td><button className="btn small" onClick={() => onSelect(c.id)}><Settings size={12} /> Manage</button></td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {creating && <CreateClient onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); onSelect(id); }} />}
    </>
  );
}

function CreateClient({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [v, setV] = useState({ name: '', code: '', owner: '' });
  const create = useAct(() => post<{ id: string }>('/api/clients', v), ['clients'], 'Client created', (r) => onCreated(r.id));
  return (
    <Modal title="New client" onClose={onClose}>
      <Field label="Name" id="cn"><input id="cn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Code" id="cc" hint="Short unique code, e.g. ACME"><input id="cc" value={v.code} onChange={(e) => setV({ ...v, code: e.target.value.toUpperCase() })} /></Field>
      <Field label="Owner (account manager)" id="co"><input id="co" value={v.owner} onChange={(e) => setV({ ...v, owner: e.target.value })} /></Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || v.name.trim().length < 1 || v.code.trim().length < 1} onClick={() => create.mutate(undefined)}>Create</button>
    </Modal>
  );
}

function ClientDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ['client', id], queryFn: () => get<ClientDetail>(`/api/clients/${id}`) });
  const members = useQuery({ queryKey: ['client-members', id], queryFn: () => get<any[]>(`/api/clients/${id}/members`), enabled: can('clients.read') });
  const summary = useQuery({ queryKey: ['client-summary', id], queryFn: () => get<any>(`/api/clients/${id}/summary`) });
  const [editing, setEditing] = useState(false);
  const [addingMember, setAddingMember] = useState(false);
  const removeMember = useAct((uid: string) => del(`/api/clients/${id}/members/${uid}`), ['client-members'], 'Member removed');

  if (q.isLoading) return <Drawer title="Client" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Client" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const c = q.data!;

  return (
    <Drawer title={<span className="row" style={{ gap: 8 }}>{c.brand_color && <span className="brand-swatch" style={{ background: c.brand_color }} />}{c.name}</span>} onClose={onClose}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}><span className="badge">{c.code}</span><span className="badge">{titleCase(c.tier)}</span>{!c.active && <span className="badge" style={{ background: 'var(--bad-bg)', color: 'var(--bad)' }}>Inactive</span>}</div>
      {summary.data && (
        <div className="kpi-row" style={{ marginBottom: 16 }}>
          <div className="kpi"><div><strong>{summary.data.alerts_open}</strong><small>Open alerts</small></div></div>
          <div className="kpi"><div><strong>{summary.data.cases_open}</strong><small>Open cases</small></div></div>
          <div className="kpi"><div><strong>{summary.data.assets}</strong><small>Assets</small></div></div>
          <div className="kpi"><div><strong>{summary.data.vulns_open}</strong><small>Open vulns</small></div></div>
        </div>
      )}
      <dl className="kv">
        <dt>Timezone</dt><dd>{c.timezone}</dd>
        <dt>Contact</dt><dd>{c.contact_email || '—'}</dd>
        <dt>Owner</dt><dd>{c.owner || '—'}</dd>
        <dt>Created</dt><dd>{ago(c.created_at)}</dd>
      </dl>
      {can('clients.write') && <button className="btn small" style={{ marginTop: 10 }} onClick={() => setEditing(true)}><Settings size={12} /> Edit branding &amp; details</button>}

      <h4 style={{ marginTop: 20, marginBottom: 8 }}>Members</h4>
      {members.data && members.data.length > 0 ? (
        <ul className="item-list">{members.data.map((m) => (
          <li key={m.user_id} className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{m.name} <small style={{ color: 'var(--muted)' }}>({titleCase(m.role)})</small></span>
            {can('clients.manage_members') && <button className="btn small danger" onClick={() => removeMember.mutate(m.user_id)}><UserMinus size={12} /></button>}
          </li>
        ))}</ul>
      ) : <Empty>No members assigned.</Empty>}
      {can('clients.manage_members') && <button className="btn small" style={{ marginTop: 8 }} onClick={() => setAddingMember(true)}><UserPlus size={13} /> Add member</button>}

      {editing && <EditClientModal client={c} onClose={() => setEditing(false)} />}
      {addingMember && <AddMemberModal clientId={id} onClose={() => setAddingMember(false)} />}
    </Drawer>
  );
}

function EditClientModal({ client, onClose }: { client: ClientDetail; onClose: () => void }) {
  const [v, setV] = useState({ brand_color: client.brand_color, logo_url: client.logo_url, timezone: client.timezone, contact_email: client.contact_email, tier: client.tier });
  const save = useAct(() => patch(`/api/clients/${client.id}`, v), ['client', 'clients', 'mssp-dashboard'], 'Client updated', onClose);
  return (
    <Modal title={`Edit ${client.name}`} onClose={onClose}>
      <div className="grid cols-2">
        <Field label="Brand color" id="ebc" hint="Shown as a swatch across dashboards."><input id="ebc" type="color" style={{ width: 60, height: 38, padding: 2 }} value={v.brand_color || '#145fbd'} onChange={(e) => setV({ ...v, brand_color: e.target.value })} /></Field>
        <Field label="Tier" id="et"><select id="et" value={v.tier} onChange={(e) => setV({ ...v, tier: e.target.value })}><option value="standard">Standard</option><option value="premium">Premium</option></select></Field>
      </div>
      <Field label="Logo URL" id="elu"><input id="elu" value={v.logo_url} onChange={(e) => setV({ ...v, logo_url: e.target.value })} /></Field>
      <div className="grid cols-2">
        <Field label="Timezone" id="etz"><input id="etz" value={v.timezone} onChange={(e) => setV({ ...v, timezone: e.target.value })} /></Field>
        <Field label="Contact email" id="ece"><input id="ece" type="email" value={v.contact_email} onChange={(e) => setV({ ...v, contact_email: e.target.value })} /></Field>
      </div>
      {save.error && <ErrorBox error={save.error} />}
      <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate(undefined)}>Save</button>
    </Modal>
  );
}

function AddMemberModal({ clientId, onClose }: { clientId: string; onClose: () => void }) {
  const users = useQuery({ queryKey: ['admin-users'], queryFn: () => get<{ id: string; name: string; email: string }[]>('/api/admin/users') });
  const [userId, setUserId] = useState('');
  const add = useAct(() => post(`/api/clients/${clientId}/members`, { user_id: userId }), ['client-members'], 'Member added', onClose);
  return (
    <Modal title="Add a member" onClose={onClose}>
      <Field label="User" id="amu">
        <select id="amu" value={userId} onChange={(e) => setUserId(e.target.value)}>
          <option value="">Select a user…</option>
          {users.data?.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
        </select>
      </Field>
      {add.error && <ErrorBox error={add.error} />}
      <button className="btn primary" disabled={add.isPending || !userId} onClick={() => add.mutate(undefined)}>Add</button>
    </Modal>
  );
}
