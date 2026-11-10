import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Status } from '../components/ui';
import { get, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, SEVERITIES } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Automation({ soar = false }: { soar?: boolean }) {
  const [tab, setTab] = useState<'rules' | 'notify'>('rules');
  return (
    <>
      <PageHead title={soar ? "SOAR" : "Automation"} sub="Rules that act on new alerts, and notification routing. Automation can request response actions but never bypass approval." />
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'rules'} className={`tab${tab === 'rules' ? ' active' : ''}`} onClick={() => setTab('rules')}>Rules</button>
        <button role="tab" aria-selected={tab === 'notify'} className={`tab${tab === 'notify' ? ' active' : ''}`} onClick={() => setTab('notify')}>Notifications</button>
      </div>
      {tab === 'rules' ? <Rules /> : <Notifications />}
    </>
  );
}

const FIELDS = ['severity', 'source', 'rule_id', 'host', 'category', 'title', 'client_id', 'src_ip', 'username', 'status'];
const OPS = ['eq', 'ne', 'in', 'gte', 'contains', 'startswith'];
const ACTIONS = ['set_status', 'create_case', 'enrich', 'request_action', 'add_note'];

function Rules() {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ['rules'], queryFn: () => get<any[]>('/api/automation/rules') });
  const [sel, setSel] = useState<any>(null);
  const [edit, setEdit] = useState<any>(null);
  return (
    <>
      {can('automation.write') && <div style={{ marginBottom: 10 }}><button className="btn primary" onClick={() => setEdit({ name: '', description: '', conditions: [], actions: [{ type: 'add_note', text: '' }], max_per_hour: 30 })}>New rule</button></div>}
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.length === 0 ? <Empty>No automation rules.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Conditions</th><th>Actions</th><th>State</th><th>Failures</th></tr></thead>
          <tbody>{q.data!.map((r) => <tr key={r.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(r)} onKeyDown={(e) => e.key === 'Enter' && setSel(r)}>
            <td>{r.name}</td><td className="wrap">{r.conditions.length ? r.conditions.map((c: any) => `${c.field} ${c.op} ${JSON.stringify(c.value)}`).join(' AND ') : 'every alert'}</td><td>{r.actions.map((a: any) => a.type).join(', ')}</td><td><Status v={r.enabled ? 'ok' : 'paused'} /></td><td>{r.consecutive_failures}</td></tr>)}</tbody></table></div>
      )}
      {sel && <RuleDrawer r={sel} onClose={() => setSel(null)} onEdit={() => { setEdit(sel); setSel(null); }} />}
      {edit && <RuleEditor r={edit} onClose={() => setEdit(null)} />}
    </>
  );
}

function RuleDrawer({ r, onClose, onEdit }: { r: any; onClose: () => void; onEdit: () => void }) {
  const { can } = useAuth();
  const [dry, setDry] = useState<any>(null);
  const runs = useQuery({ queryKey: ['rule-runs', r.id], queryFn: () => get<any[]>(`/api/automation/rules/${r.id}/runs`) });
  const test = useAct(() => post(`/api/automation/rules/${r.id}/dry-run`), ['rule-runs'], undefined, setDry);
  const toggle = useAct(() => post(`/api/automation/rules/${r.id}/toggle`, { enabled: !r.enabled }), ['rules'], r.enabled ? 'Rule disabled' : 'Rule enabled', onClose);
  return (
    <Drawer title={r.name} onClose={onClose}>
      <p>{r.description}</p>
      <dl className="kv"><dt>Max per hour</dt><dd>{r.max_per_hour}</dd><dt>Version</dt><dd>{r.version}</dd><dt>Actions</dt><dd className="mono wrap">{JSON.stringify(r.actions)}</dd></dl>
      <div className="row" style={{ margin: '12px 0' }}>
        <button className="btn small" onClick={() => test.mutate(undefined)} disabled={test.isPending}>Dry run on recent alerts</button>
        {can('automation.write') && <button className="btn small" onClick={onEdit}>Edit</button>}
        {can('automation.write') && <button className={`btn small ${r.enabled ? '' : 'primary'}`} onClick={() => toggle.mutate(undefined)}>{r.enabled ? 'Disable' : 'Enable'}</button>}
      </div>
      {[test, toggle].map((m, i) => m.error ? <ErrorBox key={i} error={m.error} /> : null)}
      {dry && <div className="notice"><b>{dry.matched} of {dry.evaluated} recent alerts would match.</b><ul>{dry.samples.map((s: any) => <li key={s.alert_id}>{s.title}</li>)}</ul></div>}
      <h3>Recent runs</h3>
      {runs.data && runs.data.length > 0 ? <div className="table-wrap"><table><thead><tr><th>When</th><th>Mode</th><th>Matched</th><th>Status</th></tr></thead><tbody>{runs.data.map((x) => <tr key={x.id}><td>{ago(x.created_at)}</td><td>{x.dry_run ? 'dry-run' : 'live'}</td><td>{x.matched ? 'yes' : 'no'}</td><td>{x.status}</td></tr>)}</tbody></table></div> : <Empty>No runs yet.</Empty>}
    </Drawer>
  );
}

function RuleEditor({ r, onClose }: { r: any; onClose: () => void }) {
  const [v, setV] = useState<any>({ ...r, conditions: r.conditions.map((c: any) => ({ ...c, value: Array.isArray(c.value) ? c.value.join(',') : c.value })) });
  const body = () => ({
    name: v.name, description: v.description, max_per_hour: v.max_per_hour, client_id: v.client_id ?? null,
    conditions: v.conditions.map((c: any) => ({ field: c.field, op: c.op, value: c.op === 'in' ? String(c.value).split(',').map((s) => s.trim()).filter(Boolean) : c.value })),
    actions: v.actions,
  });
  const save = useAct(() => (r.id ? put(`/api/automation/rules/${r.id}`, body()) : post('/api/automation/rules', body())), ['rules'], 'Saved. Dry-run it before enabling.', onClose);
  const setC = (i: number, k: string, x: any) => setV({ ...v, conditions: v.conditions.map((c: any, j: number) => (j === i ? { ...c, [k]: x } : c)) });
  const setA = (i: number, k: string, x: any) => setV({ ...v, actions: v.actions.map((a: any, j: number) => (j === i ? { ...a, [k]: x } : a)) });
  return (
    <Modal title={r.id ? `Edit ${r.name}` : 'New rule'} onClose={onClose} wide>
      <Field label="Name" id="rn"><input id="rn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Description" id="rd"><input id="rd" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      <h3>When an alert is created and…</h3>
      {v.conditions.map((c: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <select aria-label="Field" value={c.field} onChange={(e) => setC(i, 'field', e.target.value)}>{FIELDS.map((f) => <option key={f}>{f}</option>)}</select>
          <select aria-label="Operator" value={c.op} onChange={(e) => setC(i, 'op', e.target.value)}>{OPS.map((f) => <option key={f}>{f}</option>)}</select>
          {c.field === 'severity' ? <select aria-label="Value" value={c.value} onChange={(e) => setC(i, 'value', e.target.value)}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select> : <input aria-label="Value" value={c.value} onChange={(e) => setC(i, 'value', e.target.value)} placeholder={c.op === 'in' ? 'a,b,c' : ''} />}
          <button className="btn small" aria-label="Remove condition" onClick={() => setV({ ...v, conditions: v.conditions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>))}
      <button className="btn small" onClick={() => setV({ ...v, conditions: [...v.conditions, { field: 'severity', op: 'gte', value: 'high' }] })}>Add condition</button>
      <h3 style={{ marginTop: 14 }}>Then…</h3>
      {v.actions.map((a: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <select aria-label="Action" value={a.type} onChange={(e) => setV({ ...v, actions: v.actions.map((x: any, j: number) => (j === i ? { type: e.target.value } : x)) })}>{ACTIONS.map((f) => <option key={f}>{f}</option>)}</select>
          {a.type === 'set_status' && <select aria-label="Status" value={a.status ?? ''} onChange={(e) => setA(i, 'status', e.target.value)}><option value="">Select…</option>{['acknowledged', 'investigating', 'false_positive', 'resolved'].map((s) => <option key={s}>{s}</option>)}</select>}
          {a.type === 'add_note' && <input aria-label="Note" placeholder="Note text" value={a.text ?? ''} onChange={(e) => setA(i, 'text', e.target.value)} />}
          {a.type === 'create_case' && <input aria-label="Template" placeholder="Case template name (optional)" value={a.template ?? ''} onChange={(e) => setA(i, 'template', e.target.value)} />}
          {a.type === 'request_action' && <><input aria-label="Action key" placeholder="action key, e.g. block_ip" value={a.action_key ?? ''} onChange={(e) => setA(i, 'action_key', e.target.value)} /><select aria-label="Target field" value={a.target_field ?? 'src_ip'} onChange={(e) => setA(i, 'target_field', e.target.value)}>{['src_ip', 'host', 'username'].map((f) => <option key={f}>{f}</option>)}</select></>}
          <button className="btn small" aria-label="Remove action" disabled={v.actions.length === 1} onClick={() => setV({ ...v, actions: v.actions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>))}
      <button className="btn small" onClick={() => setV({ ...v, actions: [...v.actions, { type: 'add_note', text: '' }] })}>Add action</button>
      <Field label="Max executions per hour" id="rm"><input id="rm" type="number" min={1} max={1000} value={v.max_per_hour} onChange={(e) => setV({ ...v, max_per_hour: Number(e.target.value) })} /></Field>
      {save.error && <ErrorBox error={save.error} />}
      <button className="btn primary" disabled={save.isPending || v.name.trim().length < 3} onClick={() => save.mutate(undefined)}>Save (stays disabled until dry-run)</button>
    </Modal>
  );
}

function Notifications() {
  const { can } = useAuth();
  const dest = useQuery({ queryKey: ['destinations'], queryFn: () => get<any[]>('/api/notifications/destinations') });
  const rules = useQuery({ queryKey: ['nrules'], queryFn: () => get<any[]>('/api/notifications/rules') });
  const dl = useQuery({ queryKey: ['deliveries'], queryFn: () => get<any[]>('/api/notifications/deliveries', { limit: 30 }) });
  const [addDest, setAddDest] = useState(false);
  const [addRule, setAddRule] = useState(false);
  const test = useAct((id: string) => post(`/api/notifications/destinations/${id}/test`), ['deliveries'], undefined, (r) => { if (!r.ok) throw new Error(r.error); });
  const toggle = useAct((a: { id: string; enabled: boolean }) => post(`/api/notifications/rules/${a.id}/toggle`, { enabled: a.enabled }), ['nrules']);
  return (
    <>
      <div className="row" style={{ marginBottom: 8 }}><h2>Destinations</h2><span className="spacer" />{can('notifications.write') && <button className="btn small" onClick={() => setAddDest(true)}>Add destination</button>}</div>
      {dest.data && dest.data.length > 0 ? <div className="table-wrap"><table><thead><tr><th>Name</th><th>Channel</th><th>Address</th><th /></tr></thead><tbody>{dest.data.map((d) => <tr key={d.id}><td>{d.name}</td><td>{d.channel}</td><td className="mono">{d.address || '—'}</td><td>{can('notifications.write') && <button className="btn small" onClick={() => test.mutate(d.id)}>Send test</button>}</td></tr>)}</tbody></table></div> : <Empty>No destinations. Link Slack, Telegram or email under Integrations first.</Empty>}
      <div className="row" style={{ margin: '20px 0 8px' }}><h2>Routing rules</h2><span className="spacer" />{can('notifications.write') && <button className="btn small" onClick={() => setAddRule(true)} disabled={!dest.data?.length}>Add rule</button>}</div>
      {rules.data && rules.data.length > 0 ? <div className="table-wrap"><table><thead><tr><th>Name</th><th>Events</th><th>Min severity</th><th>Escalation</th><th>State</th><th /></tr></thead><tbody>{rules.data.map((r) => <tr key={r.id}><td>{r.name}</td><td>{r.event_types.join(', ')}</td><td>{r.min_severity}</td><td>{r.escalate_after_minutes ? `${r.escalate_after_minutes} min` : '—'}</td><td>{r.enabled ? 'On' : 'Off'}</td><td>{can('notifications.write') && <button className="btn small" onClick={() => toggle.mutate({ id: r.id, enabled: !r.enabled })}>{r.enabled ? 'Turn off' : 'Turn on'}</button>}</td></tr>)}</tbody></table></div> : <Empty>No routing rules.</Empty>}
      <h2 style={{ margin: '20px 0 8px' }}>Recent deliveries</h2>
      {dl.data && dl.data.length > 0 ? <div className="table-wrap"><table><thead><tr><th>Subject</th><th>Status</th><th>Attempts</th><th>When</th></tr></thead><tbody>{dl.data.map((d) => <tr key={d.id}><td className="wrap">{d.subject}</td><td>{d.status}{d.error && ` · ${d.error}`}</td><td>{d.attempts}</td><td>{ago(d.created_at)}</td></tr>)}</tbody></table></div> : <Empty>No deliveries yet.</Empty>}
      {addDest && <DestModal onClose={() => setAddDest(false)} />}
      {addRule && <RuleModal dests={dest.data ?? []} onClose={() => setAddRule(false)} />}
    </>
  );
}

function DestModal({ onClose }: { onClose: () => void }) {
  const tools = useQuery({ queryKey: ['tools'], queryFn: () => get<any[]>('/api/integrations/tools') });
  const [v, setV] = useState({ name: '', tool_id: '', address: '' });
  const tool = tools.data?.find((t) => t.id === v.tool_id);
  const m = useAct(() => post('/api/notifications/destinations', { ...v, channel: tool.type }), ['destinations'], 'Destination added', onClose);
  const eligible = (tools.data ?? []).filter((t) => ['slack', 'telegram', 'email', 'clickup'].includes(t.type));
  return (
    <Modal title="Add destination" onClose={onClose}>
      <Field label="Name" id="dn"><input id="dn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Integration" id="dt"><select id="dt" value={v.tool_id} onChange={(e) => setV({ ...v, tool_id: e.target.value })}><option value="">Select…</option>{eligible.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.type})</option>)}</select></Field>
      <Field label="Address (chat id, channel or recipient group)" id="da"><input id="da" value={v.address} onChange={(e) => setV({ ...v, address: e.target.value })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !tool || v.name.trim().length < 2} onClick={() => m.mutate(undefined)}>Add</button>
    </Modal>
  );
}

const EVENTS = ['alert.created', 'server.down', 'case.created', 'sla.breached', 'approval.pending'];
function RuleModal({ dests, onClose }: { dests: any[]; onClose: () => void }) {
  const [v, setV] = useState({ name: '', event_types: ['alert.created'] as string[], min_severity: 'high', destinations: [] as string[], escalate_after_minutes: 0, escalation_destinations: [] as string[], detail_level: 'summary' });
  const m = useAct(() => post('/api/notifications/rules', v), ['nrules'], 'Rule added', onClose);
  const tog = (key: 'event_types' | 'destinations' | 'escalation_destinations', id: string) => setV({ ...v, [key]: v[key].includes(id) ? v[key].filter((x) => x !== id) : [...v[key], id] });
  return (
    <Modal title="Add routing rule" onClose={onClose} wide>
      <Field label="Name" id="nrn"><input id="nrn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <fieldset><legend>Events</legend>{EVENTS.map((e) => <label key={e} className="row" style={{ gap: 6 }}><input type="checkbox" checked={v.event_types.includes(e)} onChange={() => tog('event_types', e)} /> {e}</label>)}</fieldset>
      <div className="grid cols-2">
        <Field label="Minimum severity" id="nrs"><select id="nrs" value={v.min_severity} onChange={(e) => setV({ ...v, min_severity: e.target.value })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Detail level" id="nrd" hint="Summary keeps hostnames, IPs and usernames out of chat channels."><select id="nrd" value={v.detail_level} onChange={(e) => setV({ ...v, detail_level: e.target.value })}><option>summary</option><option>full</option></select></Field>
      </div>
      <fieldset><legend>Send to</legend>{dests.map((d) => <label key={d.id} className="row" style={{ gap: 6 }}><input type="checkbox" checked={v.destinations.includes(d.id)} onChange={() => tog('destinations', d.id)} /> {d.name} ({d.channel})</label>)}</fieldset>
      <Field label="Escalate if not acknowledged after (minutes, 0 = never)" id="nre"><input id="nre" type="number" min={0} max={1440} value={v.escalate_after_minutes} onChange={(e) => setV({ ...v, escalate_after_minutes: Number(e.target.value) })} /></Field>
      {v.escalate_after_minutes > 0 && <fieldset><legend>Escalate to</legend>{dests.map((d) => <label key={d.id} className="row" style={{ gap: 6 }}><input type="checkbox" checked={v.escalation_destinations.includes(d.id)} onChange={() => tog('escalation_destinations', d.id)} /> {d.name}</label>)}</fieldset>}
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2 || !v.event_types.length || !v.destinations.length} onClick={() => m.mutate(undefined)}>Add rule</button>
    </Modal>
  );
}
