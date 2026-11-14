import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, Status } from '../components/ui';
import { del, get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useAct } from '../lib/mut';

type Rule = { id: string; name: string; description: string; strategy: string; config: Record<string, any>; severity_boost: number; enabled: boolean; client_id: string | null; created_by: string; created_at: string; updated_at: string };
type Inc = { id: string; name: string; severity: string; status: string; strategy: string; rule_name: string; alert_count: number; first_alert_time: string | null; last_alert_time: string | null; case_id: string | null; client_id: string | null; assignee_id: string | null; created_at: string; updated_at: string;
  description?: string; rule_id?: string; alert_ids?: string[]; shared_iocs?: Record<string, string[]>; kill_chain_stages?: string[] };
type Strategy = { key: string; label: string; description: string };

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const STRAT_LABEL: Record<string, string> = { ioc_overlap: 'IOC overlap', time_window: 'Time window', kill_chain: 'Kill chain', threshold: 'Threshold' };

export default function Correlation() {
  const [tab, setTab] = useState<'incidents' | 'rules'>('incidents');
  const { can } = useAuth();

  return (
    <>
      <PageHead title="Alert correlation" sub="Automatically group related alerts into incidents using configurable correlation rules.">
        <div style={{ display: 'flex', gap: 8 }}>
          {can('correlation.write') && (
            <button className="btn" onClick={() => post('/api/correlation/run').then(() => window.location.reload())}>
              Run correlation
            </button>
          )}
        </div>
      </PageHead>
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={`tab ${tab === 'incidents' ? 'active' : ''}`} onClick={() => setTab('incidents')}>Incidents</button>
        <button className={`tab ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>Rules</button>
      </div>
      {tab === 'incidents' ? <IncidentList /> : <RuleList />}
    </>
  );
}

// ── incidents ──────────────────────────────────────────────────────

function IncidentList() {
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const q = useQuery({ queryKey: ['incidents', page, statusFilter, sevFilter], queryFn: () => get<Page<Inc>>('/api/correlation/incidents', { page, status: statusFilter || undefined, severity: sevFilter || undefined }) });
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <>
      <div className="row" style={{ marginBottom: 12, gap: 8, flexWrap: 'wrap' }}>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }} style={{ minWidth: 120 }}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
        </select>
        <select value={sevFilter} onChange={(e) => { setSevFilter(e.target.value); setPage(1); }} style={{ minWidth: 120 }}>
          <option value="">All severities</option>
          {SEV_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.items.length ? (
        <Empty>No incidents found. Run correlation or adjust filters.</Empty>
      ) : (
        <>
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Incident</th>
                <th>Strategy</th>
                <th>Alerts</th>
                <th>Time range</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((inc) => (
                <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(inc.id)}>
                  <td><span className={`badge sev-${inc.severity}`}>{inc.severity}</span></td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{inc.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>{inc.rule_name}</div>
                  </td>
                  <td><span className="badge">{STRAT_LABEL[inc.strategy] ?? inc.strategy}</span></td>
                  <td style={{ fontWeight: 600 }}>{inc.alert_count}</td>
                  <td style={{ fontSize: 12 }}>
                    {inc.first_alert_time && new Date(inc.first_alert_time).toLocaleString()}
                    {inc.last_alert_time && inc.first_alert_time !== inc.last_alert_time && (
                      <> → {new Date(inc.last_alert_time).toLocaleTimeString()}</>
                    )}
                  </td>
                  <td><Status v={inc.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={q.data.page} limit={q.data.limit} total={q.data.total} set={setPage} />
        </>
      )}

      {selected && <IncidentDetail id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function IncidentDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['incident', id], queryFn: () => get<Inc>(`/api/correlation/incidents/${id}`) });
  const { can } = useAuth();
  const update = useAct((body: Partial<Inc>) => patch(`/api/correlation/incidents/${id}`, body), ['incidents', 'incident'], 'Updated');
  const remove = useAct(() => del(`/api/correlation/incidents/${id}`), ['incidents'], 'Deleted', onClose);

  if (q.isLoading) return <Drawer title="Incident" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Incident" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const inc = q.data!;

  return (
    <Drawer title={inc.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 12, gap: 8, flexWrap: 'wrap' }}>
        <span className={`badge sev-${inc.severity}`}>{inc.severity}</span>
        <Status v={inc.status} />
        <span className="badge">{STRAT_LABEL[inc.strategy] ?? inc.strategy}</span>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>{inc.alert_count} alerts</span>
        <span className="spacer" />
        {can('incidents.write') && inc.status === 'open' && (
          <button className="btn small" onClick={() => update.mutate({ status: 'investigating' })}>Investigate</button>
        )}
        {can('incidents.write') && (inc.status === 'open' || inc.status === 'investigating') && (
          <button className="btn small primary" onClick={() => update.mutate({ status: 'resolved' })}>Resolve</button>
        )}
        {can('incidents.write') && (
          <button className="btn small danger" onClick={() => { if (confirm('Delete this incident?')) remove.mutate(undefined); }}>Delete</button>
        )}
      </div>

      {inc.description && <p style={{ marginBottom: 16, lineHeight: 1.5 }}>{inc.description}</p>}

      {inc.shared_iocs && Object.keys(inc.shared_iocs).length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4>Shared indicators</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {Object.entries(inc.shared_iocs).map(([field, vals]) =>
              (vals as string[]).map((v) => (
                <span key={`${field}-${v}`} className="badge" style={{ fontSize: 12 }}>
                  <strong>{field}</strong>: {v}
                </span>
              ))
            )}
          </div>
        </div>
      )}

      {inc.kill_chain_stages && inc.kill_chain_stages.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4>Kill chain stages</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {inc.kill_chain_stages.map((t) => (
              <span key={t} className="badge" style={{ background: 'var(--bad-bg)', color: 'var(--bad)', fontSize: 12 }}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {inc.alert_ids && inc.alert_ids.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4>Correlated alerts ({inc.alert_ids.length})</h4>
          <div style={{ maxHeight: 200, overflow: 'auto', fontSize: 12, fontFamily: 'var(--mono)', background: 'var(--bg)', padding: 8, borderRadius: 6, border: '1px solid var(--border)' }}>
            {inc.alert_ids.map((aid) => <div key={aid}>{aid}</div>)}
          </div>
        </div>
      )}

      <div style={{ fontSize: 12, color: 'var(--muted)' }}>
        Rule: {inc.rule_name || 'manual'} · Created {new Date(inc.created_at).toLocaleString()}
      </div>
    </Drawer>
  );
}

// ── correlation rules ─────────────────────────────────────────────

function RuleList() {
  const q = useQuery({ queryKey: ['correlation-rules'], queryFn: () => get<Page<Rule>>('/api/correlation/rules') });
  const { can } = useAuth();
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="spacer" />
        {can('correlation.write') && <button className="btn primary" onClick={() => setCreating(true)}>New rule</button>}
      </div>

      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.items.length ? (
        <Empty>No correlation rules. Create one to start grouping alerts into incidents.</Empty>
      ) : (
        <table className="table">
          <thead><tr><th>Name</th><th>Strategy</th><th>Severity boost</th><th>Enabled</th></tr></thead>
          <tbody>
            {q.data.items.map((r) => (
              <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(r.id)}>
                <td>
                  <div style={{ fontWeight: 500 }}>{r.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>{r.description.slice(0, 80)}</div>
                </td>
                <td><span className="badge">{STRAT_LABEL[r.strategy] ?? r.strategy}</span></td>
                <td>+{r.severity_boost}</td>
                <td>{r.enabled ? <span style={{ color: 'var(--ok)' }}>Active</span> : <span style={{ color: 'var(--muted)' }}>Disabled</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {creating && <CreateRule onClose={() => setCreating(false)} />}
      {selected && <RuleDetail id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function RuleDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['correlation-rule', id], queryFn: () => get<Rule>(`/api/correlation/rules/${id}`) });
  const { can } = useAuth();
  const toggle = useAct((enabled: boolean) => patch(`/api/correlation/rules/${id}`, { enabled }), ['correlation-rules', 'correlation-rule'], 'Updated');
  const remove = useAct(() => del(`/api/correlation/rules/${id}`), ['correlation-rules'], 'Deleted', onClose);

  if (q.isLoading) return <Drawer title="Rule" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Rule" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const r = q.data!;

  return (
    <Drawer title={r.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 12, gap: 8 }}>
        <span className="badge">{STRAT_LABEL[r.strategy] ?? r.strategy}</span>
        <span style={{ color: r.enabled ? 'var(--ok)' : 'var(--muted)' }}>{r.enabled ? 'Active' : 'Disabled'}</span>
        <span className="spacer" />
        {can('correlation.write') && (
          <button className="btn small" onClick={() => toggle.mutate(!r.enabled)}>
            {r.enabled ? 'Disable' : 'Enable'}
          </button>
        )}
        {can('correlation.write') && (
          <button className="btn small danger" onClick={() => { if (confirm('Delete this rule?')) remove.mutate(undefined); }}>Delete</button>
        )}
      </div>
      {r.description && <p style={{ marginBottom: 16 }}>{r.description}</p>}
      <h4>Configuration</h4>
      <pre style={{ background: 'var(--bg)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto', border: '1px solid var(--border)' }}>
        {JSON.stringify(r.config, null, 2)}
      </pre>
      <div style={{ marginTop: 12, fontSize: 12, color: 'var(--muted)' }}>
        Severity boost: +{r.severity_boost} · Created by {r.created_by || '—'} on {new Date(r.created_at).toLocaleDateString()}
      </div>
    </Drawer>
  );
}

const DEFAULT_CONFIGS: Record<string, object> = {
  ioc_overlap: { fields: ['src_ip', 'dst_ip', 'host', 'username', 'file_hash'], min_shared: 2, window_minutes: 60 },
  time_window: { window_minutes: 15, min_alerts: 3, group_by: ['host', 'client_id'] },
  kill_chain: { tactics: ['initial-access', 'execution', 'persistence'], window_minutes: 120, same_host: true },
  threshold: { field: 'rule_id', threshold: 10, window_minutes: 30, group_by: ['client_id'] },
};

function CreateRule({ onClose }: { onClose: () => void }) {
  const [v, setV] = useState({ name: '', description: '', strategy: 'ioc_overlap', severity_boost: 1, config: JSON.stringify(DEFAULT_CONFIGS.ioc_overlap, null, 2) });
  const strategies = useQuery({ queryKey: ['strategies'], queryFn: () => get<Strategy[]>('/api/correlation/strategies') });
  const create = useAct(
    () => post('/api/correlation/rules', { ...v, config: JSON.parse(v.config), severity_boost: Number(v.severity_boost) }),
    ['correlation-rules'],
    'Rule created',
    onClose,
  );

  return (
    <Modal title="New correlation rule" onClose={onClose} wide>
      <Field label="Name" id="cr-name"><input id="cr-name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="Multi-source host alerts" /></Field>
      <Field label="Description" id="cr-desc"><textarea id="cr-desc" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} placeholder="Correlates alerts when the same host appears across multiple detection sources" /></Field>
      <div className="grid cols-2">
        <Field label="Strategy" id="cr-strat">
          <select id="cr-strat" value={v.strategy} onChange={(e) => setV({ ...v, strategy: e.target.value, config: JSON.stringify(DEFAULT_CONFIGS[e.target.value] ?? {}, null, 2) })}>
            {(strategies.data ?? []).map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            {!strategies.data && <>
              <option value="ioc_overlap">IOC overlap</option>
              <option value="time_window">Time window</option>
              <option value="kill_chain">Kill chain</option>
              <option value="threshold">Threshold</option>
            </>}
          </select>
        </Field>
        <Field label="Severity boost" id="cr-boost" hint="Escalate incident severity by N levels above the highest alert">
          <input id="cr-boost" type="number" min={0} max={4} value={v.severity_boost} onChange={(e) => setV({ ...v, severity_boost: Number(e.target.value) })} />
        </Field>
      </div>
      <Field label="Configuration (JSON)" id="cr-config">
        <textarea id="cr-config" style={{ minHeight: 140, fontFamily: 'var(--mono)', fontSize: 12 }} value={v.config} onChange={(e) => setV({ ...v, config: e.target.value })} />
      </Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || v.name.trim().length < 2} onClick={() => { try { JSON.parse(v.config); create.mutate(undefined); } catch { alert('Invalid JSON in config'); } }}>Create rule</button>
    </Modal>
  );
}
