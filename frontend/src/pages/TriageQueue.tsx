import { useQuery } from '@tanstack/react-query';
import { AlertOctagon, CheckCircle2, Clock, Flame, SkipForward, UserCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { LiveTimer } from '../components/Interactive';
import { Empty, ErrorBox, Loading, PageHead, Sev, Status } from '../components/ui';
import { get, patch } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useLive } from '../lib/live';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type QueueAlert = {
  id: string; title: string; severity: string; status: string; time: string; host: string; src_ip: string; dst_ip: string; username: string;
  rule_id: string; mitre: string[]; ack_due: string | null; resolve_due: string | null; acknowledged_at: string | null;
  sla_breached: boolean; version: number; assignee_id: string | null; assignee_name: string | null;
};
type Queue = { items: QueueAlert[]; total_waiting: number; by_severity: Record<string, number>; oldest_waiting: string | null };

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function QueueSla({ alert }: { alert: QueueAlert }) {
  const deadline = alert.acknowledged_at ? alert.resolve_due : alert.ack_due;
  if (!deadline) return <span className="muted">No SLA deadline</span>;
  return <span className="triage-sla" title={when(deadline)}>
    {alert.acknowledged_at ? 'Resolve' : 'Acknowledge'} <LiveTimer deadline={deadline} />
    {alert.sla_breached && <span className="badge st-failed">SLA breached</span>}
  </span>;
}

function ownerLabel(alert: QueueAlert, analystId?: string) {
  if (!alert.assignee_id) return 'Unassigned';
  if (alert.assignee_id === analystId) return 'You';
  return alert.assignee_name || 'Assigned analyst';
}

export default function TriageQueue() {
  const live = useLive(true);
  const { me, can } = useAuth();
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [ownership, setOwnership] = useState('unassigned');
  const [skipped, setSkipped] = useState<Set<string>>(new Set());
  const [focusMode, setFocusMode] = useState(true);

  const q = useQuery({
    queryKey: ['triage-queue', severityFilter, ownership],
    queryFn: () => get<Queue>('/api/alerts/queue', { unassigned_only: ownership === 'unassigned', mine: ownership === 'mine', severity: severityFilter, limit: 50 }),
    refetchInterval: REFRESH_MS,
  });

  const update = useAct(({ alert, changes }: { alert: QueueAlert; changes: Record<string, unknown> }) =>
    patch(`/api/alerts/${alert.id}`, { version: alert.version, ...changes }),
  ['triage-queue', 'alerts', 'alert', 'alert-stats'], 'Alert updated');

  function updateAlert(alert: QueueAlert, changes: Record<string, unknown>) {
    update.mutate({ alert, changes }, { onError: () => { void q.refetch(); } });
  }

  const queue = q.data;
  const visible = useMemo(() => (queue?.items ?? []).filter((a) => !skipped.has(a.id)), [queue, skipped]);
  const current = visible[0];

  function skip(id: string) { setSkipped((s) => new Set(s).add(id)); }

  return (
    <>
      <PageHead title="Live Triage Queue" sub="Triage new alerts and track your active investigations.">
        <span className={'demo-pill' + (live ? '' : ' off')}>{live ? 'Live' : 'Offline'}</span>
        <button className="btn small" onClick={() => setFocusMode((f) => !f)}>{focusMode ? 'Switch to list view' : 'Switch to focus mode'}</button>
      </PageHead>

      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : queue && (
        <>
          <div className="kpi-row" style={{ marginBottom: 16 }}>
            <div className="kpi"><Flame size={18} style={{ color: 'var(--bad)' }} /><div><strong>{queue.total_waiting}</strong><small>{ownership === 'mine' ? 'Assigned to me' : 'Waiting triage'}</small></div></div>
            {SEV_ORDER.filter((s) => s !== 'info').map((s) => (
              <div className="kpi" key={s}><Sev v={s} /><div><strong>{queue.by_severity[s] ?? 0}</strong><small>{s}</small></div></div>
            ))}
            <div className="kpi"><Clock size={18} /><div><strong>{queue.oldest_waiting ? ago(queue.oldest_waiting) : '—'}</strong><small>Oldest alert</small></div></div>
          </div>

          <div className="filters" style={{ marginBottom: 16 }}>
            <label className="row" style={{ gap: 6, alignItems: 'center' }}>
              Ownership
              <select value={ownership} onChange={(e) => { setOwnership(e.target.value); setSkipped(new Set()); }}>
                <option value="unassigned">Unassigned</option>
                <option value="new">All new alerts</option>
                <option value="mine">Assigned to me</option>
              </select>
            </label>
            {SEV_ORDER.map((s) => (
              <button key={s} type="button" aria-pressed={severityFilter.includes(s)} className={'btn small' + (severityFilter.includes(s) ? ' primary' : '')}
                onClick={() => setSeverityFilter((f) => f.includes(s) ? f.filter((x) => x !== s) : [...f, s])}>
                {s}
              </button>
            ))}
          </div>

          {visible.length === 0 ? (
            <Empty>No alerts in this queue view.</Empty>
          ) : focusMode ? (
            current && (
              <div className="card" style={{ padding: 24, maxWidth: 760 }}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
                  <Sev v={current.severity} />
                  <QueueSla alert={current} />
                </div>
                <h2 style={{ margin: '0 0 8px' }}>{current.title}</h2>
                <dl className="kv" style={{ marginBottom: 16 }}>
                  <dt>Owner</dt><dd>{ownerLabel(current, me?.id)}</dd>
                  <dt>Status</dt><dd><Status v={current.status} /></dd>
                  <dt>Rule</dt><dd className="mono">{current.rule_id || '—'}</dd>
                  <dt>Host</dt><dd className="mono">{current.host || '—'}</dd>
                  <dt>Source IP</dt><dd className="mono">{current.src_ip || '—'}</dd>
                  <dt>Destination IP</dt><dd className="mono">{current.dst_ip || '—'}</dd>
                  <dt>User</dt><dd className="mono">{current.username || '—'}</dd>
                  <dt>Occurred</dt><dd>{ago(current.time)}</dd>
                  {current.mitre?.length > 0 && <><dt>MITRE</dt><dd>{current.mitre.join(', ')}</dd></>}
                </dl>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                  <Link className="btn primary" to={`/app/alerts?open=${current.id}`}>Open investigation</Link>
                  {current.status === 'new' && (!current.assignee_id || current.assignee_id === me?.id) && (
                    <button className="btn" disabled={update.isPending} onClick={() => updateAlert(current, { claim: true, status: 'acknowledged' })}><UserCheck size={16} /> Claim &amp; acknowledge</button>
                  )}
                  {current.status !== 'investigating' && (!current.assignee_id || current.assignee_id === me?.id) && (
                    <button className="btn" disabled={update.isPending} onClick={() => updateAlert(current, { claim: true, status: 'investigating' })}><AlertOctagon size={16} /> Escalate to investigation</button>
                  )}
                  {current.assignee_id && current.assignee_id === me?.id && current.status === 'new' && (
                    <button className="btn" disabled={update.isPending} onClick={() => updateAlert(current, { unassign: true })}>Release ownership</button>
                  )}
                  {can('alerts.tune') && <button className="btn" disabled={update.isPending} onClick={() => updateAlert(current, { status: 'false_positive', tuning_note: 'Marked from the triage queue' })}><CheckCircle2 size={16} /> Mark false positive</button>}
                  <button className="btn" onClick={() => skip(current.id)}><SkipForward size={16} /> Skip</button>
                </div>
                {update.error && <ErrorBox error={update.error} />}
                <p style={{ color: 'var(--muted)', marginTop: 16 }}>{visible.length - 1} more in this view.</p>
              </div>
            )
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Severity</th><th>Title</th><th>Host / IP</th><th>Age</th><th>Owner</th><th>Status</th><th>SLA</th><th /></tr></thead>
                <tbody>{visible.map((a) => (
                  <tr key={a.id}>
                    <td><Sev v={a.severity} /></td>
                    <td className="wrap"><Link to={`/app/alerts?open=${a.id}`}>{a.title}</Link></td>
                    <td className="mono">{a.host || a.src_ip || '—'}</td>
                    <td>{ago(a.time)}</td>
                    <td>{ownerLabel(a, me?.id)}</td>
                    <td><Status v={a.status} /></td>
                    <td><QueueSla alert={a} /></td>
                    <td className="row" style={{ gap: 4 }}>
                      {a.status === 'new' && (!a.assignee_id || a.assignee_id === me?.id) && (
                        <button className="btn small primary" disabled={update.isPending} onClick={() => updateAlert(a, { claim: true, status: 'acknowledged' })}>Claim</button>
                      )}
                      <button className="btn small" onClick={() => skip(a.id)}>Skip</button>
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}
