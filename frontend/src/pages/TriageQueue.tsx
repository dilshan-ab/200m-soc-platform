import { useQuery } from '@tanstack/react-query';
import { AlertOctagon, CheckCircle2, Clock, Flame, SkipForward, UserCheck } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead, Sev } from '../components/ui';
import { get, patch } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useLive } from '../lib/live';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type QueueAlert = {
  id: string; title: string; severity: string; status: string; time: string; host: string; src_ip: string; dst_ip: string; username: string;
  rule_id: string; mitre: string[]; ack_due: string | null; sla_breached: boolean; version: number; assignee_id: string | null;
};
type Queue = { items: QueueAlert[]; total_waiting: number; by_severity: Record<string, number>; oldest_waiting: string | null };

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function Countdown({ dueIso }: { dueIso: string | null }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  if (!dueIso) return <span style={{ color: 'var(--muted)' }}>No SLA</span>;
  const diff = new Date(dueIso).getTime() - Date.now();
  const breached = diff < 0;
  const abs = Math.abs(diff);
  const mins = Math.floor(abs / 60000);
  const secs = Math.floor((abs % 60000) / 1000);
  return (
    <span style={{ color: breached ? 'var(--bad)' : mins < 5 ? 'var(--warn)' : 'var(--muted)', fontVariantNumeric: 'tabular-nums', fontWeight: breached ? 700 : 400 }}>
      {breached ? 'Overdue by ' : ''}{mins}m {String(secs).padStart(2, '0')}s{breached ? '' : ' left'}
    </span>
  );
}

export default function TriageQueue() {
  const live = useLive(true);
  const { me } = useAuth();
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [unassignedOnly, setUnassignedOnly] = useState(true);
  const [skipped, setSkipped] = useState<Set<string>>(new Set());
  const [focusMode, setFocusMode] = useState(true);

  const q = useQuery({
    queryKey: ['triage-queue', severityFilter, unassignedOnly],
    queryFn: () => get<Queue>('/api/alerts/queue', { unassigned_only: unassignedOnly, severity: severityFilter, limit: 50 }),
    refetchInterval: REFRESH_MS,
  });

  const claim = useAct((a: QueueAlert) => patch(`/api/alerts/${a.id}`, { version: a.version, assignee_id: me?.id, status: 'acknowledged' }), ['triage-queue', 'alerts', 'alert-stats'], 'Alert claimed');
  const falsePositive = useAct((a: QueueAlert) => patch(`/api/alerts/${a.id}`, { version: a.version, status: 'false_positive', tuning_note: 'Marked from the triage queue' }), ['triage-queue', 'alerts', 'alert-stats'], 'Marked false positive');
  const escalate = useAct((a: QueueAlert) => patch(`/api/alerts/${a.id}`, { version: a.version, assignee_id: me?.id, status: 'investigating' }), ['triage-queue', 'alerts', 'alert-stats'], 'Escalated to investigation');

  const queue = q.data;
  const visible = useMemo(() => (queue?.items ?? []).filter((a) => !skipped.has(a.id)), [queue, skipped]);
  const current = visible[0];

  function skip(id: string) { setSkipped((s) => new Set(s).add(id)); }

  return (
    <>
      <PageHead title="Live Triage Queue" sub="Work the highest-priority new alerts first, one at a time, against their SLA clock.">
        <span className={'demo-pill' + (live ? '' : ' off')}>{live ? 'Live' : 'Offline'}</span>
        <button className="btn small" onClick={() => setFocusMode((f) => !f)}>{focusMode ? 'Switch to list view' : 'Switch to focus mode'}</button>
      </PageHead>

      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : queue && (
        <>
          <div className="kpi-row" style={{ marginBottom: 16 }}>
            <div className="kpi"><Flame size={18} style={{ color: 'var(--bad)' }} /><div><strong>{queue.total_waiting}</strong><small>Waiting triage</small></div></div>
            {SEV_ORDER.filter((s) => s !== 'info').map((s) => (
              <div className="kpi" key={s}><Sev v={s} /><div><strong>{queue.by_severity[s] ?? 0}</strong><small>{s}</small></div></div>
            ))}
            <div className="kpi"><Clock size={18} /><div><strong>{queue.oldest_waiting ? ago(queue.oldest_waiting) : '—'}</strong><small>Oldest waiting</small></div></div>
          </div>

          <div className="filters" style={{ marginBottom: 16 }}>
            <label className="row" style={{ gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={unassignedOnly} onChange={(e) => setUnassignedOnly(e.target.checked)} /> Unassigned only
            </label>
            {SEV_ORDER.map((s) => (
              <button key={s} type="button" className={'btn small' + (severityFilter.includes(s) ? ' primary' : '')}
                onClick={() => setSeverityFilter((f) => f.includes(s) ? f.filter((x) => x !== s) : [...f, s])}>
                {s}
              </button>
            ))}
          </div>

          {visible.length === 0 ? (
            <Empty>Queue is clear. No new alerts waiting for triage.</Empty>
          ) : focusMode ? (
            current && (
              <div className="card" style={{ padding: 24, maxWidth: 760 }}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
                  <Sev v={current.severity} />
                  <Countdown dueIso={current.ack_due} />
                </div>
                <h2 style={{ margin: '0 0 8px' }}>{current.title}</h2>
                <dl className="kv" style={{ marginBottom: 16 }}>
                  <dt>Rule</dt><dd className="mono">{current.rule_id || '—'}</dd>
                  <dt>Host</dt><dd className="mono">{current.host || '—'}</dd>
                  <dt>Source IP</dt><dd className="mono">{current.src_ip || '—'}</dd>
                  <dt>Destination IP</dt><dd className="mono">{current.dst_ip || '—'}</dd>
                  <dt>User</dt><dd className="mono">{current.username || '—'}</dd>
                  <dt>Occurred</dt><dd>{ago(current.time)}</dd>
                  {current.mitre?.length > 0 && <><dt>MITRE</dt><dd>{current.mitre.join(', ')}</dd></>}
                </dl>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                  <button className="btn primary" disabled={claim.isPending} onClick={() => claim.mutate(current)}><UserCheck size={16} /> Claim & acknowledge</button>
                  <button className="btn" disabled={escalate.isPending} onClick={() => escalate.mutate(current)}><AlertOctagon size={16} /> Escalate to investigation</button>
                  <button className="btn" disabled={falsePositive.isPending} onClick={() => falsePositive.mutate(current)}><CheckCircle2 size={16} /> Mark false positive</button>
                  <button className="btn" onClick={() => skip(current.id)}><SkipForward size={16} /> Skip</button>
                </div>
                {(claim.error || escalate.error || falsePositive.error) && <ErrorBox error={(claim.error || escalate.error || falsePositive.error)!} />}
                <p style={{ color: 'var(--muted)', marginTop: 16 }}>{visible.length - 1} more waiting after this one.</p>
              </div>
            )
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Severity</th><th>Title</th><th>Host / IP</th><th>Age</th><th>SLA</th><th /></tr></thead>
                <tbody>{visible.map((a) => (
                  <tr key={a.id}>
                    <td><Sev v={a.severity} /></td>
                    <td className="wrap">{a.title}</td>
                    <td className="mono">{a.host || a.src_ip || '—'}</td>
                    <td>{ago(a.time)}</td>
                    <td><Countdown dueIso={a.ack_due} /></td>
                    <td className="row" style={{ gap: 4 }}>
                      <button className="btn small primary" disabled={claim.isPending} onClick={() => claim.mutate(a)}>Claim</button>
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
