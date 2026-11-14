import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, CheckCircle2, Pause, XCircle } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';
import { get } from '../lib/api';
import { ago } from '../lib/format';

type ToolHealth = {
  id: string; name: string; label: string; type: string; enabled: boolean; status: string; health_status: 'healthy' | 'degraded' | 'down' | 'paused' | 'disabled';
  health: { last_success_at: string | null; last_attempt_at: string | null; last_error: string; error_count: number; items_today: number; items_total: number; lag_seconds: number | null } | null;
};
type HealthData = { total: number; counts: Record<string, number>; avg_lag_seconds: number | null; total_errors: number; total_items_today: number; tools: ToolHealth[] };

const STATUS_META: Record<string, { color: string; icon: typeof CheckCircle2; label: string }> = {
  healthy: { color: 'var(--ok)', icon: CheckCircle2, label: 'Healthy' },
  degraded: { color: 'var(--warn)', icon: AlertTriangle, label: 'Degraded' },
  down: { color: 'var(--bad)', icon: XCircle, label: 'Down' },
  paused: { color: 'var(--muted)', icon: Pause, label: 'Paused' },
  disabled: { color: 'var(--muted)', icon: Pause, label: 'Disabled' },
};

export default function IntegrationHealth() {
  const [filter, setFilter] = useState<string>('');
  const q = useQuery({ queryKey: ['integration-health'], queryFn: () => get<HealthData>('/api/integrations/health'), refetchInterval: 15000 });

  if (q.isLoading) return <><PageHead title="Integration Health" sub="Live status of every connected tool." /><Loading /></>;
  if (q.error) return <><PageHead title="Integration Health" sub="Live status of every connected tool." /><ErrorBox error={q.error} /></>;
  const d = q.data!;
  const rows = filter ? d.tools.filter((t) => t.health_status === filter) : d.tools;

  return (
    <>
      <PageHead title="Integration Health" sub="Live status, sync lag and error counts across every connected tool." />
      <div className="kpi-row" style={{ marginBottom: 16 }}>
        <div className="kpi"><Activity size={18} /><div><strong>{d.total}</strong><small>Tools linked</small></div></div>
        {(['healthy', 'degraded', 'down', 'paused'] as const).map((k) => {
          const meta = STATUS_META[k];
          return (
            <button key={k} type="button" className="kpi" style={{ cursor: 'pointer', border: filter === k ? `2px solid ${meta.color}` : undefined, textAlign: 'left' }} onClick={() => setFilter((f) => (f === k ? '' : k))}>
              <meta.icon size={18} style={{ color: meta.color }} /><div><strong>{d.counts[k] ?? 0}</strong><small>{meta.label}</small></div>
            </button>
          );
        })}
        <div className="kpi"><div><strong>{d.avg_lag_seconds != null ? `${Math.round(d.avg_lag_seconds)}s` : '—'}</strong><small>Avg sync lag</small></div></div>
        <div className="kpi"><div><strong>{d.total_errors}</strong><small>Active errors</small></div></div>
      </div>

      {filter && <button className="btn small" style={{ marginBottom: 12 }} onClick={() => setFilter('')}>Clear filter</button>}

      {rows.length === 0 ? <Empty>No tools match this filter.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Status</th><th>Tool</th><th>Type</th><th>Last sync</th><th>Lag</th><th>Items today</th><th>Errors</th><th /></tr></thead>
            <tbody>{rows.map((t) => {
              const meta = STATUS_META[t.health_status];
              return (
                <tr key={t.id}>
                  <td><span className="row" style={{ gap: 6, alignItems: 'center' }}><meta.icon size={14} style={{ color: meta.color }} />{meta.label}</span></td>
                  <td>{t.name}</td>
                  <td>{t.label}</td>
                  <td>{t.health ? ago(t.health.last_success_at) : '—'}</td>
                  <td>{t.health?.lag_seconds != null ? `${Math.round(t.health.lag_seconds)}s` : '—'}</td>
                  <td>{t.health?.items_today ?? 0}</td>
                  <td>{t.health?.error_count ? <span style={{ color: 'var(--bad)' }}>{t.health.error_count}{t.health.last_error ? ` — ${t.health.last_error.slice(0, 60)}` : ''}</span> : 0}</td>
                  <td><Link className="btn small" to="/app/integrations">Manage</Link></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
    </>
  );
}
