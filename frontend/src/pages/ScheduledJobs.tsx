import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Calendar, CheckCircle2, Clock, Database, Loader2, Pause, Play, RefreshCw, Zap } from 'lucide-react';
import { useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';
import { get } from '../lib/api';

type Overview = {
  enrichment: { total: number; active: number; failed: number };
  reports: { total: number; active: number; failed: number };
  schedules: { total: number; active: number; paused: number };
  automation: { total_rules: number; enabled: number; runs_24h: number };
  playbooks: { total_runs: number; running: number; failed: number };
  backups: { total: number };
};

type JobItem = {
  id: string; category: string; name: string; type: string; status: string;
  verdict: string; created_at: string; finished_at: string; error: string;
};

type Schedule = {
  id: string; name: string; kind: string; cadence: string; hour: number;
  timezone: string; fmt: string; paused: boolean;
  next_run_at: string; last_run_at: string; last_status: string;
};

const CATEGORIES = [
  { value: '', label: 'All categories' },
  { value: 'enrichment', label: 'Enrichment' },
  { value: 'report', label: 'Reports' },
  { value: 'automation', label: 'Automation' },
  { value: 'playbook', label: 'Playbooks' },
  { value: 'backup', label: 'Backups' },
];

const STATUS_COLORS: Record<string, string> = {
  queued: 'var(--muted)',
  running: 'var(--accent)',
  done: 'var(--green)',
  completed: 'var(--green)',
  failed: 'var(--red)',
  rate_limited: 'var(--orange)',
  cancelled: 'var(--muted)',
  paused: 'var(--orange)',
  unknown: 'var(--muted)',
};

function statusIcon(status: string) {
  switch (status) {
    case 'running': case 'queued': return <Loader2 size={13} style={{ color: 'var(--accent)' }} className="spin" />;
    case 'done': case 'completed': return <CheckCircle2 size={13} style={{ color: 'var(--green)' }} />;
    case 'failed': return <AlertTriangle size={13} style={{ color: 'var(--red)' }} />;
    case 'paused': return <Pause size={13} style={{ color: 'var(--orange)' }} />;
    default: return <Clock size={13} style={{ color: 'var(--muted)' }} />;
  }
}

export default function ScheduledJobs() {
  const [tab, setTab] = useState<'jobs' | 'schedules'>('jobs');
  const [category, setCategory] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);
  const [size] = useState(50);

  const overview = useQuery({ queryKey: ['jobs-overview'], queryFn: () => get<Overview>('/api/jobs/overview') });

  const params = new URLSearchParams();
  if (category) params.set('category', category);
  if (statusFilter) params.set('status', statusFilter);
  params.set('page', String(page));
  params.set('size', String(size));

  const jobs = useQuery({
    queryKey: ['jobs-list', category, statusFilter, page],
    queryFn: () => get<{ total: number; items: JobItem[] }>(`/api/jobs/?${params.toString()}`),
    enabled: tab === 'jobs',
  });

  const schedules = useQuery({
    queryKey: ['jobs-schedules'],
    queryFn: () => get<Schedule[]>('/api/jobs/schedules'),
    enabled: tab === 'schedules',
  });

  const totalPages = jobs.data ? Math.ceil(jobs.data.total / size) : 0;

  return (
    <>
      <PageHead title="Scheduled Jobs" sub="Monitor all platform jobs, automation runs, report schedules, and background tasks." />

      {overview.data && (
        <div className="kpi-strip" style={{ marginBottom: 16 }}>
          <div className="kpi"><Zap size={18} /><div><strong>{overview.data.enrichment.total}</strong><small>Enrichment jobs</small></div></div>
          <div className="kpi"><RefreshCw size={18} /><div><strong>{overview.data.enrichment.active}</strong><small>Active</small></div></div>
          <div className="kpi"><Calendar size={18} /><div><strong>{overview.data.schedules.total}</strong><small>Schedules</small></div></div>
          <div className="kpi"><Play size={18} /><div><strong>{overview.data.automation.enabled}</strong><small>Automation rules</small></div></div>
          <div className="kpi"><Database size={18} /><div><strong>{overview.data.automation.runs_24h}</strong><small>Runs (24h)</small></div></div>
          <div className="kpi"><AlertTriangle size={18} /><div><strong>{overview.data.playbooks.failed + overview.data.enrichment.failed + overview.data.reports.failed}</strong><small>Failed</small></div></div>
        </div>
      )}

      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <div className="tab-bar">
          <button className={tab === 'jobs' ? 'active' : ''} onClick={() => setTab('jobs')}>Job History</button>
          <button className={tab === 'schedules' ? 'active' : ''} onClick={() => setTab('schedules')}>Schedules</button>
        </div>
        {tab === 'jobs' && (
          <>
            <select value={category} onChange={e => { setCategory(e.target.value); setPage(1); }} style={{ width: 160 }}>
              {CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
            <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }} style={{ width: 140 }}>
              <option value="">All statuses</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="done">Done</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </>
        )}
      </div>

      {tab === 'jobs' && (
        <>
          {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data!.items.length === 0 ? (
            <Empty>No jobs found{category ? ` in ${category}` : ''}{statusFilter ? ` with status "${statusFilter}"` : ''}.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Category</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Verdict</th>
                    <th>Started</th>
                    <th>Finished</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.data!.items.map(j => (
                    <tr key={j.id}>
                      <td>{statusIcon(j.status)} <span style={{ fontSize: 12, color: STATUS_COLORS[j.status] || 'var(--muted)' }}>{j.status}</span></td>
                      <td><span className="badge">{j.category}</span></td>
                      <td style={{ fontSize: 13 }}>{j.name}</td>
                      <td style={{ fontSize: 12, color: 'var(--muted)' }}>{j.type}</td>
                      <td>{j.verdict ? <span className="badge" style={{ background: j.verdict === 'matched' ? 'var(--green-bg)' : undefined }}>{j.verdict}</span> : '—'}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{j.created_at ? new Date(j.created_at).toLocaleString() : '—'}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{j.finished_at ? new Date(j.finished_at).toLocaleString() : '—'}</td>
                      <td style={{ fontSize: 12, color: 'var(--red)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.error || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {totalPages > 1 && (
            <div className="row" style={{ justifyContent: 'center', gap: 8, marginTop: 16 }}>
              <button className="btn small" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
              <span style={{ fontSize: 13, color: 'var(--muted)', padding: '6px 12px' }}>Page {page} of {totalPages}</span>
              <button className="btn small" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          )}
        </>
      )}

      {tab === 'schedules' && (
        <>
          {schedules.isLoading ? <Loading /> : schedules.error ? <ErrorBox error={schedules.error} /> : schedules.data!.length === 0 ? (
            <Empty>No report schedules configured. Create one from the Reports page.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Cadence</th>
                    <th>Hour</th>
                    <th>Format</th>
                    <th>Next run</th>
                    <th>Last run</th>
                    <th>Last status</th>
                  </tr>
                </thead>
                <tbody>
                  {schedules.data!.map(s => (
                    <tr key={s.id}>
                      <td>
                        {s.paused
                          ? <span style={{ color: 'var(--orange)', display: 'flex', alignItems: 'center', gap: 4 }}><Pause size={13} /> Paused</span>
                          : <span style={{ color: 'var(--green)', display: 'flex', alignItems: 'center', gap: 4 }}><Play size={13} /> Active</span>
                        }
                      </td>
                      <td style={{ fontSize: 13 }}>{s.name}</td>
                      <td><span className="badge">{s.kind}</span></td>
                      <td style={{ fontSize: 12 }}>{s.cadence}</td>
                      <td style={{ fontSize: 12 }}>{String(s.hour).padStart(2, '0')}:00</td>
                      <td style={{ fontSize: 12 }}>{s.fmt.toUpperCase()}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{s.next_run_at ? new Date(s.next_run_at).toLocaleString() : '—'}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{s.last_run_at ? new Date(s.last_run_at).toLocaleString() : '—'}</td>
                      <td>{s.last_status ? <span className="badge" style={{ background: s.last_status === 'done' ? 'var(--green-bg)' : s.last_status === 'failed' ? 'var(--red-bg)' : undefined }}>{s.last_status}</span> : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}
