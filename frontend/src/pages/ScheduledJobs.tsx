import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Skeleton } from '../components/Interactive';
import { Chips, Summary } from '../components/manage';
import { Empty, ErrorBox, PageHead, Pager, Status } from '../components/ui';
import { get, type Page } from '../lib/api';
import { ago, when } from '../lib/format';

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
  { value: '', label: 'All' },
  { value: 'enrichment', label: 'Enrichment' },
  { value: 'report', label: 'Reports' },
  { value: 'automation', label: 'Automation' },
  { value: 'playbook', label: 'Playbooks' },
  { value: 'backup', label: 'Backups' },
];
const STATUSES = ['queued', 'running', 'done', 'completed', 'failed'];

export default function ScheduledJobs() {
  const [tab, setTab] = useState<'jobs' | 'schedules'>('jobs');
  const [category, setCategory] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);
  const limit = 50;

  const overview = useQuery({ queryKey: ['jobs-overview'], queryFn: () => get<Overview>('/api/jobs/overview') });
  const jobs = useQuery({
    queryKey: ['jobs-list', category, statusFilter, page],
    queryFn: () => get<Page<JobItem>>('/api/jobs/', { category, status: statusFilter, page, size: limit }),
    enabled: tab === 'jobs',
  });
  const schedules = useQuery({ queryKey: ['jobs-schedules'], queryFn: () => get<Schedule[]>('/api/jobs/schedules'), enabled: tab === 'schedules' });

  const o = overview.data;
  const failed = o ? o.playbooks.failed + o.enrichment.failed + o.reports.failed : 0;
  const clear = () => { setCategory(''); setStatusFilter(''); setPage(1); };

  return (
    <>
      <PageHead title="Scheduled Jobs" sub="Platform jobs, automation runs, report schedules and background tasks." />
      {o && <Summary items={[
        { label: 'Enrichment jobs', value: o.enrichment.total },
        { label: 'Active', value: o.enrichment.active },
        { label: 'Report schedules', value: o.schedules.total },
        { label: 'Automation rules', value: o.automation.enabled },
        { label: 'Runs (24h)', value: o.automation.runs_24h },
        { label: 'Failed', value: failed, tone: failed > 0 ? 'bad' : 'ok' },
      ]} />}

      <div className="tabs" style={{ marginBottom: 12 }}>
        <button className={tab === 'jobs' ? 'active' : ''} onClick={() => setTab('jobs')}>Job history</button>
        <button className={tab === 'schedules' ? 'active' : ''} onClick={() => setTab('schedules')}>Report schedules{o ? ` (${o.schedules.total})` : ''}</button>
      </div>

      {tab === 'jobs' && (
        <>
          <Chips items={CATEGORIES.map((c) => ({ label: c.label, active: category === c.value, onClick: () => { setCategory(c.value); setPage(1); } }))} />
          <div className="filters">
            <select aria-label="Status" style={{ flex: "0 1 220px" }} value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
              <option value="">Any status</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            {(category || statusFilter) && <button className="btn" onClick={clear}>Clear filters</button>}
          </div>
          {jobs.isLoading ? <Skeleton lines={6} /> : jobs.error ? <ErrorBox error={jobs.error} onRetry={() => void jobs.refetch()} retrying={jobs.isFetching} /> : jobs.data!.items.length === 0 ? (
            <Empty onAction={category || statusFilter ? clear : undefined}>No jobs match these filters.</Empty>
          ) : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Status</th><th>Category</th><th>Name</th><th>Type</th><th>Verdict</th><th>Started</th><th>Finished</th><th>Error</th></tr></thead>
                <tbody>{jobs.data!.items.map((j) => (
                  <tr key={j.id}>
                    <td><Status v={j.status} /></td>
                    <td><span className="badge">{j.category}</span></td>
                    <td className="wrap">{j.name}</td>
                    <td>{j.type || '—'}</td>
                    <td>{j.verdict ? <span className="badge">{j.verdict}</span> : '—'}</td>
                    <td title={when(j.created_at)}>{ago(j.created_at)}</td>
                    <td title={when(j.finished_at)}>{j.finished_at ? ago(j.finished_at) : '—'}</td>
                    <td className="wrap" style={{ color: j.error ? 'var(--bad)' : undefined }}>{j.error || '—'}</td>
                  </tr>
                ))}</tbody>
              </table></div>
              <Pager page={page} limit={limit} total={jobs.data!.total} set={setPage} />
            </>
          )}
        </>
      )}

      {tab === 'schedules' && (
        schedules.isLoading ? <Skeleton lines={4} /> : schedules.error ? <ErrorBox error={schedules.error} onRetry={() => void schedules.refetch()} retrying={schedules.isFetching} /> : schedules.data!.length === 0 ? (
          <Empty>No report schedules yet. Create one from the Reports page.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead><tr><th>Status</th><th>Name</th><th>Report</th><th>Cadence</th><th>Format</th><th>Next run</th><th>Last run</th><th>Last result</th></tr></thead>
            <tbody>{schedules.data!.map((s) => (
              <tr key={s.id}>
                <td><Status v={s.paused ? 'paused' : 'active'} /></td>
                <td className="wrap">{s.name}</td>
                <td><span className="badge">{s.kind}</span></td>
                <td>{s.cadence} at {String(s.hour).padStart(2, '0')}:00 <span style={{ color: 'var(--muted)' }}>{s.timezone}</span></td>
                <td>{s.fmt.toUpperCase()}</td>
                <td title={when(s.next_run_at)}>{s.paused ? '—' : when(s.next_run_at)}</td>
                <td title={when(s.last_run_at)}>{s.last_run_at ? ago(s.last_run_at) : '—'}</td>
                <td>{s.last_status ? <Status v={s.last_status} /> : '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )
      )}
    </>
  );
}
