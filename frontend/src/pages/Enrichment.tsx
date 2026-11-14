import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, CheckCircle2, Clock, Database, ExternalLink, Search, Shield, XCircle } from 'lucide-react';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Status } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';

type Provider = { type: string; label: string; category: string; capabilities: string[]; setup_hint: string; configured: boolean; id?: string; name?: string; enabled?: boolean };
type Job = { id: string; indicator: string; type: string; status: string; verdict: string; results: Record<string, any>; tlp: string; created_at: string; alert_id?: string; case_id?: string };

const VERDICT_COLORS: Record<string, string> = { malicious: 'var(--red)', suspicious: 'var(--yellow)', benign: 'var(--green)', unknown: 'var(--muted)' };
const VERDICT_ICONS: Record<string, typeof Shield> = { malicious: XCircle, suspicious: AlertTriangle, benign: CheckCircle2, unknown: Search };

export default function Enrichment() {
  const [tab, setTab] = useState<'jobs' | 'providers'>('jobs');
  return (
    <>
      <PageHead title="Enrichment" sub="IOC enrichment across VirusTotal, AbuseIPDB, OTX, Shodan, MISP, Cortex, and OpenCTI." />
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={tab === 'jobs' ? 'active' : ''} onClick={() => setTab('jobs')}>Enrichment Jobs</button>
        <button className={tab === 'providers' ? 'active' : ''} onClick={() => setTab('providers')}>Providers</button>
      </div>
      {tab === 'jobs' ? <JobsPanel /> : <ProvidersPanel />}
    </>
  );
}

function JobsPanel() {
  const { can } = useAuth();
  const [ind, setInd] = useState('');
  const [alertId, setAlertId] = useState('');
  const jobs = useQuery({ queryKey: ['intel-jobs'], queryFn: () => get<Job[]>('/api/intel/jobs'), refetchInterval: 10000 });
  const run = useAct(() => post('/api/intel/enrich', { indicator: ind.trim(), alert_id: alertId || undefined }), ['intel-jobs'], 'Enrichment queued', () => { setInd(''); setAlertId(''); });
  const [detail, setDetail] = useState<Job | null>(null);

  const stats = jobs.data ? {
    total: jobs.data.length,
    malicious: jobs.data.filter((j) => j.verdict === 'malicious').length,
    suspicious: jobs.data.filter((j) => j.verdict === 'suspicious').length,
    running: jobs.data.filter((j) => j.status === 'running' || j.status === 'queued').length,
  } : null;

  return (
    <>
      {stats && (
        <div className="kpi-row" style={{ marginBottom: 16 }}>
          <div className="kpi"><Database size={18} /><div><strong>{stats.total}</strong><small>Total jobs</small></div></div>
          <div className="kpi"><XCircle size={18} style={{ color: 'var(--red)' }} /><div><strong>{stats.malicious}</strong><small>Malicious</small></div></div>
          <div className="kpi"><AlertTriangle size={18} style={{ color: 'var(--yellow)' }} /><div><strong>{stats.suspicious}</strong><small>Suspicious</small></div></div>
          <div className="kpi"><Clock size={18} style={{ color: 'var(--blue)' }} /><div><strong>{stats.running}</strong><small>In progress</small></div></div>
        </div>
      )}
      {can('intel.enrich') && (
        <form className="row" onSubmit={(e) => { e.preventDefault(); if (ind.trim().length >= 3) run.mutate(undefined); }} style={{ marginBottom: 12, gap: 8 }}>
          <input style={{ flex: 2 }} placeholder="IP, domain, URL or file hash" aria-label="Indicator" value={ind} onChange={(e) => setInd(e.target.value)} />
          <input style={{ flex: 1 }} placeholder="Alert ID (optional)" aria-label="Alert ID" value={alertId} onChange={(e) => setAlertId(e.target.value)} />
          <button className="btn primary" disabled={ind.trim().length < 3 || run.isPending}>Enrich</button>
        </form>
      )}
      {run.error && <ErrorBox error={run.error} />}
      {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data!.length === 0 ? <Empty>No enrichment jobs yet. Submit an indicator above or enable auto-enrichment.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Type</th><th>Status</th><th>Verdict</th><th>Sources</th><th>TLP</th><th>When</th><th /></tr></thead>
          <tbody>{jobs.data!.map((j) => {
            const Icon = VERDICT_ICONS[j.verdict] || Search;
            return (
              <tr key={j.id}>
                <td className="mono wrap">{j.indicator}</td>
                <td><span className="badge">{j.type}</span></td>
                <td><Status v={j.status} /></td>
                <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: VERDICT_COLORS[j.verdict] }}><Icon size={14} />{j.verdict}</span></td>
                <td>{Object.keys(j.results || {}).length}</td>
                <td><span className={`badge tlp-${j.tlp?.toLowerCase()}`}>{j.tlp}</span></td>
                <td>{ago(j.created_at)}</td>
                <td><button className="btn small" onClick={() => setDetail(j)}>Details</button></td>
              </tr>
            );
          })}</tbody></table></div>
      )}
      {detail && <JobDrawer job={detail} onClose={() => setDetail(null)} />}
    </>
  );
}

function JobDrawer({ job, onClose }: { job: Job; onClose: () => void }) {
  const sources = Object.entries(job.results || {});
  const Icon = VERDICT_ICONS[job.verdict] || Search;
  return (
    <Drawer title={job.indicator} onClose={onClose}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <Icon size={20} style={{ color: VERDICT_COLORS[job.verdict] }} />
        <span style={{ fontSize: 18, fontWeight: 600, color: VERDICT_COLORS[job.verdict] }}>{job.verdict}</span>
        <span className="badge">{job.type}</span>
        <span className={`badge tlp-${job.tlp?.toLowerCase()}`}>{job.tlp}</span>
        <Status v={job.status} />
      </div>
      <dl className="kv">
        <dt>Created</dt><dd>{ago(job.created_at)}</dd>
        {job.alert_id && <><dt>Alert</dt><dd className="mono">{job.alert_id}</dd></>}
        {job.case_id && <><dt>Case</dt><dd className="mono">{job.case_id}</dd></>}
      </dl>
      <h4 style={{ marginTop: 16, marginBottom: 8 }}>Source Results ({sources.length})</h4>
      {sources.length === 0 ? <Empty>No sources returned data.</Empty> : sources.map(([name, data]) => (
        <details key={name} open style={{ marginBottom: 8, border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
            {data.error ? <XCircle size={14} style={{ color: 'var(--red)' }} /> : <CheckCircle2 size={14} style={{ color: 'var(--green)' }} />}
            {name}
            {data.verdict && <span style={{ marginLeft: 'auto', fontSize: 12, color: VERDICT_COLORS[data.verdict] }}>{data.verdict}</span>}
          </summary>
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', fontSize: 12, marginTop: 8, maxHeight: '30vh', overflow: 'auto' }}>{JSON.stringify(data, null, 2)}</pre>
        </details>
      ))}
    </Drawer>
  );
}

function ProvidersPanel() {
  const providers = useQuery({ queryKey: ['intel-providers'], queryFn: () => get<Provider[]>('/api/intel/providers') });

  if (providers.isLoading) return <Loading />;
  if (providers.error) return <ErrorBox error={providers.error} />;
  const data = providers.data!;
  const configured = data.filter((p) => p.configured);
  const available = data.filter((p) => !p.configured);

  return (
    <>
      <h3 style={{ marginBottom: 12 }}>Configured Providers ({configured.length})</h3>
      {configured.length === 0 ? <Empty>No enrichment providers configured. Add integrations in Settings → Integrations.</Empty> : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12, marginBottom: 24 }}>
          {configured.map((p) => (
            <div key={p.type} className="card" style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Activity size={18} style={{ color: p.enabled ? 'var(--green)' : 'var(--muted)' }} />
                <strong>{p.label}</strong>
                <span className={`badge ${p.enabled ? 'st-ok' : 'st-down'}`}>{p.enabled ? 'Active' : 'Disabled'}</span>
              </div>
              {p.name && <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 4 }}>Instance: {p.name}</div>}
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{p.capabilities.map((c) => <span key={c} className="badge">{c}</span>)}</div>
            </div>
          ))}
        </div>
      )}
      <h3 style={{ marginBottom: 12 }}>Available Providers ({available.length})</h3>
      {available.length === 0 ? <p style={{ color: 'var(--muted)' }}>All enrichment providers are configured.</p> : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
          {available.map((p) => (
            <div key={p.type} className="card" style={{ padding: 16, opacity: 0.7 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <ExternalLink size={18} style={{ color: 'var(--muted)' }} />
                <strong>{p.label}</strong>
                <span className="badge">Not configured</span>
              </div>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 4 }}>{p.setup_hint}</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{p.capabilities.map((c) => <span key={c} className="badge">{c}</span>)}</div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
