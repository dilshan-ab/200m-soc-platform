import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, CheckCircle2, Clock, Database, ExternalLink, Search, Shield, XCircle } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Status } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';

type Provider = { type: string; label: string; category: string; capabilities: string[]; setup_hint: string; configured: boolean; id?: string; name?: string; enabled?: boolean };
type Job = { id: string; indicator: string; type: string; status: string; verdict: string; results: Record<string, any>; tlp: string; created_at: string; alert_id?: string; case_id?: string };

const VERDICT_COLORS: Record<string, string> = { malicious: 'var(--bad)', suspicious: 'var(--warn)', benign: 'var(--ok)', unknown: 'var(--muted)' };
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
          <div className="kpi"><XCircle size={18} style={{ color: 'var(--bad)' }} /><div><strong>{stats.malicious}</strong><small>Malicious</small></div></div>
          <div className="kpi"><AlertTriangle size={18} style={{ color: 'var(--warn)' }} /><div><strong>{stats.suspicious}</strong><small>Suspicious</small></div></div>
          <div className="kpi"><Clock size={18} style={{ color: 'var(--info)' }} /><div><strong>{stats.running}</strong><small>In progress</small></div></div>
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
            {data.error ? <XCircle size={14} style={{ color: 'var(--bad)' }} /> : <CheckCircle2 size={14} style={{ color: 'var(--ok)' }} />}
            {name}
            {data.verdict && <span style={{ marginLeft: 'auto', fontSize: 12, color: VERDICT_COLORS[data.verdict] }}>{data.verdict}</span>}
          </summary>
          <SourceResult name={name} data={data} />
        </details>
      ))}
    </Drawer>
  );
}

function Segmented({ segments, total }: { segments: { key: string; label: string; value: number; color: string }[]; total: number }) {
  const t = total || 1;
  return (
    <>
      <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', background: 'var(--soft)' }}>
        {segments.filter((s) => s.value > 0).map((s) => (
          <div key={s.key} title={`${s.label}: ${s.value}`} style={{ width: `${(s.value / t) * 100}%`, background: s.color }} />
        ))}
      </div>
      <div className="row" style={{ gap: 12, marginTop: 6, fontSize: 12, flexWrap: 'wrap' }}>
        {segments.map((s) => (
          <span key={s.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--muted)' }}>
            <i style={{ width: 8, height: 8, borderRadius: 4, background: s.color, display: 'inline-block' }} />{s.label}: {s.value}
          </span>
        ))}
      </div>
    </>
  );
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 50 ? 'var(--bad)' : score > 0 ? 'var(--warn)' : 'var(--ok)';
  return (
    <div className="row" style={{ gap: 10, alignItems: 'center' }}>
      <div style={{ flex: 1, height: 10, borderRadius: 5, background: 'var(--soft)', overflow: 'hidden' }}>
        <div style={{ width: `${Math.min(100, Math.max(0, score))}%`, height: '100%', background: color }} />
      </div>
      <strong style={{ color, fontSize: 13 }}>{score}%</strong>
    </div>
  );
}

function KvFallback({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([k]) => k !== 'verdict');
  if (entries.length === 0) return <p style={{ color: 'var(--muted)', fontSize: 12, marginTop: 8 }}>No additional detail returned.</p>;
  return (
    <dl className="kv" style={{ marginTop: 8 }}>
      {entries.map(([k, v]) => (
        <Fragment key={k}>
          <dt>{k.replace(/_/g, ' ')}</dt>
          <dd className="wrap">{Array.isArray(v) ? (v.length ? v.join(', ') : '—') : v && typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

function SourceResult({ name, data }: { name: string; data: Record<string, any> }) {
  if (data.error) return <p style={{ color: 'var(--bad)', fontSize: 13, marginTop: 8 }}>{String(data.error)}</p>;

  if (name === 'VirusTotal' && data.stats) {
    const stats = data.stats as Record<string, number>;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    const segments = [
      { key: 'malicious', label: 'Malicious', value: stats.malicious ?? 0, color: 'var(--bad)' },
      { key: 'suspicious', label: 'Suspicious', value: stats.suspicious ?? 0, color: 'var(--warn)' },
      { key: 'harmless', label: 'Harmless', value: stats.harmless ?? 0, color: 'var(--ok)' },
      { key: 'undetected', label: 'Undetected', value: stats.undetected ?? 0, color: 'var(--muted)' },
    ];
    return (
      <div style={{ marginTop: 8 }}>
        <Segmented segments={segments} total={total} />
        <p style={{ fontSize: 12, color: 'var(--muted)', margin: '6px 0 0' }}>{total} security vendors scanned this indicator.</p>
      </div>
    );
  }

  if (name === 'AbuseIPDB' && data.abuse_score != null) {
    return (
      <div style={{ marginTop: 8 }}>
        <ScoreBar score={data.abuse_score} />
        <p style={{ fontSize: 12, color: 'var(--muted)', margin: '6px 0 0' }}>
          {data.total_reports} report{data.total_reports === 1 ? '' : 's'}{data.isp ? ` · ${data.isp}` : ''}
        </p>
      </div>
    );
  }

  if (name === 'AlienVault OTX' && data.pulse_count != null) {
    return <p style={{ fontSize: 13, marginTop: 8 }}><strong>{data.pulse_count}</strong> threat pulse{data.pulse_count === 1 ? '' : 's'} reference this indicator.</p>;
  }

  if (name === 'Shodan') {
    const ports: number[] = data.ports ?? [];
    const vulns: string[] = data.vulns ?? [];
    return (
      <div style={{ marginTop: 8 }}>
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', marginBottom: ports.length ? 6 : 0 }}>
          {ports.length > 0 ? ports.map((p) => <span key={p} className="badge">{p}</span>) : <span style={{ fontSize: 12, color: 'var(--muted)' }}>No open ports found</span>}
        </div>
        {vulns.length > 0 && <p style={{ fontSize: 12, color: 'var(--bad)', margin: '0 0 6px' }}>Vulnerabilities: {vulns.join(', ')}</p>}
        <p style={{ fontSize: 12, color: 'var(--muted)', margin: 0 }}>{[data.org, data.isp, data.country].filter(Boolean).join(' · ') || '—'}</p>
      </div>
    );
  }

  if ((name === 'MISP' || name === 'OpenCTI') && data.matches != null) {
    return (
      <p style={{ fontSize: 13, marginTop: 8 }}>
        <strong>{data.matches}</strong> match{data.matches === 1 ? '' : 'es'} found{data.events?.length ? ` across events ${data.events.join(', ')}` : ''}
      </p>
    );
  }

  return <KvFallback data={data} />;
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
                <Activity size={18} style={{ color: p.enabled ? 'var(--ok)' : 'var(--muted)' }} />
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
