import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Clock, Database, MinusCircle, Plus, Search, Shield, Trash2, XCircle, Zap } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Status } from '../components/ui';
import { del, get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type Job = { id: string; indicator: string; type: string; status: string; verdict: string; results: Record<string, any>; tlp: string; created_at: string; alert_id?: string; case_id?: string };
type Rule = { id: string; name: string; description: string; rule_type: string; indicator_type: string; pattern: string; verdict: string; confidence: number; tags: string[]; enabled: boolean; hit_count: number; last_hit_at: string | null; created_at: string };
type EngineStats = { indicators: { total: number; by_verdict: Record<string, number>; auto_learned: number }; rules: { total: number; enabled: number; total_hits: number } };

const VERDICT_COLORS: Record<string, string> = { malicious: 'var(--bad)', suspicious: 'var(--warn)', benign: 'var(--ok)', unknown: 'var(--muted)' };
const VERDICT_ICONS: Record<string, typeof Shield> = { malicious: XCircle, suspicious: AlertTriangle, benign: CheckCircle2, unknown: Search };

export default function Enrichment() {
  const [tab, setTab] = useState<'jobs' | 'rules'>('jobs');
  return (
    <>
      <PageHead title="Enrichment Engine" sub="Local IOC database, custom rules, and reputation scoring." />
      <EngineOverview />
      <div className="tabs" role="tablist" style={{ marginBottom: 16 }}>
        <button type="button" role="tab" aria-selected={tab === 'jobs'} className={tab === 'jobs' ? 'active' : ''} onClick={() => setTab('jobs')}>Enrichment Jobs</button>
        <button type="button" role="tab" aria-selected={tab === 'rules'} className={tab === 'rules' ? 'active' : ''} onClick={() => setTab('rules')}>Enrichment Rules</button>
      </div>
      {tab === 'jobs' ? <JobsPanel /> : <RulesPanel />}
    </>
  );
}

function EngineOverview() {
  const stats = useQuery({ queryKey: ['enrichment-stats'], queryFn: () => get<EngineStats>('/api/enrichment/stats'), refetchInterval: REFRESH_MS });
  if (!stats.data) return null;
  const s = stats.data;
  return (
    <div className="kpi-row" style={{ marginBottom: 16 }}>
      <div className="kpi"><Database size={18} /><div><strong>{s.indicators.total}</strong><small>Local IOCs</small></div></div>
      <div className="kpi"><XCircle size={18} style={{ color: 'var(--bad)' }} /><div><strong>{s.indicators.by_verdict?.malicious ?? 0}</strong><small>Malicious</small></div></div>
      <div className="kpi"><Zap size={18} style={{ color: 'var(--info)' }} /><div><strong>{s.rules.enabled}</strong><small>Active rules</small></div></div>
      <div className="kpi"><CheckCircle2 size={18} style={{ color: 'var(--ok)' }} /><div><strong>{s.rules.total_hits}</strong><small>Rule hits</small></div></div>
      <div className="kpi"><Shield size={18} style={{ color: 'var(--accent)' }} /><div><strong>{s.indicators.auto_learned}</strong><small>Auto-learned</small></div></div>
    </div>
  );
}

function JobsPanel() {
  const { can } = useAuth();
  const [ind, setInd] = useState('');
  const [alertId, setAlertId] = useState('');
  const jobs = useQuery({ queryKey: ['intel-jobs'], queryFn: () => get<Job[]>('/api/intel/jobs'), refetchInterval: REFRESH_MS });
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

function ReputationBadge({ results }: { results: Record<string, any> }) {
  const rep = results?._reputation;
  if (!rep) return null;
  const color = rep.score >= 75 ? 'var(--bad)' : rep.score >= 40 ? 'var(--warn)' : rep.score > 0 ? 'var(--ok)' : 'var(--muted)';
  return (
    <div style={{ background: 'var(--soft)', borderRadius: 8, padding: '12px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{ textAlign: 'center', minWidth: 60 }}>
        <div style={{ fontSize: 28, fontWeight: 700, color, fontVariantNumeric: 'tabular-nums' }}>{rep.score}</div>
        <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase' }}>Risk Score</div>
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ height: 8, borderRadius: 4, background: 'var(--border)', overflow: 'hidden', marginBottom: 6 }}>
          <div style={{ width: `${rep.score}%`, height: '100%', background: color, borderRadius: 4 }} />
        </div>
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>
          {rep.sources} source{rep.sources !== 1 ? 's' : ''} · {rep.confidence}% confidence
        </div>
      </div>
    </div>
  );
}

function JobDrawer({ job, onClose }: { job: Job; onClose: () => void }) {
  const sources = Object.entries(job.results || {}).filter(([k]) => !k.startsWith('_'));
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
      <ReputationBadge results={job.results} />
      <dl className="kv">
        <dt>Created</dt><dd>{ago(job.created_at)}</dd>
        {job.alert_id && <><dt>Alert</dt><dd className="mono">{job.alert_id}</dd></>}
        {job.case_id && <><dt>Case</dt><dd className="mono">{job.case_id}</dd></>}
      </dl>
      <h4 style={{ marginTop: 16, marginBottom: 8 }}>Source Results ({sources.length})</h4>
      {sources.length === 0 ? <Empty>No sources returned data.</Empty> : sources.map(([name, data]) => (
        <details key={name} open style={{ marginBottom: 8, border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
            {data.error ? <XCircle size={14} style={{ color: 'var(--bad)' }} /> : data.skipped ? <MinusCircle size={14} style={{ color: 'var(--muted)' }} /> : <CheckCircle2 size={14} style={{ color: 'var(--ok)' }} />}
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
  if (data.skipped) return <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 8 }}>Not asked: {String(data.skipped)}</p>;

  if (name === 'Local Intel' && data.matched) {
    return (
      <div style={{ marginTop: 8 }}>
        <dl className="kv">
          <dt>Verdict</dt><dd style={{ color: VERDICT_COLORS[data.verdict] }}>{data.verdict}</dd>
          <dt>Confidence</dt><dd>{data.confidence}%</dd>
          <dt>Source</dt><dd>{data.source}</dd>
          <dt>Sightings</dt><dd>{data.sightings}</dd>
          {data.labels?.length > 0 && <><dt>Labels</dt><dd>{data.labels.join(', ')}</dd></>}
          {data.first_seen && <><dt>First seen</dt><dd>{data.first_seen}</dd></>}
        </dl>
      </div>
    );
  }

  if (name === 'Custom Rules' && data.matches) {
    return (
      <div style={{ marginTop: 8 }}>
        {data.tags?.length > 0 && <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>{data.tags.map((t: string) => <span key={t} className="badge">{t}</span>)}</div>}
        {data.matches.map((m: any) => (
          <div key={m.rule_id} style={{ fontSize: 13, padding: '4px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Zap size={12} style={{ color: VERDICT_COLORS[m.verdict] }} />
            <strong>{m.rule_name}</strong>
            <span style={{ color: VERDICT_COLORS[m.verdict] }}>{m.verdict}</span>
            <span style={{ color: 'var(--muted)', fontSize: 11 }}>{m.confidence}% confidence</span>
          </div>
        ))}
      </div>
    );
  }

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

function RulesPanel() {
  const { can } = useAuth();
  const rules = useQuery({ queryKey: ['enrichment-rules'], queryFn: () => get<Rule[]>('/api/enrichment/rules'), refetchInterval: REFRESH_MS });
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', rule_type: 'cidr', indicator_type: 'ip', pattern: '', verdict: 'suspicious', confidence: 70, tags: '' });
  const create = useAct(() => post('/api/enrichment/rules', { ...form, confidence: Number(form.confidence), tags: form.tags ? form.tags.split(',').map((t) => t.trim()) : [] }), ['enrichment-rules', 'enrichment-stats'], 'Rule created', () => { setShowAdd(false); setForm({ name: '', description: '', rule_type: 'cidr', indicator_type: 'ip', pattern: '', verdict: 'suspicious', confidence: 70, tags: '' }); });
  const remove = useAct((id: string) => del(`/api/enrichment/rules/${id}`), ['enrichment-rules', 'enrichment-stats'], 'Rule deleted');

  const RULE_TYPES: Record<string, string> = { cidr: 'CIDR Range', domain_pattern: 'Domain Pattern', hash_list: 'Hash List', regex: 'Regex' };
  const HINTS: Record<string, string> = { cidr: '10.0.0.0/8, 192.168.1.0/24', domain_pattern: '*.evil.com, *.malware.xyz', hash_list: 'abc123..., def456...', regex: '.*\\.ru$' };

  return (
    <>
      {can('intel.enrich') && (
        <div style={{ marginBottom: 16 }}>
          {!showAdd ? (
            <button className="btn primary" onClick={() => setShowAdd(true)}><Plus size={14} /> Add Rule</button>
          ) : (
            <div className="card" style={{ padding: 16 }}>
              <h4 style={{ marginBottom: 12 }}>New Enrichment Rule</h4>
              <form onSubmit={(e) => { e.preventDefault(); if (form.name.length >= 2 && form.pattern.length >= 1) create.mutate(undefined); }} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <input placeholder="Rule name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} style={{ gridColumn: '1 / -1' }} />
                <select value={form.rule_type} onChange={(e) => setForm({ ...form, rule_type: e.target.value })}>
                  {Object.entries(RULE_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
                <select value={form.indicator_type} onChange={(e) => setForm({ ...form, indicator_type: e.target.value })}>
                  <option value="ip">IP</option><option value="domain">Domain</option><option value="hash">Hash</option><option value="url">URL</option><option value="any">Any</option>
                </select>
                <textarea placeholder={HINTS[form.rule_type] || 'Pattern'} value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} rows={2} style={{ gridColumn: '1 / -1' }} />
                <select value={form.verdict} onChange={(e) => setForm({ ...form, verdict: e.target.value })}>
                  <option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="benign">Benign</option>
                </select>
                <input type="number" min={0} max={100} placeholder="Confidence (0-100)" value={form.confidence} onChange={(e) => setForm({ ...form, confidence: Number(e.target.value) })} />
                <input placeholder="Tags (comma-separated)" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
                <input placeholder="Description (optional)" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8 }}>
                  <button className="btn primary" type="submit" disabled={form.name.length < 2 || form.pattern.length < 1 || create.isPending}>Create</button>
                  <button className="btn" type="button" onClick={() => setShowAdd(false)}>Cancel</button>
                </div>
              </form>
              {create.error && <ErrorBox error={create.error} />}
            </div>
          )}
        </div>
      )}
      {rules.isLoading ? <Loading /> : rules.error ? <ErrorBox error={rules.error} /> : rules.data!.length === 0 ? <Empty>No enrichment rules. Create rules to auto-tag and score indicators from CIDR ranges, domain patterns, hash watchlists, or regex.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Indicator</th><th>Verdict</th><th>Confidence</th><th>Hits</th><th>Status</th><th /></tr></thead>
          <tbody>{rules.data!.map((r) => (
            <tr key={r.id}>
              <td><strong>{r.name}</strong>{r.description && <div style={{ fontSize: 11, color: 'var(--muted)' }}>{r.description}</div>}</td>
              <td><span className="badge">{RULE_TYPES[r.rule_type] || r.rule_type}</span></td>
              <td><span className="badge">{r.indicator_type}</span></td>
              <td><span style={{ color: VERDICT_COLORS[r.verdict] }}>{r.verdict}</span></td>
              <td>{r.confidence}%</td>
              <td>{r.hit_count}{r.last_hit_at && <div style={{ fontSize: 11, color: 'var(--muted)' }}>{ago(r.last_hit_at)}</div>}</td>
              <td><span className={`badge ${r.enabled ? 'st-ok' : 'st-down'}`}>{r.enabled ? 'Active' : 'Disabled'}</span></td>
              <td>{can('intel.enrich') && <button className="btn small" onClick={() => remove.mutate(r.id)} title="Delete"><Trash2 size={13} /></button>}</td>
            </tr>
          ))}</tbody></table></div>
      )}
    </>
  );
}

