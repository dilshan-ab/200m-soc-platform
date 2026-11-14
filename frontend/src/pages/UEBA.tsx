import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, Monitor, Shield, TrendingUp, User, XCircle } from 'lucide-react';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Sev } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';

type Profile = { id: string; entity_type: string; entity_value: string; risk_score: number; alert_count: number; baseline: any; anomalies: any[]; first_seen: string; last_seen: string; updated_at: string; client_id?: string };
type Summary = { total_entities: number; by_type: Record<string, number>; risk_distribution: Record<string, number>; top_risk: Profile[]; total_anomalies: number };

const RISK_COLORS: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange, var(--yellow))', medium: 'var(--yellow)', low: 'var(--green)' };
const ENTITY_ICONS: Record<string, typeof User> = { user: User, host: Monitor, ip: Activity };

function riskLabel(score: number): string {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

export default function UEBA() {
  const [tab, setTab] = useState<'overview' | 'entities'>('overview');
  return (
    <>
      <PageHead title="Behavior Analytics" sub="User and entity behavioral baselines, anomaly detection, and risk scoring." />
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>Overview</button>
        <button className={tab === 'entities' ? 'active' : ''} onClick={() => setTab('entities')}>Entity Profiles</button>
      </div>
      {tab === 'overview' ? <OverviewPanel /> : <EntitiesPanel />}
    </>
  );
}

function OverviewPanel() {
  const { can } = useAuth();
  const summary = useQuery({ queryKey: ['ueba-summary'], queryFn: () => get<Summary>('/api/ueba/summary'), refetchInterval: 30000 });
  const compute = useAct(() => post('/api/ueba/compute?days=30'), ['ueba-summary', 'ueba-profiles'], 'Profile computation started');
  const [detail, setDetail] = useState<Profile | null>(null);

  if (summary.isLoading) return <Loading />;
  if (summary.error) return <ErrorBox error={summary.error} />;
  const s = summary.data!;

  return (
    <>
      <div className="kpi-row" style={{ marginBottom: 16 }}>
        <div className="kpi"><Shield size={18} /><div><strong>{s.total_entities}</strong><small>Tracked entities</small></div></div>
        <div className="kpi"><XCircle size={18} style={{ color: 'var(--red)' }} /><div><strong>{s.risk_distribution.critical}</strong><small>Critical risk</small></div></div>
        <div className="kpi"><AlertTriangle size={18} style={{ color: 'var(--yellow)' }} /><div><strong>{s.risk_distribution.high}</strong><small>High risk</small></div></div>
        <div className="kpi"><TrendingUp size={18} style={{ color: 'var(--blue)' }} /><div><strong>{s.total_anomalies}</strong><small>Anomalies detected</small></div></div>
      </div>
      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <User size={24} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 24, fontWeight: 700 }}>{s.by_type.user ?? 0}</div>
          <small>Users</small>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <Monitor size={24} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 24, fontWeight: 700 }}>{s.by_type.host ?? 0}</div>
          <small>Hosts</small>
        </div>
        <div className="card" style={{ padding: 16, textAlign: 'center' }}>
          <Activity size={24} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 24, fontWeight: 700 }}>{s.by_type.ip ?? 0}</div>
          <small>IP Addresses</small>
        </div>
      </div>
      {can('ueba.write') && (
        <div style={{ marginBottom: 16 }}>
          <button className="btn primary" onClick={() => compute.mutate(undefined)} disabled={compute.isPending}>
            {compute.isPending ? 'Computing…' : 'Recompute Baselines'}
          </button>
          {compute.error && <ErrorBox error={compute.error} />}
        </div>
      )}
      <h3 style={{ marginBottom: 12 }}>Top Risk Entities</h3>
      {s.top_risk.length === 0 ? <Empty>No entities profiled yet. Run baseline computation to get started.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Entity</th><th>Type</th><th>Risk Score</th><th>Alerts</th><th>Anomalies</th><th>Last Seen</th><th /></tr></thead>
          <tbody>{s.top_risk.map((p) => {
            const Icon = ENTITY_ICONS[p.entity_type] || Shield;
            const risk = riskLabel(p.risk_score);
            return (
              <tr key={p.id}>
                <td className="mono">{p.entity_value}</td>
                <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Icon size={14} />{p.entity_type}</span></td>
                <td><span className="badge" style={{ background: RISK_COLORS[risk], color: '#fff' }}>{p.risk_score.toFixed(0)}</span></td>
                <td>{p.alert_count}</td>
                <td>{p.anomalies?.length ?? 0}</td>
                <td>{ago(p.last_seen)}</td>
                <td><button className="btn small" onClick={() => setDetail(p)}>Details</button></td>
              </tr>
            );
          })}</tbody></table></div>
      )}
      {detail && <EntityDrawer profile={detail} onClose={() => setDetail(null)} />}
    </>
  );
}

function EntitiesPanel() {
  const [entityType, setEntityType] = useState('');
  const [minRisk, setMinRisk] = useState(0);
  const profiles = useQuery({ queryKey: ['ueba-profiles', entityType, minRisk], queryFn: () => get<Profile[]>('/api/ueba/profiles', { entity_type: entityType || undefined, min_risk: minRisk, limit: 200 }) });
  const [detail, setDetail] = useState<Profile | null>(null);

  return (
    <>
      <div className="filters" style={{ marginBottom: 12 }}>
        <select aria-label="Entity type" value={entityType} onChange={(e) => setEntityType(e.target.value)}>
          <option value="">All types</option>
          <option value="user">Users</option>
          <option value="host">Hosts</option>
          <option value="ip">IP Addresses</option>
        </select>
        <label className="row" style={{ gap: 6, alignItems: 'center' }}>
          Min risk: <input type="range" min={0} max={100} value={minRisk} onChange={(e) => setMinRisk(Number(e.target.value))} style={{ width: 120 }} /> <span>{minRisk}</span>
        </label>
      </div>
      {profiles.isLoading ? <Loading /> : profiles.error ? <ErrorBox error={profiles.error} /> : profiles.data!.length === 0 ? <Empty>No entities match the filter criteria.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Entity</th><th>Type</th><th>Risk</th><th>Alerts</th><th>Rules</th><th>Active Days</th><th>Anomalies</th><th>Last Seen</th><th /></tr></thead>
          <tbody>{profiles.data!.map((p) => {
            const Icon = ENTITY_ICONS[p.entity_type] || Shield;
            const risk = riskLabel(p.risk_score);
            return (
              <tr key={p.id}>
                <td className="mono">{p.entity_value}</td>
                <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Icon size={14} />{p.entity_type}</span></td>
                <td><span className="badge" style={{ background: RISK_COLORS[risk], color: '#fff' }}>{p.risk_score.toFixed(0)}</span></td>
                <td>{p.alert_count}</td>
                <td>{p.baseline?.unique_rules ?? '—'}</td>
                <td>{p.baseline?.active_days ?? '—'}</td>
                <td>{p.anomalies?.length ?? 0}</td>
                <td>{ago(p.last_seen)}</td>
                <td><button className="btn small" onClick={() => setDetail(p)}>Details</button></td>
              </tr>
            );
          })}</tbody></table></div>
      )}
      {detail && <EntityDrawer profile={detail} onClose={() => setDetail(null)} />}
    </>
  );
}

function EntityDrawer({ profile: p, onClose }: { profile: Profile; onClose: () => void }) {
  const risk = riskLabel(p.risk_score);
  const Icon = ENTITY_ICONS[p.entity_type] || Shield;
  const timeline = useQuery({ queryKey: ['ueba-entity', p.entity_type, p.entity_value], queryFn: () => get<any>(`/api/ueba/entity/${p.entity_type}/${encodeURIComponent(p.entity_value)}`) });

  return (
    <Drawer title={<><Icon size={18} style={{ verticalAlign: -3 }} /> {p.entity_value}</>} onClose={onClose}>
      <div className="row" style={{ gap: 8, marginBottom: 16 }}>
        <span className="badge" style={{ background: RISK_COLORS[risk], color: '#fff', fontSize: 16, padding: '4px 12px' }}>Risk: {p.risk_score.toFixed(0)}</span>
        <span className="badge">{p.entity_type}</span>
        <span style={{ color: 'var(--muted)' }}>{p.alert_count} alerts</span>
      </div>
      <dl className="kv">
        <dt>First seen</dt><dd>{ago(p.first_seen)}</dd>
        <dt>Last seen</dt><dd>{ago(p.last_seen)}</dd>
        <dt>Updated</dt><dd>{ago(p.updated_at)}</dd>
        <dt>Alerts/day</dt><dd>{p.baseline?.alerts_per_day?.toFixed(1) ?? '—'}</dd>
        <dt>Active days</dt><dd>{p.baseline?.active_days ?? '—'}</dd>
        <dt>Unique rules</dt><dd>{p.baseline?.unique_rules ?? '—'}</dd>
      </dl>

      {p.baseline?.severity_distribution && (
        <>
          <h4 style={{ marginTop: 16, marginBottom: 8 }}>Severity Distribution</h4>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {Object.entries(p.baseline.severity_distribution as Record<string, number>).map(([sev, count]) => (
              <div key={sev} style={{ textAlign: 'center' }}><Sev v={sev} /><div>{count}</div></div>
            ))}
          </div>
        </>
      )}

      {p.baseline?.peak_hours && (
        <>
          <h4 style={{ marginTop: 16, marginBottom: 8 }}>Peak Activity Hours</h4>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(p.baseline.peak_hours as number[]).map((h) => <span key={h} className="badge">{String(h).padStart(2, '0')}:00</span>)}
          </div>
        </>
      )}

      {p.baseline?.top_rules && Object.keys(p.baseline.top_rules).length > 0 && (
        <>
          <h4 style={{ marginTop: 16, marginBottom: 8 }}>Top Detection Rules</h4>
          <div className="table-wrap"><table><thead><tr><th>Rule</th><th>Count</th></tr></thead>
            <tbody>{Object.entries(p.baseline.top_rules as Record<string, number>).slice(0, 8).map(([rule, count]) => (
              <tr key={rule}><td className="mono" style={{ fontSize: 12 }}>{rule}</td><td>{count}</td></tr>
            ))}</tbody></table></div>
        </>
      )}

      {p.baseline?.top_techniques && Object.keys(p.baseline.top_techniques).length > 0 && (
        <>
          <h4 style={{ marginTop: 16, marginBottom: 8 }}>MITRE Techniques</h4>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(p.baseline.top_techniques as Record<string, number>).map(([t, c]) => (
              <span key={t} className="badge">{t} ({c})</span>
            ))}
          </div>
        </>
      )}

      <h4 style={{ marginTop: 16, marginBottom: 8 }}>Anomalies ({p.anomalies?.length ?? 0})</h4>
      {!p.anomalies?.length ? <Empty>No anomalies detected.</Empty> : p.anomalies.map((a, i) => (
        <div key={i} style={{ marginBottom: 8, padding: '8px 12px', border: '1px solid var(--border)', borderRadius: 6, borderLeft: `3px solid ${a.score >= 50 ? 'var(--red)' : 'var(--yellow)'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>{a.type.replace(/_/g, ' ')}</strong>
            <span className="badge" style={{ background: a.score >= 50 ? 'var(--red)' : 'var(--yellow)', color: '#fff' }}>{a.score}</span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}>{a.description}</div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>{ago(a.detected_at)}</div>
        </div>
      ))}

      <h4 style={{ marginTop: 16, marginBottom: 8 }}>Recent Alert Timeline</h4>
      {timeline.isLoading ? <Loading /> : timeline.error ? <ErrorBox error={timeline.error} /> : (
        timeline.data?.timeline?.length === 0 ? <Empty>No recent alerts.</Empty> : (
          <div className="table-wrap" style={{ maxHeight: '40vh', overflow: 'auto' }}><table><thead><tr><th>Time</th><th>Title</th><th>Severity</th><th>Rule</th></tr></thead>
            <tbody>{timeline.data?.timeline?.slice(0, 50).map((a: any) => (
              <tr key={a.id}><td style={{ whiteSpace: 'nowrap' }}>{ago(a.time)}</td><td className="wrap">{a.title}</td><td><Sev v={a.severity} /></td><td className="mono" style={{ fontSize: 12 }}>{a.rule_id}</td></tr>
            ))}</tbody></table></div>
        )
      )}
    </Drawer>
  );
}
