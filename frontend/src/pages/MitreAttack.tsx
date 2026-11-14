import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, Crosshair } from 'lucide-react';
import { useRef, useState, type MouseEvent } from 'react';
import { Link } from 'react-router-dom';
import { Drawer, ErrorBox, Loading, PageHead, Pager, SearchBox, Sev, Status } from '../components/ui';
import { get, type Page } from '../lib/api';
import { ago, SEVERITIES, titleCase } from '../lib/format';

type Technique = { id: string; name: string; count: number; max_severity: string; rule_count: number };
type MatrixData = {
  tactics: string[];
  matrix: Record<string, Technique[]>;
  total_techniques: number;
  covered: number;
  coverage_pct: number;
  total_alerts_mapped: number;
  rules_covered: number;
  rules_coverage_pct: number;
  total_rules_mapped: number;
  days: number;
};
type AlertItem = { id: string; title: string; severity: string; status: string; time: string | null; src_ip: string; host: string };
type TechniqueDetail = { id: string; name: string; tactics: string[]; desc: string };
type TechniqueRow = Technique & { tactics: string[] };

const number = new Intl.NumberFormat();

function TechniqueDrawer({ technique, days, onClose }: { technique: TechniqueRow; days: number; onClose: () => void }) {
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ['mitre-technique-alerts', technique.id, days, page],
    queryFn: () => get<Page<AlertItem> & { technique?: TechniqueDetail }>(
      `/api/mitre/technique/${encodeURIComponent(technique.id)}/alerts`, { days, page },
    ),
  });
  const result = q.data;

  return (
    <Drawer title={technique.name} onClose={onClose}>
      <div className="attack-detail-meta">
        <code>{technique.id}</code>
        <span>{technique.tactics.join(' · ')}</span>
        <a href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`} target="_blank" rel="noreferrer">
          MITRE reference <ArrowUpRight size={14} aria-hidden="true" />
        </a>
      </div>
      {result?.technique?.desc && <p className="attack-description">{result.technique.desc}</p>}
      <div className="attack-detail-meta">
        <Link to={`/app/sigma?technique=${encodeURIComponent(technique.id)}`}>
          {technique.rule_count > 0 ? `${number.format(technique.rule_count)} detection ${technique.rule_count === 1 ? 'rule' : 'rules'}` : 'No detection rules yet'}
          <ArrowUpRight size={14} aria-hidden="true" />
        </Link>
      </div>
      <h3>Mapped alerts</h3>
      <p className="attack-caption">Last {days} days{result && ` · ${number.format(result.total)} alerts`}</p>
      {q.isPending && <Loading />}
      {q.error && <ErrorBox error={q.error} />}
      {result?.items.length === 0 && <div className="empty">No mapped alerts in this time range.</div>}
      {result && result.items.length > 0 && (
        <>
          <ul className="attack-alerts">
            {result.items.map((alert) => (
              <li key={alert.id}>
                <Link to={`/app/alerts?open=${encodeURIComponent(alert.id)}`}>
                  <strong>{alert.title}</strong>
                  <ArrowUpRight size={16} aria-hidden="true" />
                  <span>{alert.host || alert.src_ip || 'Unknown source'}{alert.time && ` · ${ago(alert.time)}`}</span>
                  <div><Sev v={alert.severity} /> <Status v={alert.status} /></div>
                </Link>
              </li>
            ))}
          </ul>
          <Pager page={page} limit={result.limit} total={result.total} set={setPage} />
        </>
      )}
    </Drawer>
  );
}

const HEAT_COLOR: Record<string, string> = { critical: 'var(--bad)', high: 'var(--bad)', medium: 'var(--warn)', low: 'var(--ok)', info: 'var(--muted)' };

function heatOpacity(count: number, max: number): number {
  return count === 0 ? 0 : 0.25 + Math.min(1, count / max) * 0.75;
}

export default function MitreAttack() {
  const [days, setDays] = useState(90);
  const [tactic, setTactic] = useState('');
  const [search, setSearch] = useState('');
  const [activity, setActivity] = useState('all');
  const [severity, setSeverity] = useState('');
  const [sort, setSort] = useState('volume');
  const [view, setView] = useState<'list' | 'heatmap'>('heatmap');
  const [selected, setSelected] = useState<TechniqueRow | null>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const q = useQuery({
    queryKey: ['mitre-matrix', days],
    queryFn: () => get<MatrixData>('/api/mitre/matrix', { days }),
    refetchInterval: 15000,
  });
  const data = q.data;

  const catalog = new Map<string, TechniqueRow>();
  for (const name of data?.tactics ?? []) {
    for (const technique of data?.matrix[name] ?? []) {
      const row = catalog.get(technique.id);
      if (row) row.tactics.push(name);
      else catalog.set(technique.id, { ...technique, tactics: [name] });
    }
  }

  const term = search.trim().toLowerCase();
  const rows = [...catalog.values()].filter((row) =>
    (!tactic || row.tactics.includes(tactic)) &&
    (!term || `${row.id} ${row.name}`.toLowerCase().includes(term)) &&
    (activity !== 'observed' || row.count > 0) &&
    (activity !== 'unobserved' || row.count === 0) &&
    (!severity || (row.count > 0 && row.max_severity === severity)),
  ).sort((a, b) => (sort === 'volume' ? b.count - a.count : 0) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const maxCount = Math.max(1, ...rows.map((r) => r.count));

  function clearFilters() {
    setTactic('');
    setSearch('');
    setActivity('all');
    setSeverity('');
  }

  function openTechnique(event: MouseEvent<HTMLButtonElement>, row: TechniqueRow) {
    trigger.current = event.currentTarget;
    setSelected(row);
  }

  return (
    <>
      <PageHead title="MITRE ATT&CK mapping" sub="Explore observed techniques and investigate the alerts behind them." eyebrow="THREAT INTELLIGENCE">
        <select aria-label="Time range" value={days} onChange={(e) => setDays(Number(e.target.value))} className="select">
          {[7, 30, 90, 180, 365].map((n) => <option key={n} value={n}>Last {n} days</option>)}
        </select>
      </PageHead>
      {q.error && <ErrorBox error={q.error} />}
      {q.isPending && <Loading />}
      {data && (
        <div className="attack-workspace">
          <dl className="attack-summary panel">
            <div><dt>Techniques observed</dt><dd>{number.format(data.covered)} <small>of {number.format(data.total_techniques)}</small></dd></div>
            <div><dt>Catalog observed</dt><dd>{number.format(data.coverage_pct)}%</dd></div>
            <div><dt>Alert-to-technique mappings</dt><dd>{number.format(data.total_alerts_mapped)}</dd></div>
            <div><dt>Detection rule coverage</dt><dd>{number.format(data.rules_covered)} <small>of {number.format(data.total_techniques)} · <Link to="/app/sigma">manage rules</Link></small></dd></div>
          </dl>
          <div className="attack-browser">
            <section className="panel attack-tactics" aria-labelledby="attack-tactics-title">
              <h2 id="attack-tactics-title"><Crosshair size={18} aria-hidden="true" /> Tactics</h2>
              <p>Observed / catalog</p>
              {[['', 'All tactics', data.covered, data.total_techniques] as const, ...data.tactics.map((name) => {
                const entries = data.matrix[name] ?? [];
                return [name, name, entries.filter((entry) => entry.count > 0).length, entries.length] as const;
              })].map(([id, label, observed, total]) => (
                <button type="button" key={id} aria-pressed={tactic === id} onClick={() => setTactic(id)}>
                  <span>{label}</span><small>{observed} / {total}</small>
                </button>
              ))}
            </section>
            <section className="panel attack-results" aria-labelledby="attack-results-title">
              <header>
                <h2 id="attack-results-title">{tactic || 'Technique explorer'}</h2>
                <p className="attack-caption" role="status">{number.format(rows.length)} {rows.length === 1 ? 'technique' : 'techniques'} · Last {days} days</p>
                <div className="row" style={{ gap: 4 }}>
                  <button type="button" className={'btn small' + (view === 'heatmap' ? ' primary' : '')} onClick={() => setView('heatmap')}>Heatmap</button>
                  <button type="button" className={'btn small' + (view === 'list' ? ' primary' : '')} onClick={() => setView('list')}>List</button>
                </div>
              </header>
              <div className="attack-filters">
                <SearchBox value={search} onChange={setSearch} placeholder="Name or ID, e.g. T1059" label="Search techniques" />
                <label>Activity
                  <select className="select" value={activity} onChange={(e) => {
                    setActivity(e.target.value);
                    if (e.target.value === 'unobserved') setSeverity('');
                  }}>
                    <option value="all">All techniques</option><option value="observed">Observed</option><option value="unobserved">Unobserved</option>
                  </select>
                </label>
                <label>Highest severity
                  <select className="select" value={severity} disabled={activity === 'unobserved'} onChange={(e) => setSeverity(e.target.value)}>
                    <option value="">Any severity</option>
                    {SEVERITIES.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                  </select>
                </label>
                <label>Sort by
                  <select className="select" value={sort} onChange={(e) => setSort(e.target.value)}>
                    <option value="volume">Most alerts</option><option value="name">Name A–Z</option>
                  </select>
                </label>
              </div>
              {(tactic || search || activity !== 'all' || severity) && <button className="btn small attack-clear" onClick={clearFilters}>Clear filters</button>}
              {rows.length === 0 ? <div className="empty">No techniques match these filters.</div> : view === 'heatmap' ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(34px, 1fr))', gap: 4, marginTop: 8 }}>
                  {rows.map((row) => (
                    <button
                      key={row.id} type="button" title={`${row.id} ${row.name} — ${row.count} alert(s)${row.rule_count ? `, ${row.rule_count} rule(s)` : ''}`}
                      aria-haspopup="dialog" onClick={(e) => openTechnique(e, row)}
                      style={{
                        aspectRatio: '1', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer',
                        background: row.count > 0 ? HEAT_COLOR[row.max_severity] : 'transparent',
                        opacity: row.count > 0 ? heatOpacity(row.count, maxCount) : 1,
                      }}
                    />
                  ))}
                </div>
              ) : (
                <ul className="attack-techniques">
                  {rows.map((row) => (
                    <li key={row.id}>
                      <button type="button" aria-haspopup="dialog" onClick={(e) => openTechnique(e, row)}>
                        <span className="attack-technique-label"><code>{row.id}</code><strong>{row.name}</strong></span>
                        <span className="attack-technique-activity">
                          {row.count > 0 ? <><Sev v={row.max_severity} /><span>{number.format(row.count)} {row.count === 1 ? 'alert' : 'alerts'}</span></> : <span>Unobserved</span>}
                          {row.rule_count > 0 && <span className="badge">{row.rule_count} {row.rule_count === 1 ? 'rule' : 'rules'}</span>}
                          <ArrowUpRight size={16} aria-hidden="true" />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </div>
      )}
      {selected && <TechniqueDrawer technique={selected} days={days} onClose={() => {
        setSelected(null);
        requestAnimationFrame(() => trigger.current?.focus());
      }} />}
    </>
  );
}
