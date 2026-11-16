import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowRight, Bell, Clock, ExternalLink, Globe, Layers, Plug, Plus, RefreshCw, Shield, Wrench, X } from 'lucide-react';
import { lazy, Suspense, useEffect, useState } from 'react';
import { Link, useOutletContext } from 'react-router-dom';
import { ThreatCategories } from '../components/ThreatCategories';
import { AnimatedNumber } from '../components/AnimatedNumber';
import { Button } from '../components/Button';
import { ErrorBox, Field, Loading, Modal, PageHead, Sev, Status } from '../components/ui';
import { del, get, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, firstName, until } from '../lib/format';
import { useAct } from '../lib/mut';
import type { Point } from '../Trend';
import type { MapData } from './ThreatMap';

const OverviewMap = lazy(() => import('./ThreatMap').then(({ WorldMap }) => ({ default: WorldMap })));
const Trend = lazy(() => import('../Trend'));
const number = new Intl.NumberFormat();

type DashboardData = {
  metrics: {
    alerts_by_status: Record<string, number>;
    open_cases: number;
    mtta_minutes: number | null;
    sla_breached: number;
    agent_coverage_pct: number;
    agents_active: number;
    assets_total: number;
  };
  sources: { id: string; name: string; type: string; last_success_at: string | null; error_count: number; lag_seconds: number }[];
  categories?: { name: string; count: number }[];
  top_alerts: { id: string; title: string; host?: string; rule_id?: string; source: string; severity: string; ack_due?: string; status: string }[];
  series: Point[];
};

export default function Dashboard() {
  const { me, can } = useAuth();
  const { dark, live } = useOutletContext<{ dark: boolean; live: boolean }>();
  const [days, setDays] = useState(1);
  const allowed = can('alerts.read');
  const query = useQuery({
    queryKey: ['dashboard', days],
    queryFn: () => get<DashboardData>('/api/dashboard', { days }),
    enabled: allowed,
    refetchInterval: 15_000,
  });
  const map = useQuery({
    queryKey: ['threat-map', days], queryFn: () => get<MapData>('/api/threat-map', { days }),
    enabled: allowed, refetchInterval: 30_000,
  });
  const recent = useQuery({
    queryKey: ['overview-recent-alerts'],
    queryFn: () => get<Page<RecentAlert>>('/api/alerts', { limit: 5 }),
    enabled: allowed, refetchInterval: 15_000,
  });
  const cases = useQuery({
    queryKey: ['overview-active-cases'],
    queryFn: () => get<Page<ActiveCase>>('/api/cases', { status: ['open', 'in_progress'], limit: 5 }),
    enabled: can('cases.read'), refetchInterval: 15_000,
  });
  const data = query.data;

  return (
    <div className="ops-overview">
      <div className="overview-heading">
        <PageHead eyebrow="OPERATIONS" title="Security overview" sub={`${me?.name ? `Welcome back, ${firstName(me.name)}. ` : ''}Detections, investigations, and response at a glance.`} />
        <div className="overview-status">
          <span className={`overview-stream ${live ? 'online' : 'offline'}`}><Activity size={15} aria-hidden="true" />{live ? 'Stream connected' : 'Stream disconnected'}</span>
          <DualClock live={live} />
        </div>
      </div>
      <div className="soc-period">
        {allowed && <>
          <div className="period-switch" role="group" aria-label="Reporting period">
            {[[1, '24 hours'], [7, '7 days'], [30, '30 days']].map(([value, label]) => <button key={value} type="button" aria-pressed={days === value} onClick={() => setDays(Number(value))}>{label}</button>)}
          </div>
          <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}><RefreshCw className={query.isFetching ? 'console-refreshing' : undefined} size={16} />{query.isFetching ? 'Updating…' : 'Refresh'}</Button>
        </>}
      </div>
      {!allowed && <p className="notice">Use the navigation to open the areas assigned to your role.</p>}
      {allowed && query.isPending && <Loading />}
      {query.error && <ErrorBox error={query.error} />}
      {data && <OverviewData data={data} dark={dark} map={map} recent={recent} cases={cases} />}
    </div>
  );
}

const lktTime = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'Asia/Colombo' });
const lktDate = new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'Asia/Colombo' });
const utcDate = new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' });

function DualClock({ live = true }: { live?: boolean }) {
  const [now, setNow] = useState(() => new Date());
  const [primary, setPrimary] = useState<'lkt' | 'utc'>(() => {
    try { return localStorage.getItem('200m-clock') === 'utc' ? 'utc' : 'lkt'; } catch { return 'lkt'; }
  });
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const toggle = () => {
    const next = primary === 'lkt' ? 'utc' : 'lkt';
    setPrimary(next);
    try { localStorage.setItem('200m-clock', next); } catch { /* */ }
  };
  const utc = now.toISOString().slice(11, 19);
  const lkt = lktTime.format(now);
  const pTime = primary === 'lkt' ? lkt : utc;
  const pLabel = primary === 'lkt' ? 'Local' : 'UTC';
  const pDate = primary === 'lkt' ? lktDate.format(now) : utcDate.format(now);
  const sTime = primary === 'lkt' ? utc : lkt;
  const sLabel = primary === 'lkt' ? 'UTC' : 'Local';

  return (
    <button type="button" className={`soc-clock ${live ? 'online' : 'offline'}`} onClick={toggle} title="Click to swap primary timezone">
      <Globe size={19} aria-hidden="true" />
      <span className="soc-clock-primary">
        <strong>{pTime}</strong>
        <small>{pLabel} · {pDate}</small>
      </span>
      <span className="soc-clock-sep" />
      <span className="soc-clock-secondary">
        <strong>{sTime}</strong>
        <small>{sLabel}</small>
      </span>
      <span className={`soc-clock-pulse ${live ? 'online' : 'offline'}`} />
    </button>
  );
}

type OverviewQuery<T> = { data?: T; error: Error | null; isPending: boolean };
type RecentAlert = { id: string; title: string; host?: string; src_ip?: string; time: string; severity: string };
type ActiveCase = { id: string; number: string; title: string; severity: string; status: string; updated_at: string };

function OverviewData({ data, dark, map, recent, cases }: {
  data: DashboardData; dark: boolean;
  map: OverviewQuery<MapData>; recent: OverviewQuery<Page<RecentAlert>>; cases: OverviewQuery<Page<ActiveCase>>;
}) {
  const { can } = useAuth();
  const m = data.metrics;
  const open = ['new', 'acknowledged', 'investigating'].reduce((count, status) => count + (m.alerts_by_status[status] ?? 0), 0);
  const cards = [
    { tone: 'red', label: 'Active alerts', value: <AnimatedNumber value={open} />, note: 'In the selected reporting window', icon: Bell, to: '/app/alerts', cap: 'alerts.read' },
    { tone: 'amber', label: 'Open incidents', value: <AnimatedNumber value={m.open_cases} />, note: 'Across your assigned scope', icon: Layers, to: '/app/cases', cap: 'cases.read' },
    { tone: 'blue', label: 'Mean time to acknowledge', value: <AnimatedNumber value={m.mtta_minutes} suffix=" min" />, note: `${number.format(m.sla_breached)} SLA breaches in this period`, icon: Clock },
    { tone: 'teal', label: 'Endpoint coverage', value: <AnimatedNumber value={m.assets_total ? m.agent_coverage_pct : null} suffix="%" />, note: `${m.agents_active} of ${m.assets_total} agents active`, icon: Shield, to: '/app/assets', cap: 'assets.read' },
  ];
  const categories = data.categories ?? [];
  const connectors = [...data.sources].sort((a, b) => Number(b.error_count > 0) - Number(a.error_count > 0)
    || Number(!b.last_success_at) - Number(!a.last_success_at) || a.name.localeCompare(b.name));

  return (
    <>
      <div className="metrics ops-metrics">
        {cards.filter(({ cap }) => cap !== 'cases.read' || can(cap)).map(({label, value, note, icon: Icon, to, cap, tone}, index) => {
          const body = <><span className="ops-kpi-index" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span><span className="ops-kpi-label"><Icon size={17} aria-hidden="true" />{label}</span><strong>{value}</strong><small>{note}</small></>;
          return to && cap && can(cap)
            ? <Link className="metric ops-kpi" data-tone={tone} key={label} to={to}>{body}</Link>
            : <article className="metric ops-kpi" data-tone={tone} key={label}>{body}</article>;
        })}
      </div>
      <div className="soc-overview-grid">
        <section className="panel ops-trend">
          <div className="panel-title"><div><h2><Activity size={18} /> Security overview</h2><p>Alert volume by severity · UTC / Local</p></div></div>
          <Suspense fallback={<div className="chart empty">Loading chart…</div>}><Trend dark={dark} series={data.series} /></Suspense>
        </section>
        <section className="panel soc-landscape">
          <div className="panel-title"><div><h2><Globe size={18} /> Threat landscape</h2><p>Alert origins in the selected period</p></div><Link to="/app/threat-map">Open map <ArrowRight size={14} /></Link></div>
          <div className="soc-landscape-body">
            <div>
              {map.error ? <ErrorBox error={map.error} /> : map.data ? (
                <Suspense fallback={<Loading />}><OverviewMap data={map.data} dark={dark} compact /></Suspense>
              ) : <Loading />}
              {map.data && <p className="soc-map-note">{map.data.unique_countries ? `${map.data.unique_countries} countries with located alerts` : 'No geolocated alert origins'}</p>}
            </div>
          </div>
        </section>
      </div>
      <div className="soc-detail-grid">
        <section className="panel soc-recent">
          <div className="panel-title"><h2><Bell size={18} /> Recent alerts</h2><Link to="/app/alerts">View all <ArrowRight size={14} /></Link></div>
          {recent.error ? <ErrorBox error={recent.error} /> : recent.isPending ? <Loading /> : recent.data?.items.length ? (
            <ul className="soc-alert-list">{recent.data.items.map((alert) => (
              <li key={alert.id}><Link to={`/app/alerts?open=${encodeURIComponent(alert.id)}`}>
                <span><strong>{alert.title}</strong><small>{alert.host || alert.src_ip || 'Unknown source'} · {ago(alert.time)}</small></span>
                <Sev v={alert.severity} />
              </Link></li>
            ))}</ul>
          ) : <p className="empty">No alerts recorded.</p>}
        </section>
        {can('cases.read') && <section className="panel soc-active">
          <div className="panel-title"><h2><Shield size={18} /> Active incidents</h2><Link to="/app/cases">View cases <ArrowRight size={14} /></Link></div>
          {cases.error ? <ErrorBox error={cases.error} /> : cases.isPending ? <Loading /> : cases.data?.items.length ? (
            <div className="table-scroll"><table><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Updated</th></tr></thead>
              <tbody>{cases.data.items.map((item) => <tr key={item.id}>
                <td><Link className="record-link" to={`/app/cases?open=${encodeURIComponent(item.id)}`}>{item.title}<small>{item.number}</small></Link></td>
                <td><Sev v={item.severity} /></td><td><Status v={item.status} /></td><td>{ago(item.updated_at)}</td>
              </tr>)}</tbody></table></div>
          ) : <p className="empty">No active cases.</p>}
        </section>}
        <DashboardLinks />
      </div>
      <div className="soc-support-grid">
        <section className="panel soc-priority">
          <div className="panel-title"><h2><Bell size={18} /> Priority alerts</h2><Link to="/app/alerts">Open queue <ArrowRight size={14} /></Link></div>
          {data.top_alerts.length ? <ul className="soc-alert-list">{data.top_alerts.slice(0, 5).map((alert) => (
            <li key={alert.id}><Link to={`/app/alerts?open=${encodeURIComponent(alert.id)}`}>
              <span><strong>{alert.title}</strong><small>{alert.status === 'new' && alert.ack_due ? `Ack due ${until(alert.ack_due)}` : alert.host || alert.rule_id || alert.source}</small></span>
              <Sev v={alert.severity} />
            </Link></li>
          ))}</ul> : <p className="empty">No open critical or high alerts.</p>}
        </section>
        <ThreatCategories categories={categories} />
        {can('integrations.read') && <section className="panel ops-connectors">
          <div className="panel-title"><div><h2>Connector health</h2><p>Recent sync activity</p></div><Plug size={19} aria-hidden="true" /></div>
          <div className="ops-worklist-items">
            {connectors.slice(0, 5).map((connector) => (
              <div className="ops-connector" key={connector.id}>
                <div><strong>{connector.name}</strong><small>{connector.last_success_at ? `Last success ${ago(connector.last_success_at)}` : 'No successful sync recorded'}</small></div>
                <Status v={connector.error_count ? 'error' : connector.last_success_at ? 'ok' : 'unknown'} />
              </div>
            ))}
            {!connectors.length && <p className="empty">No enabled integrations.</p>}
          </div>
          <Link className="button ghost ops-connector-link" to="/app/integrations">Manage integrations <ArrowRight size={15} /></Link>
        </section>}
      </div>
    </>
  );
}

type DashboardLink = { id: string; name: string; url: string };

/** Pulls the linked site's own favicon straight from its domain, so any newly added tool gets a logo
 * automatically with no manual mapping — falls back to a generic icon if the site has none. */
function ToolIcon({ url }: { url: string }) {
  const [broken, setBroken] = useState(false);
  let origin = '';
  try { origin = new URL(url).origin; } catch { /* malformed URL: fall back below */ }
  if (broken || !origin) return <ExternalLink size={22} aria-hidden="true" />;
  return <img className="soc-tool-icon" src={`${origin}/favicon.ico`} alt="" width={22} height={22} onError={() => setBroken(true)} />;
}

function DashboardLinks() {
  const { can } = useAuth();
  const canEdit = can('admin.settings');
  const links = useQuery({ queryKey: ['dashboard-links'], queryFn: () => get<DashboardLink[]>('/api/dashboard-links') });
  const [adding, setAdding] = useState(false);
  const remove = useAct((id: string) => del(`/api/dashboard-links/${id}`), ['dashboard-links']);
  const list = links.data ?? [];

  if (!canEdit && list.length === 0) return null;

  return (
    <section className="panel soc-tools">
      <div className="panel-title">
        <h2><Wrench size={18} /> Linked dashboards</h2>
        {canEdit && <button type="button" className="btn small" onClick={() => setAdding(true)}><Plus size={14} /> Add link</button>}
      </div>
      {links.error && <ErrorBox error={links.error} />}
      {list.length === 0 ? (
        <p className="empty">Add links to your Wazuh, Grafana, Uptime Kuma or other dashboards.</p>
      ) : (
        <div className="soc-tool-grid">{list.map((link) => (
          <a href={link.url} key={link.id} target="_blank" rel="noreferrer" className={canEdit ? 'soc-tool-editable' : undefined}>
            {canEdit && <button type="button" className="soc-tool-remove" aria-label={`Remove ${link.name}`} onClick={(e) => { e.preventDefault(); if (confirm(`Remove “${link.name}”?`)) remove.mutate(link.id); }}><X size={13} /></button>}
            <ToolIcon url={link.url} />
            {link.name}
          </a>
        ))}</div>
      )}
      {adding && <AddDashboardLink onClose={() => setAdding(false)} />}
    </section>
  );
}

function AddDashboardLink({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const add = useAct(() => post('/api/dashboard-links', { name: name.trim(), url: url.trim() }), ['dashboard-links'], 'Link added', onClose);
  const urlValid = /^https?:\/\/.+/i.test(url.trim());
  return (
    <Modal title="Add dashboard link" onClose={onClose}>
      <Field label="Name" id="dl-name"><input id="dl-name" value={name} placeholder="Wazuh dashboard" onChange={(e) => setName(e.target.value)} /></Field>
      <Field label="URL" id="dl-url" hint="Must start with http:// or https://"><input id="dl-url" value={url} placeholder="https://wazuh.corp.local" onChange={(e) => setUrl(e.target.value)} /></Field>
      {add.error && <ErrorBox error={add.error} />}
      <button className="btn primary" disabled={add.isPending || name.trim().length < 1 || !urlValid} onClick={() => add.mutate(undefined)}>Add link</button>
    </Modal>
  );
}
