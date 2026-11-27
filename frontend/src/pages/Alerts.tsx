import { LiveTimer, Skeleton } from '../components/Interactive';
import { SavedViews } from '../components/SavedViews';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useOutletContext, useSearchParams } from 'react-router-dom';
import { Chips } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, PageHead, Pager, Modal, SearchBox, Sev, Status, useToast } from '../components/ui';
import { get, patch, post, type Page } from '../lib/api';
import { useAct } from '../lib/mut';
import { useAuth } from '../lib/auth';
import { SEVERITIES, ago, when } from '../lib/format';
import { RequestActionModal } from './Response';
import { REFRESH_MS } from '../lib/refresh';
import type { Point } from '../Trend';

const Trend = lazy(() => import('../Trend'));

type Alert = any;

export default function Alerts({ workspace = 'alerts' }: { workspace?: 'alerts' | 'siem' | 'hunting' }) {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [deleting, setDeleting] = useState<string[] | null>(null);
  const [deletingAll, setDeletingAll] = useState(false);
  const [overviewOpen, setOverviewOpen] = useState(false);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const DEFAULT_SEVERITIES = ['medium', 'high', 'critical'];
  const explicitSev = sp.getAll('severity');
  const f = { severity: explicitSev.length > 0 ? explicitSev : (sp.has('show_all') ? [] : DEFAULT_SEVERITIES), status: sp.get('status') ?? '', q: sp.get('q') ?? '', category: sp.get('category') ?? '',
    source: sp.get('source') ?? '', host: sp.get('host') ?? '', username: sp.get('username') ?? '', client_id: sp.get('client_id') ?? '',
    unassigned_client: sp.get('unassigned_client') === 'true' ? true : undefined,
    since: sp.get('since') ?? '', until: sp.get('until') ?? '',
  };
  const setF = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); setPage(1); };
  const q = useQuery({ queryKey: ['alerts', f, page], queryFn: () => get<Page<Alert>>('/api/alerts', { ...f, status: f.status ? [f.status] : [], page, limit: 50 }) });
  const total = q.data?.total;
  useEffect(() => { if (total !== undefined) setPage((current) => Math.min(current, Math.max(1, Math.ceil(total / 50)))); }, [total]);
  const scoped = Boolean(f.source || f.host || f.username || f.since || f.until || f.client_id || f.unassigned_client);
  const sources = useQuery({ queryKey: ['alert-sources'], queryFn: () => get<string[]>('/api/alerts/sources'), enabled: workspace !== 'alerts' });
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const bulk = useMutation({
    mutationFn: (status: string) => post('/api/alerts/bulk', { ids: [...sel], status }),
    onSuccess: (r: any) => { toast(`${r.updated} alert(s) updated`); setSel(new Set()); void qc.invalidateQueries({ queryKey: ['alerts'] }); },
    onError: (e: Error) => toast(e.message, true),
  });
  const severityKey = f.severity.join(',');
  useEffect(() => { setPage(1); setSel(new Set()); setCur(-1); }, [f.q, f.status, f.category, severityKey, f.source, f.host, f.username, f.since, f.until, f.client_id, f.unassigned_client]);
  const open = sp.get('open');
  const [cur, setCur] = useState(-1);
  const items = q.data?.items ?? [];
  const changePage = (next: number) => { setPage(next); setSel(new Set()); setCur(-1); };
  const openAlert = (id: string | null) => { const n = new URLSearchParams(sp); if (id) n.set('open', id); else n.delete('open'); setSp(n); };
  const allSel = items.length > 0 && items.every((a) => sel.has(a.id));
  const clearAll = () => { setSp(new URLSearchParams(), { replace: true }); setPage(1); setSel(new Set()); };
  const showAll = () => { const n = new URLSearchParams(); n.set('show_all', '1'); setSp(n, { replace: true }); setPage(1); setSel(new Set()); };
  const isDefault = explicitSev.length === 0 && !sp.has('show_all') && !f.status && !f.q && !f.category && !scoped;
  const isShowAll = sp.has('show_all') && !f.status && !f.q && !f.category && !scoped;
  const view = (sev: string, st: string) => f.severity.join() === sev && f.status === st && !f.q && !f.category && !scoped;
  const setView = (sev: string, st: string) => { const n = new URLSearchParams(); if (sev) n.set('severity', sev); if (st) n.set('status', st); setSp(n, { replace: true }); setPage(1); };
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.defaultPrevented || t.closest('input, textarea, select, button, a, [contenteditable], [role=dialog]') || document.querySelector('[role=dialog]') || e.metaKey || e.ctrlKey || open) return;
      if (e.key === 'j') setCur((c) => Math.min(c + 1, items.length - 1));
      else if (e.key === 'k') setCur((c) => Math.max(c - 1, 0));
      else if (e.key === 'Enter' && items[cur]) openAlert(items[cur].id);
      else if (e.key === 'x' && items[cur]) setSel((s) => { const n = new Set(s); if (n.has(items[cur].id)) n.delete(items[cur].id); else n.add(items[cur].id); return n; });
      else if (e.key === 'a' && can('alerts.triage') && sel.size && !bulk.isPending) bulk.mutate('acknowledged');
      else if (e.key === 'Escape') setSel(new Set());
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  });
  const toggle = (id: string) => setSel((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const showOverview = workspace === 'alerts' && !f.unassigned_client;
  function inspectBucket(point: Point, severity?: string) {
    if (!point.since || !point.until) return;
    const filters = new URLSearchParams({ since: point.since, until: point.until, show_all: '1' });
    if (f.client_id) filters.set('client_id', f.client_id);
    if (severity) filters.set('severity', severity);
    setSp(filters);
    changePage(1);
    setOverviewOpen(false);
  }
  return (
    <>
      <PageHead title={workspace === 'siem' ? 'SIEM' : workspace === 'hunting' ? 'Threat Hunting' : 'Alerts'}
        sub={workspace === 'siem' ? 'Search normalized security alerts across connected sources.'
          : workspace === 'hunting' ? 'Hunt by hostname, IP address, username, or detection rule across normalized alerts.'
          : 'Normalised, de-duplicated alerts from every connected source'}>
        {showOverview && <button type="button" className="btn small" aria-expanded={overviewOpen}
          aria-controls={overviewOpen ? 'alerts-overview' : undefined} onClick={() => setOverviewOpen((open) => !open)}>
          {overviewOpen ? 'Hide alert overview' : 'Show alert overview'}
        </button>}
        {workspace === 'alerts' && can('alerts.delete') && (q.data?.total ?? 0) > 0 && (
          <button className="btn small danger" onClick={() => setDeletingAll(true)}>Delete all alerts</button>
        )}
      </PageHead>
      {showOverview && overviewOpen && <AlertOverview clientId={f.client_id} onInspect={inspectBucket} />}
      {scoped && <p className="notice">Filtered telemetry{f.host ? ` · Host: ${f.host}` : ''}{f.username ? ` · User: ${f.username}` : ''}{f.source ? ` · Source: ${f.source}` : ''}{f.since ? ` · Since ${when(f.since)}` : ''}{f.until ? ` · Until ${when(f.until)}` : ''}</p>}
      <div className="toolbar">
      <Chips items={[
        { label: 'Medium+', active: isDefault, onClick: clearAll },
        { label: 'All severities', active: isShowAll, onClick: showAll },
        { label: 'New', active: view('', 'new'), onClick: () => setView('', 'new') },
        { label: 'Critical', active: view('critical', ''), onClick: () => setView('critical', '') },
        { label: 'High', active: view('high', ''), onClick: () => setView('high', '') },
        { label: 'Investigating', active: view('', 'investigating'), onClick: () => setView('', 'investigating') },
      ]} />
      <SavedViews area="alerts" onApply={() => { setPage(1); setSel(new Set()); setCur(-1); }} />
      </div>
      <div className="filters compact">
        <Field label="Search" id="f-q">
          <SearchBox id="f-q" value={f.q} onChange={(value) => setF('q', value)} placeholder="Title, host, IP, user, or rule" label="Search alerts" />
        </Field>
        <Field label="Severity" id="f-sev"><select id="f-sev" value={f.severity[0] ?? ''} onChange={(e) => { const n = new URLSearchParams(sp); n.delete('severity'); if (e.target.value) n.set('severity', e.target.value); setSp(n, { replace: true }); setPage(1); }}><option value="">All</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Status" id="f-st"><select id="f-st" value={f.status} onChange={(e) => setF('status', e.target.value)}><option value="">All</option>{['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'].map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Category" id="f-cat"><select id="f-cat" value={f.category} onChange={(e) => setF('category', e.target.value)}><option value="">All</option><option>security</option><option>infrastructure</option></select></Field>
        {workspace !== 'alerts' && <>
          <Field label="Source" id="f-source"><select id="f-source" value={f.source} onChange={(e) => setF('source', e.target.value)}>
            <option value="">All sources</option>
            {[...new Set([...(sources.data ?? []), ...(f.source ? [f.source] : [])])].map((source) => <option key={source}>{source}</option>)}
          </select></Field>
          <Field label="Activity window" id="f-window"><select id="f-window" value={f.since ? 'custom' : ''} onChange={(e) => {
            const hours = Number(e.target.value);
            setF('since', hours ? new Date(Date.now() - hours * 3600000).toISOString() : '');
          }}><option value="">All time</option>{f.since && <option value="custom" disabled>Since {when(f.since)}</option>}<option value="24">Last 24 hours</option><option value="168">Last 7 days</option></select></Field>
        </>}
        {(scoped || f.q || f.status || f.category || f.severity.length > 0) && <button className="btn small" onClick={clearAll}>Clear filters</button>}
      </div>
      {q.isLoading ? <Skeleton lines={8} /> : q.error ? <ErrorBox error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} /> : q.data!.items.length === 0 ? <Empty onAction={clearAll}>No alerts match these filters. Clear filters to return to the full queue.</Empty> : (
        <>
          <div className="table-wrap"><table>
            <thead><tr><th><input type="checkbox" style={{ width: 'auto' }} aria-label="Select all on this page" checked={allSel} onChange={() => setSel(allSel ? new Set() : new Set(items.map((a) => a.id)))} /></th><th>Severity</th><th>Alert</th><th>Host</th><th>Source IP</th><th>Source</th><th>Status</th><th>Count</th><th>Ack due</th><th>Time</th></tr></thead>
            <tbody>{q.data!.items.map((a) => (
              <tr key={a.id} data-sev={a.severity} tabIndex={0} className={`clickable${items[cur]?.id === a.id ? ' kbd-focus' : ''}`} onClick={() => openAlert(a.id)} onKeyDown={(event) => { if (event.target === event.currentTarget && event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); openAlert(a.id); } }}>
                <td onClick={(e) => e.stopPropagation()}><input type="checkbox" style={{ width: 'auto' }} aria-label={`Select ${a.title}`} checked={sel.has(a.id)} onChange={() => toggle(a.id)} /></td>
                <td><Sev v={a.severity} /></td><td className="truncate"><span className="cell-text" title={a.title}>{a.sla_breached && <span className="badge st-failed" style={{ marginRight: 8 }}>SLA</span>}{a.title}</span></td>
                <td>{a.host || '—'}</td><td className="mono">{a.src_ip || '—'}</td><td>{a.source}</td><td><Status v={a.status} /></td><td>{a.count}</td>
                <td><LiveTimer deadline={a.ack_due} done={a.status !== 'new'} /></td><td>{ago(a.time)}</td>
              </tr>))}</tbody>
          </table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={changePage} />
          {(can('alerts.triage') || can('alerts.delete')) && sel.size > 0 && (
            <div className="bulkbar"><b>{sel.size} selected</b><span style={{ flex: 1 }} />
              {can('alerts.triage') && <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('acknowledged')}>Acknowledge</button>}
              {can('alerts.triage') && <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('investigating')}>Investigate</button>}
              {can('alerts.triage') && <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('resolved')}>Resolve</button>}
              {can('alerts.delete') && <button className="btn small danger" disabled={bulk.isPending} onClick={() => setDeleting([...sel])}>Delete selected</button>}
              <button className="btn small" onClick={() => setSel(new Set())}>Clear</button></div>
          )}
        </>
      )}
      {deleting && <DeleteAlertsModal ids={deleting} onClose={() => setDeleting(null)} onDeleted={() => { setDeleting(null); setSel(new Set()); setCur(-1); setPage(1); }} />}
      {deletingAll && <DeleteAllAlertsModal total={q.data?.total ?? 0} onClose={() => setDeletingAll(false)} onDeleted={() => { setDeletingAll(false); setSel(new Set()); setCur(-1); setPage(1); }} />}
      {open && <AlertDrawer key={open} id={open} onClose={() => { const n = new URLSearchParams(sp); n.delete('open'); setSp(n); }} />}
    </>
  );
}

function AlertOverview({ clientId, onInspect }: { clientId: string; onInspect: (point: Point, severity?: string) => void }) {
  const { dark } = useOutletContext<{ dark: boolean }>();
  const overview = useQuery({
    queryKey: clientId ? ['dashboard', 1, clientId] : ['dashboard', 1],
    queryFn: () => get<{ series: Point[] }>('/api/dashboard', { days: 1, client_id: clientId }),
    refetchInterval: REFRESH_MS,
  });
  return (
    <section id="alerts-overview" className="panel ops-trend alert-volume-overview" aria-labelledby="alert-volume-heading">
      <div className="panel-title">
        <div><h2 id="alert-volume-heading">Alert overview</h2><p>Hourly alert counts · Last 24 hours · UTC</p></div>
      </div>
      {overview.error ? <ErrorBox error={overview.error} onRetry={() => void overview.refetch()} retrying={overview.isFetching} />
        : overview.data ? <Suspense fallback={<Skeleton lines={4} />}>
            <Trend key={clientId} dark={dark} series={overview.data.series} onInspect={onInspect} />
          </Suspense> : <Skeleton lines={4} />}
    </section>
  );
}

function alertPivot(field: string, value: string, client: string | null) {
  const params = new URLSearchParams({ [field]: value, show_all: '1' });
  if (client) params.set('client_id', client);
  else params.set('unassigned_client', 'true');
  return `/app/alerts?${params}`;
}

type AlertActivity = {
  id: number; time: string; actor: string; status: string | null; assigned: boolean; released: boolean;
};

function InvestigationTimeline({ alert }: { alert: {
  first_seen: string | null; last_seen: string | null; count: number;
  acknowledged_at: string | null; resolved_at: string | null; activity?: AlertActivity[];
} }) {
  const activity = alert.activity ?? [];
  const entries = activity.map((event) => ({
    id: String(event.id), time: event.time, actor: event.actor,
    label: [
      event.status && `Status changed to ${event.status.replaceAll('_', ' ')}`,
      event.assigned && 'Ownership assigned',
      event.released && 'Ownership released',
    ].filter(Boolean).join(' · '),
  }));
  if (alert.first_seen) entries.push({ id: 'first', time: alert.first_seen, actor: '', label: 'First observed' });
  if (alert.last_seen && alert.count > 1) entries.push({ id: 'last', time: alert.last_seen, actor: '', label: `Last observed · ${alert.count} occurrences` });
  if (alert.acknowledged_at && !activity.some((event) => event.time === alert.acknowledged_at || event.status === 'acknowledged')) {
    entries.push({ id: 'ack', time: alert.acknowledged_at, actor: '', label: 'Acknowledged' });
  }
  if (alert.resolved_at && !activity.some((event) => event.status === 'resolved' || event.status === 'false_positive')) {
    entries.push({ id: 'closed', time: alert.resolved_at, actor: '', label: 'Closed' });
  }
  entries.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  return <section className="alert-investigation-timeline">
    <h3>Investigation timeline</h3>
    {entries.length ? <ol>{entries.map((entry) => <li key={entry.id}>
      <strong>{entry.label}</strong>
      <time dateTime={entry.time}>{when(entry.time)}</time>
      {entry.actor && <small>{entry.actor}</small>}
    </li>)}</ol> : <p className="muted">No recorded activity.</p>}
  </section>;
}

function AlertDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['alert', id], queryFn: () => get<Alert>(`/api/alerts/${id}`) });
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const nav = useNavigate();
  const [note, setNote] = useState('');
  const [block, setBlock] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const rawEvent = useRef<HTMLDetailsElement>(null);
  const a = q.data;
  const upd = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch(`/api/alerts/${id}`, { version: a.version, ...body }),
    onSuccess: () => { toast('Alert updated'); void qc.invalidateQueries({ queryKey: ['alert', id] }); void qc.invalidateQueries({ queryKey: ['alerts'] }); void qc.invalidateQueries({ queryKey: ['triage-queue'] }); },
    onError: (e: Error) => toast(e.message, true),
  });
  const toCase = useMutation({ mutationFn: () => post('/api/alerts/to-case', { alert_ids: [id] }), onSuccess: (r: any) => { toast(`Case #${r.number} created`); nav(`/app/cases?open=${r.id}`); }, onError: (e: Error) => toast(e.message, true) });
  const enrich = useMutation({ mutationFn: (ind: string) => post('/api/intel/enrich', { indicator: ind, alert_id: id }), onSuccess: () => toast('Enrichment queued — see Threat intel'), onError: (e: Error) => toast(e.message, true) });
  return (
    <Drawer title={a ? <><Sev v={a.severity} /> {a.title}</> : 'Alert'} onClose={onClose}>
      {q.isLoading ? <Skeleton lines={8} /> : q.error ? <ErrorBox error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} /> : (
        <>
          <div className="row" style={{ marginBottom: 14 }}>
            {can('alerts.triage') && a.status === 'new' && <button className="btn primary small" onClick={() => upd.mutate({ status: 'acknowledged' })}>Acknowledge</button>}
            {can('alerts.triage') && ['new', 'acknowledged'].includes(a.status) && <button className="btn small" onClick={() => upd.mutate({ status: 'investigating' })}>Investigate</button>}
            {can('alerts.triage') && !['resolved', 'false_positive'].includes(a.status) && <button className="btn small" onClick={() => upd.mutate({ status: 'resolved' })}>Resolve</button>}
            {can('cases.write') && !a.case_id && <button className="btn small" onClick={() => toCase.mutate()}>Create case</button>}
            {can('response.request') && a.src_ip && <button className="btn small danger" onClick={() => setBlock(true)}>Request IP block</button>}
            {can('intel.enrich') && a.src_ip && <button className="btn small" onClick={() => enrich.mutate(a.src_ip)}>Enrich IP</button>}
            {can('alerts.delete') && <button className="btn small danger" onClick={() => setDeleting(true)}>Delete alert</button>}
          </div>
          {deleting && <DeleteAlertsModal ids={[id]} onClose={() => setDeleting(false)} onDeleted={onClose} />}
          <dl className="kv">
            <dt>Status</dt><dd><Status v={a.status} /></dd><dt>Owner</dt><dd>{a.assignee_name ?? (a.assignee_id ? 'Assigned analyst' : 'Unassigned')}</dd><dt>Source</dt><dd>{a.source} · rule {a.rule_id || '—'}</dd><dt>Host</dt><dd>{a.host || '—'}</dd>
            <dt>Source IP</dt><dd className="mono">{a.src_ip || '—'}</dd><dt>User</dt><dd>{a.username || '—'}</dd><dt>First seen</dt><dd>{when(a.first_seen)}</dd><dt>Occurrences</dt><dd>{a.count}</dd>
            <dt>Ack due</dt><dd>{a.acknowledged_at ? `acknowledged ${when(a.acknowledged_at)}` : when(a.ack_due)}</dd><dt>Resolve due</dt><dd>{when(a.resolve_due)}</dd>
            <dt>MITRE</dt><dd>{a.mitre?.join(', ') || '—'}</dd><dt>Case</dt><dd>{a.case_id ? <Link to={`/app/cases?open=${a.case_id}`}>Open case</Link> : '—'}</dd>
          </dl>
          <section className="investigation-pivots" aria-label="Investigation pivots">
            <h3>Investigate</h3>
            <div className="row">
              {a.host && <Link className="btn small" to={alertPivot('host', a.host, a.client_id)}>Host alerts</Link>}
              {a.username && <Link className="btn small" to={alertPivot('username', a.username, a.client_id)}>User alerts</Link>}
              {a.src_ip && <Link className="btn small" to={alertPivot('q', a.src_ip, a.client_id)}>Source IP alerts</Link>}
              {a.rule_id && <Link className="btn small" to={alertPivot('q', a.rule_id, a.client_id)}>Related rule alerts</Link>}
              {a.raw != null && <button type="button" className="btn small" onClick={() => {
                const details = rawEvent.current;
                if (details) {
                  details.open = true;
                  details.querySelector('summary')?.focus();
                }
              }}>View raw event</button>}
            </div>
          </section>
          <InvestigationTimeline alert={a} />
          {a.description && <><h3 style={{ margin: '16px 0 6px' }}>Description</h3><p style={{ whiteSpace: 'pre-wrap' }}>{a.description}</p></>}
          {can('alerts.tune') && (
            <div style={{ marginTop: 16 }}>
              <Field label="Tuning note / false-positive justification" id="tn"><textarea id="tn" value={note} onChange={(e) => setNote(e.target.value)} placeholder={a.tuning_note || 'Why is this noise?'} /></Field>
              <div className="row"><button className="btn small" disabled={!note.trim()} onClick={() => upd.mutate({ tuning_note: note })}>Save note</button><button className="btn small" disabled={!note.trim() && !a.tuning_note} onClick={() => upd.mutate({ status: 'false_positive', tuning_note: note || a.tuning_note })}>Mark false positive</button></div>
            </div>
          )}
          <details ref={rawEvent} style={{ marginTop: 16 }}><summary>Raw event</summary><pre className="mono" style={{ overflow: 'auto' }}>{JSON.stringify(a.raw, null, 2)}</pre></details>
          {block && <RequestActionModal initial={{ action_key: 'block_ip', targets: a.src_ip, alert_id: id }} onClose={() => setBlock(false)} />}
        </>
      )}
    </Drawer>
  );
}

function DeleteAlertsModal({ ids, onClose, onDeleted }: { ids: string[]; onClose: () => void; onDeleted: () => void }) {
  const qc = useQueryClient();
  const label = ids.length === 1 ? 'Delete alert' : `Delete ${ids.length} alerts`;
  const remove = useAct(() => post('/api/alerts/bulk-delete', { ids }), [], ids.length === 1 ? 'Alert deleted' : `${ids.length} alerts deleted`, () => {
    onDeleted();
    void qc.invalidateQueries();
  });
  return <Modal title={label} onClose={() => { if (!remove.isPending) onClose(); }}>
    <p>Permanently delete {ids.length === 1 ? 'this alert' : `these ${ids.length} alerts`} from the workspace? This action cannot be undone.</p>
    {remove.error && <ErrorBox error={remove.error} />}
    <div className="row">
      <button className="btn" disabled={remove.isPending} onClick={onClose}>Cancel</button>
      <button className="btn danger" disabled={remove.isPending} onClick={() => remove.mutate(undefined)}>{remove.isPending ? 'Deleting…' : label}</button>
    </div>
  </Modal>;
}

type PurgeStatus = { status: 'idle' | 'running' | 'done' | 'failed'; deleted?: number; remaining?: number; started_by?: string; error?: string | null };

function DeleteAllAlertsModal({ total, onClose, onDeleted }: { total: number; onClose: () => void; onDeleted: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [confirmText, setConfirmText] = useState('');
  const [started, setStarted] = useState(false);
  // Delete-all removes every alert in your scope, not only the filtered list, so show that number (the filtered total understated it).
  const everything = useQuery({ queryKey: ['alerts-total-unfiltered'], queryFn: () => get<Page<unknown>>('/api/alerts', { limit: 1 }) });
  const all = everything.data?.total ?? total;
  // The purge runs as a server-side job, one batch at a time, so it never hits the proxy timeout and the page can be closed.
  const status = useQuery({
    queryKey: ['alerts-purge-status'],
    queryFn: () => get<PurgeStatus>('/api/alerts/delete-all/status'),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 2000 : false),
  });
  const running = status.data?.status === 'running';
  const start = useMutation({
    mutationFn: () => post<PurgeStatus>('/api/alerts/delete-all/background'),
    onSuccess: (s) => { setStarted(true); qc.setQueryData(['alerts-purge-status'], s); },
    onError: (e: Error) => toast(e.message, true),
  });
  useEffect(() => {
    if (!started || !status.data) return;
    if (status.data.status === 'done') {
      toast(`${status.data.deleted ?? 0} alert${status.data.deleted === 1 ? '' : 's'} deleted`);
      onDeleted();
      void qc.invalidateQueries();
    }
  }, [started, status.data, toast, onDeleted, qc]);
  const done = status.data?.deleted ?? 0;
  const left = status.data?.remaining ?? all;
  return <Modal title={running ? 'Deleting all alerts' : `Delete all ${all} alerts`} onClose={onClose}>
    {running ? <>
      <p className="notice">Running on the server{status.data?.started_by ? ` (started by ${status.data.started_by})` : ''}. You can close this window; it keeps going.</p>
      <div className="purge-progress" role="progressbar" aria-valuemin={0} aria-valuemax={done + left} aria-valuenow={done} aria-label="Alerts deleted">
        <span style={{ width: `${Math.min(100, Math.round((done / Math.max(1, done + left)) * 100))}%` }} />
      </div>
      <p className="muted">{done.toLocaleString()} deleted · {left.toLocaleString()} remaining</p>
      <div className="row"><button className="btn" onClick={onClose}>Close</button></div>
    </> : <>
      <p className="notice">This permanently deletes every alert you can see across all filters and severities. It cannot be undone.</p>
      {status.data?.status === 'failed' && <ErrorBox error={new Error(`The last purge stopped: ${status.data.error ?? 'unknown error'}`)} />}
      <Field label="Type DELETE to confirm" id="confirm-delete-all">
        <input id="confirm-delete-all" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder="DELETE" autoFocus />
      </Field>
      <div className="row">
        <button className="btn" disabled={start.isPending} onClick={onClose}>Cancel</button>
        <button className="btn danger" disabled={start.isPending || confirmText !== 'DELETE'} onClick={() => start.mutate()}>{start.isPending ? 'Starting…' : 'Delete all alerts'}</button>
      </div>
    </>}
  </Modal>;
}
