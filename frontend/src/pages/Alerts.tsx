import { LiveTimer, Skeleton } from '../components/Interactive';
import { SavedViews } from '../components/SavedViews';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Chips } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, PageHead, Pager, SearchBox, Sev, Status, useToast } from '../components/ui';
import { get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { SEVERITIES, ago, when } from '../lib/format';
import { RequestActionModal } from './Response';

type Alert = any;

export default function Alerts({ workspace = 'alerts' }: { workspace?: 'alerts' | 'siem' | 'hunting' }) {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const f = { severity: sp.getAll('severity'), status: sp.get('status') ?? '', q: sp.get('q') ?? '', category: sp.get('category') ?? '',
    source: sp.get('source') ?? '', host: sp.get('host') ?? '', client_id: sp.get('client_id') ?? '',
    unassigned_client: sp.get('unassigned_client') === 'true' ? true : undefined,
    since: sp.get('since') ?? '',
  };
  const setF = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); setPage(1); };
  const q = useQuery({ queryKey: ['alerts', f, page], queryFn: () => get<Page<Alert>>('/api/alerts', { ...f, status: f.status ? [f.status] : [], page, limit: 50 }) });
  const scoped = Boolean(f.source || f.host || f.since || f.client_id || f.unassigned_client);
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
  useEffect(() => { setPage(1); setSel(new Set()); setCur(-1); }, [f.q, f.status, f.category, severityKey, f.source, f.host, f.since, f.client_id, f.unassigned_client]);
  const open = sp.get('open');
  const [cur, setCur] = useState(-1);
  const items = q.data?.items ?? [];
  const changePage = (next: number) => { setPage(next); setSel(new Set()); setCur(-1); };
  const openAlert = (id: string | null) => { const n = new URLSearchParams(sp); if (id) n.set('open', id); else n.delete('open'); setSp(n); };
  const allSel = items.length > 0 && items.every((a) => sel.has(a.id));
  const clearAll = () => { setSp(new URLSearchParams(), { replace: true }); setPage(1); setSel(new Set()); };
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
  return (
    <>
      <PageHead title={workspace === 'siem' ? 'SIEM' : workspace === 'hunting' ? 'Threat Hunting' : 'Alerts'}
        sub={workspace === 'siem' ? 'Search normalized security alerts across connected sources.'
          : workspace === 'hunting' ? 'Hunt by hostname, IP address, username, or detection rule across normalized alerts.'
          : 'Normalised, de-duplicated alerts from every connected source'} />
      {scoped && <p className="notice">Filtered telemetry{f.host ? ` · Host: ${f.host}` : ''}{f.source ? ` · Source: ${f.source}` : ''}{f.since ? ` · Since ${when(f.since)}` : ''}</p>}
      <SavedViews area="alerts" onApply={() => { setPage(1); setSel(new Set()); setCur(-1); }} />
      <Chips items={[
        { label: 'All', active: !scoped && !f.q && !f.status && !f.category && f.severity.length === 0, onClick: clearAll },
        { label: 'New', active: view('', 'new'), onClick: () => setView('', 'new') },
        { label: 'Critical', active: view('critical', ''), onClick: () => setView('critical', '') },
        { label: 'High', active: view('high', ''), onClick: () => setView('high', '') },
        { label: 'Investigating', active: view('', 'investigating'), onClick: () => setView('', 'investigating') },
      ]} />
      <div className="filters">
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
      {q.isLoading ? <Skeleton lines={8} /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No alerts match these filters.</Empty> : (
        <>
          <div className="table-wrap"><table>
            <thead><tr><th><input type="checkbox" style={{ width: 'auto' }} aria-label="Select all on this page" checked={allSel} onChange={() => setSel(allSel ? new Set() : new Set(items.map((a) => a.id)))} /></th><th>Severity</th><th>Alert</th><th>Host</th><th>Source IP</th><th>Source</th><th>Status</th><th>Count</th><th>Ack due</th><th>Time</th></tr></thead>
            <tbody>{q.data!.items.map((a) => (
              <tr key={a.id} tabIndex={0} className={`clickable${items[cur]?.id === a.id ? ' kbd-focus' : ''}`} onClick={() => openAlert(a.id)} onKeyDown={(event) => { if (event.target === event.currentTarget && event.key === 'Enter') openAlert(a.id); }}>
                <td onClick={(e) => e.stopPropagation()}><input type="checkbox" style={{ width: 'auto' }} aria-label={`Select ${a.title}`} checked={sel.has(a.id)} onChange={() => toggle(a.id)} /></td>
                <td><Sev v={a.severity} /></td><td className="wrap">{a.title}{a.sla_breached && <span className="badge st-failed" style={{ marginLeft: 8 }}>SLA</span>}</td>
                <td>{a.host || '—'}</td><td className="mono">{a.src_ip || '—'}</td><td>{a.source}</td><td><Status v={a.status} /></td><td>{a.count}</td>
                <td><LiveTimer deadline={a.ack_due} done={a.status !== 'new'} /></td><td>{ago(a.time)}</td>
              </tr>))}</tbody>
          </table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={changePage} />
          {can('alerts.triage') && sel.size > 0 && (
            <div className="bulkbar"><b>{sel.size} selected</b><span style={{ flex: 1 }} />
              <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('acknowledged')}>Acknowledge</button>
              <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('investigating')}>Investigate</button>
              <button className="btn small" disabled={bulk.isPending} onClick={() => bulk.mutate('resolved')}>Resolve</button>
              <button className="btn small" onClick={() => setSel(new Set())}>Clear</button></div>
          )}
        </>
      )}
      {open && <AlertDrawer key={open} id={open} onClose={() => { const n = new URLSearchParams(sp); n.delete('open'); setSp(n); }} />}
    </>
  );
}

function AlertDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['alert', id], queryFn: () => get<Alert>(`/api/alerts/${id}`) });
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const nav = useNavigate();
  const [note, setNote] = useState('');
  const [block, setBlock] = useState(false);
  const a = q.data;
  const upd = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch(`/api/alerts/${id}`, { version: a.version, ...body }),
    onSuccess: () => { toast('Alert updated'); void qc.invalidateQueries({ queryKey: ['alert', id] }); void qc.invalidateQueries({ queryKey: ['alerts'] }); },
    onError: (e: Error) => toast(e.message, true),
  });
  const toCase = useMutation({ mutationFn: () => post('/api/alerts/to-case', { alert_ids: [id] }), onSuccess: (r: any) => { toast(`Case #${r.number} created`); nav(`/app/cases?open=${r.id}`); }, onError: (e: Error) => toast(e.message, true) });
  const enrich = useMutation({ mutationFn: (ind: string) => post('/api/intel/enrich', { indicator: ind, alert_id: id }), onSuccess: () => toast('Enrichment queued — see Threat intel'), onError: (e: Error) => toast(e.message, true) });
  return (
    <Drawer title={a ? <><Sev v={a.severity} /> {a.title}</> : 'Alert'} onClose={onClose}>
      {q.isLoading ? <Skeleton lines={8} /> : q.error ? <ErrorBox error={q.error} /> : (
        <>
          <div className="row" style={{ marginBottom: 14 }}>
            {can('alerts.triage') && a.status === 'new' && <button className="btn primary small" onClick={() => upd.mutate({ status: 'acknowledged' })}>Acknowledge</button>}
            {can('alerts.triage') && ['new', 'acknowledged'].includes(a.status) && <button className="btn small" onClick={() => upd.mutate({ status: 'investigating' })}>Investigate</button>}
            {can('alerts.triage') && !['resolved', 'false_positive'].includes(a.status) && <button className="btn small" onClick={() => upd.mutate({ status: 'resolved' })}>Resolve</button>}
            {can('cases.write') && !a.case_id && <button className="btn small" onClick={() => toCase.mutate()}>Create case</button>}
            {can('response.request') && a.src_ip && <button className="btn small danger" onClick={() => setBlock(true)}>Request IP block</button>}
            {can('intel.enrich') && a.src_ip && <button className="btn small" onClick={() => enrich.mutate(a.src_ip)}>Enrich IP</button>}
          </div>
          <dl className="kv">
            <dt>Status</dt><dd><Status v={a.status} /></dd><dt>Source</dt><dd>{a.source} · rule {a.rule_id || '—'}</dd><dt>Host</dt><dd>{a.host || '—'}</dd>
            <dt>Source IP</dt><dd className="mono">{a.src_ip || '—'}</dd><dt>User</dt><dd>{a.username || '—'}</dd><dt>First seen</dt><dd>{when(a.first_seen)}</dd><dt>Occurrences</dt><dd>{a.count}</dd>
            <dt>Ack due</dt><dd>{a.acknowledged_at ? `acknowledged ${when(a.acknowledged_at)}` : when(a.ack_due)}</dd><dt>Resolve due</dt><dd>{when(a.resolve_due)}</dd>
            <dt>MITRE</dt><dd>{a.mitre?.join(', ') || '—'}</dd><dt>Case</dt><dd>{a.case_id ? <a href={`/app/cases?open=${a.case_id}`}>Open case</a> : '—'}</dd>
          </dl>
          {(a.src_ip || a.host || a.rule_id) && <section className="investigation-pivots" aria-label="Related alert searches">
            <h3>Related activity</h3>
            <p>Search the alert queue for a shared indicator.</p>
            <div className="row">
              {[[a.src_ip, 'Source IP'], [a.host, 'Host'], [a.rule_id, 'Rule']].filter(([value]) => value).map(([value, label]) => (
                <Link className="btn small" key={label} to={`/app/alerts?q=${encodeURIComponent(value)}`}>{label} · {value}</Link>
              ))}
            </div>
          </section>}
          {a.description && <><h3 style={{ margin: '16px 0 6px' }}>Description</h3><p style={{ whiteSpace: 'pre-wrap' }}>{a.description}</p></>}
          {can('alerts.tune') && (
            <div style={{ marginTop: 16 }}>
              <Field label="Tuning note / false-positive justification" id="tn"><textarea id="tn" value={note} onChange={(e) => setNote(e.target.value)} placeholder={a.tuning_note || 'Why is this noise?'} /></Field>
              <div className="row"><button className="btn small" disabled={!note.trim()} onClick={() => upd.mutate({ tuning_note: note })}>Save note</button><button className="btn small" disabled={!note.trim() && !a.tuning_note} onClick={() => upd.mutate({ status: 'false_positive', tuning_note: note || a.tuning_note })}>Mark false positive</button></div>
            </div>
          )}
          <details style={{ marginTop: 16 }}><summary>Raw event</summary><pre className="mono" style={{ overflow: 'auto' }}>{JSON.stringify(a.raw, null, 2)}</pre></details>
          {block && <RequestActionModal initial={{ action_key: 'block_ip', targets: a.src_ip, alert_id: id }} onClose={() => setBlock(false)} />}
        </>
      )}
    </Drawer>
  );
}
