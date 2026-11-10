import { SavedViews } from '../components/SavedViews';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Chips } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, SearchBox, Sev, Status } from '../components/ui';
import { get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { SEVERITIES, ago, until, when } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Cases() {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const { can } = useAuth();
  const f = { status: sp.get('status') ?? '', severity: sp.get('severity') ?? '', mine: sp.get('mine') === '1', q: sp.get('q') ?? '' };
  const setF = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); setPage(1); };
  const q = useQuery({ queryKey: ['cases', f, page], queryFn: () => get<Page<any>>('/api/cases', { status: f.status ? [f.status] : [], severity: f.severity, mine: f.mine, q: f.q, page, limit: 50 }) });
  const open = sp.get('open');
  const openCase = (id: string | null) => { const n = new URLSearchParams(sp); if (id) n.set('open', id); else n.delete('open'); setSp(n, { replace: true }); };
  return (
    <>
      <PageHead title="Cases" sub="Investigations with tasks, observables and a full timeline.">
        {can('cases.write') && <button className="btn primary" onClick={() => setCreating(true)}>New case</button>}
      </PageHead>
      <SavedViews area="cases" onApply={() => { setPage(1); }} />
      <Chips items={[
        { label: 'All', active: !f.status && !f.severity && !f.mine && !f.q, onClick: () => { setSp(new URLSearchParams(), { replace: true }); setPage(1); } },
        { label: 'Open', active: f.status === 'open' && !f.mine, onClick: () => { setSp(new URLSearchParams({ status: 'open' }), { replace: true }); setPage(1); } },
        { label: 'In progress', active: f.status === 'in_progress', onClick: () => { setSp(new URLSearchParams({ status: 'in_progress' }), { replace: true }); setPage(1); } },
        { label: 'Critical', active: f.severity === 'critical', onClick: () => { setSp(new URLSearchParams({ severity: 'critical' }), { replace: true }); setPage(1); } },
        { label: 'Mine', active: f.mine, onClick: () => { setSp(new URLSearchParams({ mine: '1' }), { replace: true }); setPage(1); } },
      ]} />
      <div className="filters">
        <SearchBox value={f.q} onChange={(v) => setF('q', v)} placeholder="Search title…" label="Search cases" />
        <select aria-label="Status" value={f.status} onChange={(e) => setF('status', e.target.value)}><option value="">Any status</option>{['open', 'in_progress', 'resolved', 'closed'].map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}</select>
        <select aria-label="Severity" value={f.severity} onChange={(e) => setF('severity', e.target.value)}><option value="">Any severity</option>{SEVERITIES.filter((s) => s !== 'info').map((s) => <option key={s}>{s}</option>)}</select>
        <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={f.mine} onChange={(e) => setF('mine', e.target.checked ? '1' : '')} /> Mine</label>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No cases match.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Resolve SLA</th><th>Sync</th><th>Created</th></tr></thead>
            <tbody>{q.data!.items.map((c) => <tr key={c.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => openCase(c.id)} onKeyDown={(e) => e.key === 'Enter' && openCase(c.id)}>
              <td className="mono">{c.number}</td><td className="wrap">{c.title}</td><td><Sev v={c.severity} /></td><td><Status v={c.status} /></td><td>{c.status === 'closed' || c.status === 'resolved' ? '—' : until(c.resolve_due)}</td><td>{c.sync_status}</td><td>{ago(c.created_at)}</td></tr>)}</tbody></table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={setPage} />
        </>
      )}
      {open && <CaseDrawer id={open} onClose={() => openCase(null)} />}
      {creating && <CreateCase onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); openCase(id); }} />}
    </>
  );
}

function CreateCase({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const tpl = useQuery({ queryKey: ['case-templates'], queryFn: () => get<any[]>('/api/cases/templates') });
  const clients = useQuery({ queryKey: ['clients'], queryFn: () => get<any[]>('/api/clients') });
  const [v, setV] = useState({ title: '', description: '', severity: 'medium', template: '', client_id: '', tlp: 'AMBER' });
  const m = useAct(() => post('/api/cases', { ...v, template: v.template || null, client_id: v.client_id || null }), ['cases'], 'Case created', (r) => onCreated(r.id));
  return (
    <Modal title="New case" onClose={onClose}>
      <Field label="Title" id="ct"><input id="ct" value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} /></Field>
      <Field label="Description" id="cd"><textarea id="cd" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      <div className="grid cols-2">
        <Field label="Severity" id="cs"><select id="cs" value={v.severity} onChange={(e) => setV({ ...v, severity: e.target.value })}>{['low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="TLP" id="ctl"><select id="ctl" value={v.tlp} onChange={(e) => setV({ ...v, tlp: e.target.value })}>{['WHITE', 'GREEN', 'AMBER', 'RED'].map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Template (adds tasks)" id="cx"><select id="cx" value={v.template} onChange={(e) => setV({ ...v, template: e.target.value })}><option value="">None</option>{tpl.data?.map((t) => <option key={t.id} value={t.name}>{t.name}</option>)}</select></Field>
        <Field label="Client / business unit" id="cc"><select id="cc" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">Unassigned</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
      </div>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={v.title.trim().length < 3 || m.isPending} onClick={() => m.mutate(undefined)}>Create case</button>
    </Modal>
  );
}

function CaseDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['case', id], queryFn: () => get<any>(`/api/cases/${id}`) });
  const { can } = useAuth();
  const [note, setNote] = useState('');
  const [task, setTask] = useState('');
  const [obs, setObs] = useState({ type: 'ip', value: '' });
  const [resolve, setResolve] = useState<null | { status: string; resolution: string }>(null);
  const keys = ['case', 'cases'];
  const addNote = useAct(() => post(`/api/cases/${id}/notes`, { text: note }), keys, 'Note added', () => setNote(''));
  const addTask = useAct(() => post(`/api/cases/${id}/tasks`, { title: task }), keys, undefined, () => setTask(''));
  const setTaskStatus = useAct((a: { tid: string; status: string }) => patch(`/api/cases/${id}/tasks/${a.tid}`, { status: a.status }), keys);
  const addObs = useAct(() => post(`/api/cases/${id}/observables`, obs), keys, 'Observable added', () => setObs({ ...obs, value: '' }));
  const enrich = useAct((value: string) => post('/api/intel/enrich', { indicator: value, case_id: id }), ['case', 'intel-jobs'], 'Enrichment queued');
  const setStatus = useAct((a: { status: string; resolution?: string }) => patch(`/api/cases/${id}`, { version: q.data.version, status: a.status, resolution: a.resolution ?? '' }), keys, 'Case updated', () => setResolve(null));
  if (q.isLoading) return <Drawer title="Case" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Case" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const c = q.data;
  const write = can('cases.write') && c.status !== 'closed';
  return (
    <Drawer title={<>#{c.number} {c.title}</>} onClose={onClose}>
      <div className="row" style={{ marginBottom: 10 }}><Sev v={c.severity} /><Status v={c.status} /><span>TLP:{c.tlp}</span><span className="spacer" /><span>Resolve due {until(c.resolve_due)}</span></div>
      {c.description && <p style={{ whiteSpace: 'pre-wrap' }}>{c.description}</p>}
      {c.sync_status === 'failed' && <div className="error">Ticket sync failed: {c.sync_error}</div>}
      {write && (
        <div className="row" style={{ margin: '10px 0' }}>
          {c.status === 'open' && <button className="btn small" onClick={() => setStatus.mutate({ status: 'in_progress' })}>Start work</button>}
          {can('cases.close') && c.status !== 'resolved' && <button className="btn small" onClick={() => setResolve({ status: 'resolved', resolution: 'true_positive' })}>Resolve</button>}
          {can('cases.close') && c.status === 'resolved' && <button className="btn small" onClick={() => setStatus.mutate({ status: 'closed' })}>Close</button>}
        </div>
      )}
      <h3>Tasks</h3>
      {c.tasks.length === 0 ? <Empty>No tasks.</Empty> : <ul style={{ listStyle: 'none', padding: 0 }}>{c.tasks.map((t: any) => (
        <li key={t.id} className="row" style={{ padding: '4px 0' }}>
          <input type="checkbox" aria-label={t.title} disabled={!write} checked={t.status === 'done'} onChange={(e) => setTaskStatus.mutate({ tid: t.id, status: e.target.checked ? 'done' : 'todo' })} />
          <span style={{ textDecoration: t.status === 'done' ? 'line-through' : 'none' }}>{t.title}{t.required && ' *'}</span>
        </li>))}</ul>}
      {write && <div className="row"><input placeholder="Add task…" aria-label="New task" value={task} onChange={(e) => setTask(e.target.value)} /><button className="btn small" disabled={!task.trim()} onClick={() => addTask.mutate(undefined)}>Add</button></div>}
      <h3 style={{ marginTop: 16 }}>Observables</h3>
      {c.observables.length === 0 ? <Empty>No observables.</Empty> : <div className="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th /></tr></thead><tbody>{c.observables.map((o: any) => (
        <tr key={o.id}><td>{o.type}</td><td className="mono wrap">{o.value}</td><td>{o.verdict ?? '—'}</td><td>{can('intel.enrich') && <button className="btn small" onClick={() => enrich.mutate(o.value)}>Enrich</button>}</td></tr>))}</tbody></table></div>}
      {write && <div className="row" style={{ marginTop: 8 }}>
        <select aria-label="Observable type" value={obs.type} onChange={(e) => setObs({ ...obs, type: e.target.value })}>{['ip', 'domain', 'hash', 'url', 'user', 'email', 'host'].map((t) => <option key={t}>{t}</option>)}</select>
        <input placeholder="Value" aria-label="Observable value" value={obs.value} onChange={(e) => setObs({ ...obs, value: e.target.value })} />
        <button className="btn small" disabled={!obs.value.trim()} onClick={() => addObs.mutate(undefined)}>Add</button></div>}
      {c.alerts?.length > 0 && <><h3 style={{ marginTop: 16 }}>Linked alerts</h3><ul>{c.alerts.map((a: any) => <li key={a.id}><Sev v={a.severity} /> {a.title}</li>)}</ul></>}
      {c.tickets?.length > 0 && <><h3 style={{ marginTop: 16 }}>External tickets</h3><ul>{c.tickets.map((t: any) => <li key={t.id}>{t.provider} {t.external_id} ({t.status})</li>)}</ul></>}
      <h3 style={{ marginTop: 16 }}>Timeline</h3>
      {write && <div className="row"><input placeholder="Add a note…" aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn small" disabled={!note.trim()} onClick={() => addNote.mutate(undefined)}>Post</button></div>}
      <ul className="timeline">{[...c.timeline].reverse().map((e: any) => <li key={e.id}><b>{e.actor}</b> · {e.kind} <span style={{ color: 'var(--muted)' }}>{when(e.at)}</span><div style={{ whiteSpace: 'pre-wrap' }}>{e.message}</div></li>)}</ul>
      {resolve && (
        <Modal title="Resolve case" onClose={() => setResolve(null)}>
          <Field label="Resolution" id="res"><select id="res" value={resolve.resolution} onChange={(e) => setResolve({ ...resolve, resolution: e.target.value })}>{['true_positive', 'false_positive', 'benign', 'duplicate', 'other'].map((r) => <option key={r}>{r}</option>)}</select></Field>
          {setStatus.error && <ErrorBox error={setStatus.error} />}
          <button className="btn primary" onClick={() => setStatus.mutate(resolve)}>Resolve</button>
        </Modal>
      )}
    </Drawer>
  );
}
