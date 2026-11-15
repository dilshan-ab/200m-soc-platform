import { SavedViews } from '../components/SavedViews';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Clock, FileText, Link2, Package, Shield } from 'lucide-react';
import { useEffect, useState } from 'react';
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
  useEffect(() => { setPage(1); }, [f.status, f.severity, f.mine, f.q]);
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
        {(f.q || f.status || f.severity || f.mine) && <button className="btn" onClick={() => { setSp(new URLSearchParams(), { replace: true }); setPage(1); }}>Clear filters</button>}
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No cases match.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Resolve SLA</th><th>Sync</th><th>Created</th></tr></thead>
            <tbody>{q.data!.items.map((c) => <tr key={c.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => openCase(c.id)} onKeyDown={(e) => e.key === 'Enter' && openCase(c.id)}>
              <td className="mono">{c.number}</td><td className="wrap">{c.title}</td><td><Sev v={c.severity} /></td><td><Status v={c.status} /></td><td>{c.status === 'closed' || c.status === 'resolved' ? '—' : until(c.resolve_due)}</td><td>{c.sync_status}</td><td>{ago(c.created_at)}</td></tr>)}</tbody></table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={setPage} />
        </>
      )}
      {open && <CaseDrawer key={open} id={open} onClose={() => openCase(null)} />}
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

const KIND_ICONS: Record<string, typeof Shield> = { created: Shield, note: FileText, status: AlertTriangle, task: CheckCircle2, evidence: Package };
const KIND_COLORS: Record<string, string> = { created: 'var(--info)', note: 'var(--muted)', status: 'var(--warn)', task: 'var(--ok)', evidence: 'var(--accent)' };
const EVIDENCE_TYPES = ['file', 'screenshot', 'pcap', 'log', 'artifact', 'note'] as const;

function CaseDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['case', id], queryFn: () => get<any>(`/api/cases/${id}`) });
  const { can } = useAuth();
  const [note, setNote] = useState('');
  const [task, setTask] = useState('');
  const [obs, setObs] = useState({ type: 'ip', value: '' });
  const [resolve, setResolve] = useState<null | { status: string; resolution: string }>(null);
  const [section, setSection] = useState<'timeline' | 'evidence' | 'tasks' | 'observables'>('timeline');
  const [addEvidence, setAddEvidence] = useState(false);
  const [custodyView, setCustodyView] = useState<any>(null);
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

      <div className="tabs" style={{ marginBottom: 12, marginTop: 12 }}>
        <button className={section === 'timeline' ? 'active' : ''} onClick={() => setSection('timeline')}>Timeline ({c.timeline?.length ?? 0})</button>
        <button className={section === 'evidence' ? 'active' : ''} onClick={() => setSection('evidence')}>Evidence ({c.evidence?.length ?? 0})</button>
        <button className={section === 'tasks' ? 'active' : ''} onClick={() => setSection('tasks')}>Tasks ({c.tasks?.length ?? 0})</button>
        <button className={section === 'observables' ? 'active' : ''} onClick={() => setSection('observables')}>Observables ({c.observables?.length ?? 0})</button>
      </div>

      {section === 'timeline' && (
        <>
          {write && <div className="row" style={{ marginBottom: 8 }}><input placeholder="Add a note…" aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn small" disabled={!note.trim() || addNote.isPending} onClick={() => addNote.mutate(undefined)}>Post</button></div>}
          <div style={{ position: 'relative', paddingLeft: 24 }}>
            <div style={{ position: 'absolute', left: 8, top: 0, bottom: 0, width: 2, background: 'var(--border)' }} />
            {[...c.timeline].reverse().map((e: any) => {
              const Icon = KIND_ICONS[e.kind] || FileText;
              const color = KIND_COLORS[e.kind] || 'var(--muted)';
              return (
                <div key={e.id} style={{ position: 'relative', marginBottom: 12, paddingBottom: 4 }}>
                  <div style={{ position: 'absolute', left: -20, top: 2, width: 20, height: 20, borderRadius: '50%', background: 'var(--surface)', border: `2px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Icon size={10} style={{ color }} />
                  </div>
                  <div style={{ marginLeft: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                      <strong>{e.actor}</strong>
                      <span className="badge" style={{ fontSize: 10 }}>{e.kind}</span>
                      <span style={{ color: 'var(--muted)', marginLeft: 'auto', fontSize: 12 }}>{when(e.at)}</span>
                    </div>
                    <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, marginTop: 2 }}>{e.message}</div>
                    {e.meta && Object.keys(e.meta).length > 0 && (
                      <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                        {Object.entries(e.meta).map(([k, v]) => <span key={k} className="badge" style={{ marginRight: 4 }}>{k}: {String(v)}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          {c.alerts?.length > 0 && <><h4 style={{ marginTop: 16, marginBottom: 8 }}>Linked Alerts</h4>{c.alerts.map((a: any) => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <Link2 size={14} style={{ color: 'var(--muted)' }} /><Sev v={a.severity} /><span className="wrap">{a.title}</span><span style={{ marginLeft: 'auto', color: 'var(--muted)', fontSize: 12 }}>{ago(a.time)}</span>
            </div>
          ))}</>}
          {c.tickets?.length > 0 && <><h4 style={{ marginTop: 16, marginBottom: 8 }}>External Tickets</h4><ul>{c.tickets.map((t: any) => <li key={t.id}>{t.provider} {t.external_id} ({t.status})</li>)}</ul></>}
        </>
      )}

      {section === 'evidence' && (
        <>
          {write && can('evidence.write') && <button className="btn small" style={{ marginBottom: 8 }} onClick={() => setAddEvidence(true)}>Add evidence</button>}
          {(!c.evidence || c.evidence.length === 0) ? <Empty>No evidence collected yet.</Empty> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {c.evidence.map((e: any) => (
                <div key={e.id} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '10px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <Package size={16} style={{ color: 'var(--accent)' }} />
                    <strong>{e.name}</strong>
                    <span className="badge">{e.type}</span>
                    {e.tags?.map((t: string) => <span key={t} className="badge">{t}</span>)}
                  </div>
                  {e.description && <div style={{ fontSize: 13, color: 'var(--muted)' }}>{e.description}</div>}
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <span>Collected by {e.collected_by}</span>
                    <span>{ago(e.collected_at)}</span>
                    {e.hash_sha256 && <span className="mono">SHA256: {e.hash_sha256.slice(0, 16)}…</span>}
                    {e.file_size > 0 && <span>{(e.file_size / 1024).toFixed(1)} KB</span>}
                  </div>
                  <button className="btn small" style={{ marginTop: 6 }} onClick={() => setCustodyView(e)}>
                    Chain of custody ({e.chain_of_custody?.length ?? 0})
                  </button>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {section === 'tasks' && (
        <>
          {c.tasks.length === 0 ? <Empty>No tasks.</Empty> : <ul style={{ listStyle: 'none', padding: 0 }}>{c.tasks.map((t: any) => (
            <li key={t.id} className="row" style={{ padding: '4px 0' }}>
              <input type="checkbox" aria-label={t.title} disabled={!write} checked={t.status === 'done'} onChange={(e) => setTaskStatus.mutate({ tid: t.id, status: e.target.checked ? 'done' : 'todo' })} />
              <span style={{ textDecoration: t.status === 'done' ? 'line-through' : 'none' }}>{t.title}{t.required && ' *'}</span>
            </li>))}</ul>}
          {write && <div className="row"><input placeholder="Add task…" aria-label="New task" value={task} onChange={(e) => setTask(e.target.value)} /><button className="btn small" disabled={!task.trim() || addTask.isPending} onClick={() => addTask.mutate(undefined)}>Add</button></div>}
        </>
      )}

      {section === 'observables' && (
        <>
          {c.observables.length === 0 ? <Empty>No observables.</Empty> : <div className="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Enrichment</th><th /></tr></thead><tbody>{c.observables.map((o: any) => (
            <tr key={o.id}>
              <td>{o.type}</td>
              <td className="mono wrap">{o.value}</td>
              <td><span style={{ color: o.verdict === 'malicious' ? 'var(--bad)' : o.verdict === 'suspicious' ? 'var(--warn)' : 'var(--muted)' }}>{o.verdict ?? '—'}</span></td>
              <td>{o.enrichment && Object.keys(o.enrichment).length > 0 ? <span className="badge st-ok">enriched</span> : <span className="badge">pending</span>}</td>
              <td>{can('intel.enrich') && <button className="btn small" onClick={() => enrich.mutate(o.value)}>Enrich</button>}</td>
            </tr>))}</tbody></table></div>}
          {write && <div className="row" style={{ marginTop: 8 }}>
            <select aria-label="Observable type" value={obs.type} onChange={(e) => setObs({ ...obs, type: e.target.value })}>{['ip', 'domain', 'hash', 'url', 'user', 'email', 'host'].map((t) => <option key={t}>{t}</option>)}</select>
            <input placeholder="Value" aria-label="Observable value" value={obs.value} onChange={(e) => setObs({ ...obs, value: e.target.value })} />
            <button className="btn small" disabled={!obs.value.trim() || addObs.isPending} onClick={() => addObs.mutate(undefined)}>Add</button></div>}
        </>
      )}

      {addEvidence && <AddEvidenceModal caseId={id} onClose={() => setAddEvidence(false)} />}
      {custodyView && <CustodyModal evidence={custodyView} caseId={id} onClose={() => setCustodyView(null)} />}
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

function AddEvidenceModal({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const [v, setV] = useState({ name: '', type: 'file' as string, description: '', hash_sha256: '', tags: '' });
  const m = useAct(() => post(`/api/cases/${caseId}/evidence`, { ...v, tags: v.tags ? v.tags.split(',').map((t) => t.trim()) : [] }), ['case', 'cases'], 'Evidence added', onClose);
  return (
    <Modal title="Add evidence" onClose={onClose}>
      <Field label="Name" id="en"><input id="en" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="Evidence name" /></Field>
      <div className="grid cols-2">
        <Field label="Type" id="et"><select id="et" value={v.type} onChange={(e) => setV({ ...v, type: e.target.value })}>{EVIDENCE_TYPES.map((t) => <option key={t}>{t}</option>)}</select></Field>
        <Field label="SHA-256 hash" id="eh"><input id="eh" className="mono" value={v.hash_sha256} onChange={(e) => setV({ ...v, hash_sha256: e.target.value })} placeholder="Optional" /></Field>
      </div>
      <Field label="Description" id="ed"><textarea id="ed" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      <Field label="Tags (comma-separated)" id="etg"><input id="etg" value={v.tags} onChange={(e) => setV({ ...v, tags: e.target.value })} placeholder="malware, phishing" /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={!v.name.trim() || m.isPending} onClick={() => m.mutate(undefined)}>Add evidence</button>
    </Modal>
  );
}

function CustodyModal({ evidence, caseId, onClose }: { evidence: any; caseId: string; onClose: () => void }) {
  const [action, setAction] = useState('');
  const [custodyNote, setCustodyNote] = useState('');
  const addCustody = useAct(() => post(`/api/cases/${caseId}/evidence/${evidence.id}/custody`, { action, note: custodyNote }), ['case', 'cases'], 'Custody entry added', () => { setAction(''); setCustodyNote(''); });
  const { can } = useAuth();
  const currentCase = useQuery({ queryKey: ['case', caseId], queryFn: () => get<any>(`/api/cases/${caseId}`) });
  const currentEvidence = currentCase.data?.evidence?.find((item: any) => item.id === evidence.id) ?? evidence;
  const chain = currentEvidence.chain_of_custody || [];
  return (
    <Modal title={`Chain of custody: ${evidence.name}`} onClose={onClose}>
      {evidence.hash_sha256 && <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--surface)', borderRadius: 6 }}><small style={{ color: 'var(--muted)' }}>SHA-256</small><div className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{evidence.hash_sha256}</div></div>}
      <div style={{ position: 'relative', paddingLeft: 20, marginBottom: 16 }}>
        <div style={{ position: 'absolute', left: 6, top: 0, bottom: 0, width: 2, background: 'var(--border)' }} />
        {chain.map((entry: any, i: number) => (
          <div key={i} style={{ position: 'relative', marginBottom: 10, paddingBottom: 4 }}>
            <div style={{ position: 'absolute', left: -17, top: 4, width: 12, height: 12, borderRadius: '50%', background: i === 0 ? 'var(--accent)' : 'var(--border)' }} />
            <div style={{ marginLeft: 8 }}>
              <div style={{ fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
                <strong>{entry.actor}</strong>
                <span className="badge">{entry.action}</span>
                <span style={{ color: 'var(--muted)', fontSize: 12, marginLeft: 'auto' }}><Clock size={10} style={{ verticalAlign: -1 }} /> {ago(entry.at)}</span>
              </div>
              {entry.note && <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>{entry.note}</div>}
            </div>
          </div>
        ))}
      </div>
      {can('evidence.write') && <div className="row" style={{ gap: 6 }}>
        <select aria-label="Action" value={action} onChange={(e) => setAction(e.target.value)} style={{ flex: 1 }}>
          <option value="">Select action…</option>
          {['accessed', 'transferred', 'analyzed', 'copied', 'archived', 'exported', 'verified'].map((a) => <option key={a}>{a}</option>)}
        </select>
        <input placeholder="Note (optional)" aria-label="Note" value={custodyNote} onChange={(e) => setCustodyNote(e.target.value)} style={{ flex: 2 }} />
        <button className="btn small" disabled={!action || addCustody.isPending} onClick={() => addCustody.mutate(undefined)}>Add</button>
      </div>}
      {addCustody.error && <ErrorBox error={addCustody.error} />}
    </Modal>
  );
}
