import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Summary } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Sev, Status } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, SEVERITIES, titleCase } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type Technique = { id: string; name: string };
type HuntQuery = { q?: string; host?: string; severities?: string[]; days?: number; technique_ids?: string[] };
type AlertRow = { id: string; title: string; severity: string; status: string; host: string; time: string | null };
type HuntRow = {
  id: string; name: string; kind: 'search' | 'collection'; status: string; hypothesis: string; technique_ids: string[];
  query: HuntQuery; match_count: number; verdict: string; case_id: string | null; artifact: string; targets: string[];
  created_at: string; concluded_at: string | null;
};
type HuntDetail = HuntRow & { conclusion_note: string; results: AlertRow[] };

function queryLabel(q: HuntQuery): string {
  return [q.q && `“${q.q}”`, q.host && `host: ${q.host}`, q.severities?.length ? `severity: ${q.severities.join('/')}` : '', `last ${q.days ?? 30}d`]
    .filter(Boolean).join(' · ');
}

export default function ThreatHunting() {
  const { can } = useAuth();
  const hunts = useQuery({ queryKey: ['hunts'], queryFn: () => get<HuntRow[]>('/api/hunts'), refetchInterval: REFRESH_MS });
  const [newSearch, setNewSearch] = useState(false);
  const [newCollect, setNewCollect] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const rows = hunts.data ?? [];
  const active = rows.filter((h) => h.status !== 'concluded' && h.status !== 'rejected' && h.status !== 'cancelled');
  const concluded = rows.filter((h) => h.status === 'concluded');
  const confirmed = concluded.filter((h) => h.verdict === 'true_positive').length;

  return (
    <>
      <PageHead title="Threat hunting" sub="Hypothesis-driven hunts over the alerts you already have, mapped to MITRE ATT&CK." eyebrow="OPERATIONS">
        {can('hunts.request') && <>
          <button className="btn" onClick={() => setNewCollect(true)}>Request artifact collection</button>
          <button className="btn primary" onClick={() => setNewSearch(true)}>New hunt</button>
        </>}
      </PageHead>
      {rows.length > 0 && <Summary items={[
        { label: 'Active hunts', value: active.length },
        { label: 'Concluded', value: concluded.length },
        { label: 'Confirmed findings', value: confirmed, tone: confirmed ? 'bad' : 'ok' },
      ]} />}
      {hunts.isLoading ? <Loading /> : hunts.error ? <ErrorBox error={hunts.error} /> : rows.length === 0 ? (
        <Empty>No hunts yet. Start from a hypothesis — pick a technique you suspect is in play and search the alerts already in the platform.</Empty>
      ) : (
        <div className="table-wrap"><table>
          <thead><tr><th>Hunt</th><th>Kind</th><th>Status</th><th>Matches</th><th>Verdict</th><th>Created</th></tr></thead>
          <tbody>{rows.map((h) => (
            <tr key={h.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(h.id)} onKeyDown={(e) => e.key === 'Enter' && setSel(h.id)}>
              <td>{h.name}</td>
              <td>{h.kind === 'search' ? 'Search' : 'Artifact collection'}</td>
              <td><Status v={h.status} /></td>
              <td>{h.kind === 'search' ? h.match_count : h.targets.length}</td>
              <td>{h.verdict ? titleCase(h.verdict) : '—'}</td>
              <td>{ago(h.created_at)}</td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      {sel && <HuntDrawer id={sel} onClose={() => setSel(null)} />}
      {newSearch && <NewSearchHunt onClose={() => setNewSearch(false)} onDone={(id) => { setNewSearch(false); setSel(id); }} />}
      {newCollect && <NewCollectionHunt onClose={() => setNewCollect(false)} />}
    </>
  );
}

function TechniquePicker({ techniques, value, onChange }: { techniques: Technique[]; value: string[]; onChange: (v: string[]) => void }) {
  const [q, setQ] = useState('');
  const term = q.trim().toLowerCase();
  const matches = term ? techniques.filter((t) => !value.includes(t.id) && (t.id.toLowerCase().includes(term) || t.name.toLowerCase().includes(term))).slice(0, 8) : [];
  return (
    <div>
      {value.length > 0 && <div className="row" style={{ flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
        {value.map((id) => {
          const t = techniques.find((x) => x.id === id);
          return (
            <span key={id} className="badge">
              {id}{t ? ` · ${t.name}` : ''}{' '}
              <button type="button" aria-label={`Remove ${id}`} onClick={() => onChange(value.filter((v) => v !== id))} style={{ border: 0, background: 'none', cursor: 'pointer', color: 'inherit', padding: 0 }}>×</button>
            </span>
          );
        })}
      </div>}
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search techniques, e.g. T1059 or PowerShell" />
      {matches.length > 0 && (
        <div className="card" style={{ marginTop: 6, padding: 6, display: 'grid', gap: 2 }}>
          {matches.map((t) => (
            <button key={t.id} type="button" className="btn small" style={{ textAlign: 'left' }} onClick={() => { onChange([...value, t.id]); setQ(''); }}>
              <code>{t.id}</code> {t.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function NewSearchHunt({ onClose, onDone }: { onClose: () => void; onDone: (id: string) => void }) {
  const techniques = useQuery({ queryKey: ['mitre-techniques'], queryFn: () => get<{ techniques: Technique[] }>('/api/mitre/techniques') });
  const [name, setName] = useState('');
  const [hypothesis, setHypothesis] = useState('');
  const [techniqueIds, setTechniqueIds] = useState<string[]>([]);
  const [q, setQ] = useState('');
  const [host, setHost] = useState('');
  const [severities, setSeverities] = useState<string[]>([]);
  const [days, setDays] = useState(30);
  const create = useAct(() => post('/api/hunts/search', {
    name, hypothesis, query: { q: q.trim(), host: host.trim(), severities, days, technique_ids: techniqueIds },
  }), ['hunts'], 'Hunt created', (r) => onDone(r.id));

  return (
    <Modal title="New hunt" onClose={onClose} wide>
      <p style={{ color: 'var(--muted)' }}>Runs immediately against alerts already in the platform — no connected tool required.</p>
      <div className="grid cols-2">
        <Field label="Name *" id="hn"><input id="hn" value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Time range" id="hd"><select id="hd" className="select" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[7, 30, 90].map((n) => <option key={n} value={n}>Last {n} days</option>)}
        </select></Field>
      </div>
      <Field label="Hypothesis" id="hh" hint="What are you looking for, and why do you think it's happening?">
        <textarea id="hh" value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} />
      </Field>
      <Field label="MITRE ATT&CK techniques" id="ht">
        <TechniquePicker techniques={techniques.data?.techniques ?? []} value={techniqueIds} onChange={setTechniqueIds} />
      </Field>
      <div className="grid cols-2">
        <Field label="Keyword" id="hq" hint="Matches title, description, host or source IP"><input id="hq" value={q} onChange={(e) => setQ(e.target.value)} /></Field>
        <Field label="Host" id="hhost"><input id="hhost" value={host} onChange={(e) => setHost(e.target.value)} /></Field>
      </div>
      <Field label="Severity" id="hsev">
        <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          {SEVERITIES.map((s) => (
            <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 13 }}>
              <input type="checkbox" checked={severities.includes(s)} onChange={(e) => setSeverities(e.target.checked ? [...severities, s] : severities.filter((x) => x !== s))} />
              {titleCase(s)}
            </label>
          ))}
        </div>
      </Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || name.trim().length < 3} onClick={() => create.mutate(undefined)}>Run hunt</button>
    </Modal>
  );
}

function ConcludeModal({ id, onClose }: { id: string; onClose: () => void }) {
  const [verdict, setVerdict] = useState('true_positive');
  const [note, setNote] = useState('');
  const m = useAct(() => post(`/api/hunts/${id}/conclude`, { verdict, note }), ['hunt', 'hunts'], 'Hunt concluded', onClose);
  return (
    <Modal title="Conclude hunt" onClose={onClose}>
      <Field label="Verdict" id="cv"><select id="cv" className="select" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
        <option value="true_positive">True positive</option>
        <option value="false_positive">False positive</option>
        <option value="inconclusive">Inconclusive</option>
      </select></Field>
      <Field label="Notes" id="cn"><textarea id="cn" value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending} onClick={() => m.mutate(undefined)}>Conclude</button>
    </Modal>
  );
}

function HuntDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ['hunt', id], queryFn: () => get<HuntDetail>(`/api/hunts/${id}`) });
  const run = useAct(() => post(`/api/hunts/${id}/run`), ['hunt', 'hunts'], 'Hunt re-run');
  const escalate = useAct(() => post(`/api/hunts/${id}/escalate`, {}), ['hunt', 'hunts'], 'Case created');
  const [conclude, setConclude] = useState(false);
  if (q.isLoading) return <Drawer title="Hunt" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Hunt" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const h = q.data!;
  const isSearch = h.kind === 'search';
  return (
    <Drawer title={h.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 10, flexWrap: 'wrap' }}>
        <Status v={h.status} />{h.verdict && <span className="badge">{titleCase(h.verdict)}</span>}<span className="spacer" /><small>{ago(h.created_at)}</small>
      </div>
      {h.hypothesis && <p>{h.hypothesis}</p>}
      {h.technique_ids.length > 0 && <div className="row" style={{ flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
        {h.technique_ids.map((t) => <span key={t} className="badge mono">{t}</span>)}
      </div>}
      {isSearch ? (
        <>
          <dl className="kv">
            <dt>Query</dt><dd className="wrap">{queryLabel(h.query)}</dd>
            <dt>Matches</dt><dd>{h.match_count}</dd>
            {h.case_id && <><dt>Escalated to</dt><dd><Link to={`/app/cases?open=${h.case_id}`}>View case <ArrowUpRight size={14} style={{ verticalAlign: -2 }} /></Link></dd></>}
          </dl>
          <h3 style={{ marginTop: 14 }}>Matched alerts</h3>
          {h.results.length === 0 ? <div className="empty">No matches for this query.</div> : (
            <ul className="attack-alerts">{h.results.map((a) => (
              <li key={a.id}>
                <Link to={`/app/alerts?open=${encodeURIComponent(a.id)}`}>
                  <strong>{a.title}</strong><ArrowUpRight size={16} aria-hidden="true" />
                  <span>{a.host || 'Unknown host'}{a.time && ` · ${ago(a.time)}`}</span>
                  <div><Sev v={a.severity} /> <Status v={a.status} /></div>
                </Link>
              </li>
            ))}</ul>
          )}
        </>
      ) : (
        <dl className="kv">
          <dt>Artifact</dt><dd className="mono">{h.artifact}</dd>
          <dt>Targets</dt><dd className="mono wrap">{h.targets.join(', ')}</dd>
        </dl>
      )}
      {h.status === 'concluded' && h.conclusion_note && <><h3 style={{ marginTop: 14 }}>Conclusion</h3><p>{h.conclusion_note}</p></>}
      {run.error && <ErrorBox error={run.error} />}
      {escalate.error && <ErrorBox error={escalate.error} />}
      {can('hunts.request') && isSearch && h.status !== 'concluded' && (
        <div className="row" style={{ marginTop: 14, flexWrap: 'wrap' }}>
          <button className="btn small" onClick={() => run.mutate(undefined)} disabled={run.isPending}>Re-run</button>
          {can('cases.write') && h.match_count > 0 && !h.case_id && <button className="btn small" onClick={() => escalate.mutate(undefined)} disabled={escalate.isPending}>Escalate to case</button>}
          <button className="btn small primary" onClick={() => setConclude(true)}>Conclude</button>
        </div>
      )}
      {conclude && <ConcludeModal id={id} onClose={() => setConclude(false)} />}
    </Drawer>
  );
}

function NewCollectionHunt({ onClose }: { onClose: () => void }) {
  const arts = useQuery({ queryKey: ['hunt-artifacts'], queryFn: () => get<{ artifacts: string[] }>('/api/hunts/artifacts') });
  const [v, setV] = useState({ name: '', artifact: '', targets: '', reason: '' });
  const m = useAct(() => post('/api/hunts', { name: v.name, artifact: v.artifact, targets: v.targets.split(/[\s,]+/).filter(Boolean), reason: v.reason }), ['hunts', 'approvals'], 'Hunt requested; awaiting approval', onClose);
  const list = arts.data?.artifacts ?? [];
  return (
    <Modal title="Request artifact collection" onClose={onClose}>
      <p style={{ color: 'var(--muted)' }}>Dispatches a Velociraptor artifact pull. Requires a second admin's approval.</p>
      <Field label="Name" id="hcn"><input id="hcn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Artifact" id="hca" hint={list.length ? undefined : 'No artifacts are allowed yet. Enable Velociraptor and allow artifacts first.'}>
        <select id="hca" value={v.artifact} onChange={(e) => setV({ ...v, artifact: e.target.value })}><option value="">Select…</option>{list.map((a) => <option key={a}>{a}</option>)}</select></Field>
      <Field label="Targets (hostnames, comma or space separated)" id="hct"><input id="hct" value={v.targets} onChange={(e) => setV({ ...v, targets: e.target.value })} /></Field>
      <Field label="Reason" id="hcr"><textarea id="hcr" value={v.reason} onChange={(e) => setV({ ...v, reason: e.target.value })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !v.artifact || !v.targets.trim() || v.name.trim().length < 3 || v.reason.trim().length < 5} onClick={() => m.mutate(undefined)}>Submit for approval</button>
    </Modal>
  );
}
