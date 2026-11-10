import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, SearchBox, Sev } from '../components/ui';
import { get, patch, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { SEVERITIES, titleCase, until } from '../lib/format';
import { useAct } from '../lib/mut';

const STATUSES = ['open', 'in_progress', 'remediated', 'accepted_risk', 'false_positive'];

export default function Vulnerabilities() {
  const [page, setPage] = useState(1);
  const [params] = useSearchParams();
  const [f, setF] = useState(() => ({ q: '', severity: params.get('severity') ?? '', status: params.get('status') ?? 'open' }));
  const [edit, setEdit] = useState<any>(null);
  const { can } = useAuth();
  const sum = useQuery({ queryKey: ['vuln-summary'], queryFn: () => get<any>('/api/vulnerabilities/summary') });
  const q = useQuery({ queryKey: ['vulns', f, page], queryFn: () => get<Page<any>>('/api/vulnerabilities', { q: f.q, severity: f.severity ? [f.severity] : [], status: f.status ? [f.status] : [], page, limit: 50 }) });
  const open = (s: string) => Object.entries(sum.data?.by_severity?.[s] ?? {}).filter(([k]) => k === 'open' || k === 'in_progress').reduce((n, [, v]) => n + (v as number), 0);
  const upd = (k: string, v: string) => { setF({ ...f, [k]: v }); setPage(1); };
  return (
    <>
      <PageHead title="Vulnerabilities" sub="Findings merged from OpenVAS and Wazuh, tracked to remediation deadlines." />
      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        {SEVERITIES.filter((s) => s !== 'info').map((s) => <div key={s} className="stat"><span className="label">{titleCase(s)} open</span><span className="value">{sum.data ? open(s) : "—"}</span></div>)}
        <div className="stat"><span className="label">Overdue</span><span className="value">{sum.data?.overdue ?? "—"}</span></div>
      </div>
      <div className="filters">
        <SearchBox value={f.q} onChange={(v) => upd('q', v)} placeholder="CVE or title…" label="Search findings" />
        <select aria-label="Severity" value={f.severity} onChange={(e) => upd('severity', e.target.value)}><option value="">Any severity</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Status" value={f.status} onChange={(e) => upd('status', e.target.value)}><option value="">Any status</option>{STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</select>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No findings match.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Component</th><th>Status</th><th>Deadline</th><th /></tr></thead>
            <tbody>{q.data!.items.map((x) => <tr key={x.id}><td className="mono">{x.vuln_id}</td><td className="wrap">{x.title}</td><td><Sev v={x.severity} /></td><td>{x.cvss != null ? Number(x.cvss).toFixed(1) : '—'}</td><td>{x.component}</td><td>{titleCase(x.status)}</td><td>{x.status === 'open' || x.status === 'in_progress' ? until(x.deadline) : '—'}</td>
              <td>{can('vulns.write') && <button className="btn small" onClick={() => setEdit(x)}>Update</button>}</td></tr>)}</tbody></table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={setPage} />
        </>
      )}
      {edit && <Update f={edit} onClose={() => setEdit(null)} />}
    </>
  );
}

function Update({ f, onClose }: { f: any; onClose: () => void }) {
  const [status, setStatus] = useState(f.status);
  const [owner, setOwner] = useState(f.owner ?? '');
  const [note, setNote] = useState('');
  const m = useAct(() => patch(`/api/vulnerabilities/${f.id}`, { status, owner: owner || null, note }), ['vulns', 'vuln-summary'], 'Finding updated', onClose);
  const needNote = status === 'accepted_risk' || status === 'false_positive';
  return (
    <Modal title={f.vuln_id} onClose={onClose}>
      <p>{f.title}</p>
      <Field label="Status" id="vs"><select id="vs" value={status} onChange={(e) => setStatus(e.target.value)}>{STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</select></Field>
      <Field label="Owner" id="vo"><input id="vo" value={owner} onChange={(e) => setOwner(e.target.value)} /></Field>
      <Field label={needNote ? 'Justification (required)' : 'Note'} id="vn"><textarea id="vn" value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || (needNote && note.trim().length < 5)} onClick={() => m.mutate(undefined)}>Save</button>
    </Modal>
  );
}
