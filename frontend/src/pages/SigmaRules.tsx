import { useQuery } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, SearchBox, Status } from '../components/ui';
import { del, get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { SEVERITIES, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';

type RuleRow = {
  id: string; sigma_id: string; title: string; status: string; level: string;
  log_source: { product?: string; service?: string; category?: string };
  technique_ids: string[]; enabled: boolean; created_at: string; updated_at: string;
};
type RuleDetail = RuleRow & { description: string; tags: string[]; references: string[]; false_positives: string[]; raw_yaml: string };

const STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];
const number = new Intl.NumberFormat();

function logSourceLabel(ls: RuleRow['log_source']): string {
  return [ls.product, ls.category, ls.service].filter(Boolean).join(' · ') || '—';
}

export default function SigmaRules() {
  const { can } = useAuth();
  const [sp, setSp] = useSearchParams();
  const technique = sp.get('technique') ?? '';
  const [status, setStatus] = useState('');
  const [level, setLevel] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const [importOpen, setImportOpen] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const keys = ['sigma-rules'];
  const rules = useQuery({
    queryKey: ['sigma-rules', technique, status, level, q, page],
    queryFn: () => get<Page<RuleRow>>('/api/sigma/rules', { technique_id: technique || undefined, status: status || undefined, level: level || undefined, q: q || undefined, page, limit: 25 }),
  });

  function clearTechnique() {
    sp.delete('technique');
    setSp(sp, { replace: true });
  }

  return (
    <>
      <PageHead title="Detection rules" sub="Sigma rules mapped to MITRE ATT&CK — import rule content, track coverage, retire what's stale." eyebrow="THREAT INTELLIGENCE">
        {can('detections.write') && <button className="btn primary" onClick={() => setImportOpen(true)}><Upload size={16} />Import rules</button>}
      </PageHead>
      <div className="attack-filters" style={{ padding: 0, marginBottom: 14 }}>
        <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Title or description" label="Search rules" />
        <label>Status
          <select className="select" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="">Any status</option>
            {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </select>
        </label>
        <label>Level
          <select className="select" value={level} onChange={(e) => { setLevel(e.target.value); setPage(1); }}>
            <option value="">Any level</option>
            {['informational', ...SEVERITIES].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </select>
        </label>
      </div>
      {technique && (
        <div className="row" style={{ marginBottom: 14 }}>
          <span className="badge mono">{technique}</span>
          <button className="btn small" onClick={clearTechnique}>Clear technique filter</button>
        </div>
      )}
      {rules.isLoading ? <Loading /> : rules.error ? <ErrorBox error={rules.error} /> : rules.data!.items.length === 0 ? (
        <Empty>{technique ? `No detection rules reference ${technique} yet.` : 'No detection rules imported yet.'}</Empty>
      ) : (
        <>
          <div className="table-wrap"><table>
            <thead><tr><th>Title</th><th>Level</th><th>Status</th><th>Log source</th><th>Techniques</th><th>Updated</th></tr></thead>
            <tbody>{rules.data!.items.map((r) => (
              <tr key={r.id} tabIndex={0} style={{ cursor: 'pointer', opacity: r.enabled ? 1 : 0.55 }} onClick={() => setSelected(r.id)} onKeyDown={(e) => e.key === 'Enter' && setSelected(r.id)}>
                <td>{r.title}{!r.enabled && <small style={{ display: 'block', color: 'var(--muted)' }}>Disabled</small>}</td>
                <td><span className={`badge sev-${r.level === 'informational' ? 'info' : r.level}`}>{titleCase(r.level)}</span></td>
                <td><Status v={r.status} /></td>
                <td>{logSourceLabel(r.log_source)}</td>
                <td className="mono wrap">{r.technique_ids.join(', ') || '—'}</td>
                <td>{when(r.updated_at)}</td>
              </tr>
            ))}</tbody>
          </table></div>
          <Pager page={page} limit={rules.data!.limit} total={rules.data!.total} set={setPage} />
        </>
      )}
      {selected && <RuleDrawer id={selected} keys={keys} onClose={() => setSelected(null)} />}
      {importOpen && <ImportModal keys={keys} onClose={() => setImportOpen(false)} />}
    </>
  );
}

function RuleDrawer({ id, keys, onClose }: { id: string; keys: string[]; onClose: () => void }) {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ['sigma-rule', id], queryFn: () => get<RuleDetail>(`/api/sigma/rules/${id}`) });
  const toggle = useAct((enabled: boolean) => patch(`/api/sigma/rules/${id}`, { enabled }), [...keys, 'sigma-rule'], undefined);
  const setStatus = useAct((status: string) => patch(`/api/sigma/rules/${id}`, { status }), [...keys, 'sigma-rule']);
  const remove = useAct(() => del(`/api/sigma/rules/${id}`), keys, 'Rule deleted', onClose);
  if (q.isLoading) return <Drawer title="Detection rule" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Detection rule" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const r = q.data!;
  return (
    <Drawer title={r.title} onClose={onClose}>
      <div className="row" style={{ marginBottom: 10, flexWrap: 'wrap' }}>
        <span className={`badge sev-${r.level === 'informational' ? 'info' : r.level}`}>{titleCase(r.level)}</span>
        <Status v={r.status} />
        {!r.enabled && <span className="badge">Disabled</span>}
      </div>
      {r.description && <p>{r.description}</p>}
      <dl className="kv">
        <dt>Log source</dt><dd>{logSourceLabel(r.log_source)}</dd>
        <dt>Techniques</dt><dd className="mono wrap">{r.technique_ids.join(', ') || '—'}</dd>
        {r.references.length > 0 && <><dt>References</dt><dd>{r.references.map((ref) => <a key={ref} href={ref} target="_blank" rel="noreferrer" style={{ display: 'block' }}>{ref}</a>)}</dd></>}
        {r.false_positives.length > 0 && <><dt>Known false positives</dt><dd>{r.false_positives.join('; ')}</dd></>}
      </dl>
      <h3 style={{ marginTop: 14 }}>Raw rule</h3>
      <pre className="mono" style={{ whiteSpace: 'pre-wrap', maxHeight: '40vh', overflow: 'auto', padding: 10, background: 'var(--soft)', borderRadius: 8 }}>{r.raw_yaml}</pre>
      {toggle.error && <ErrorBox error={toggle.error} />}
      {setStatus.error && <ErrorBox error={setStatus.error} />}
      {remove.error && <ErrorBox error={remove.error} />}
      {can('detections.write') && (
        <div className="row" style={{ marginTop: 14, flexWrap: 'wrap' }}>
          <button className="btn small" disabled={toggle.isPending} onClick={() => toggle.mutate(!r.enabled)}>{r.enabled ? 'Disable' : 'Enable'}</button>
          <select className="select" value={r.status} disabled={setStatus.isPending} onChange={(e) => setStatus.mutate(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </select>
          <button className="btn small danger" onClick={() => { if (confirm(`Delete “${r.title}”? This can't be undone.`)) remove.mutate(undefined); }}>Delete</button>
        </div>
      )}
    </Drawer>
  );
}

function ImportModal({ keys, onClose }: { keys: string[]; onClose: () => void }) {
  const [yaml, setYaml] = useState('');
  const [result, setResult] = useState<{ imported: number; duplicates: string[]; skipped: string[] } | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const run = useAct(() => post('/api/sigma/rules/import', { yaml }), keys, undefined, (r) => setResult(r));

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then(setYaml);
  }

  return (
    <Modal title="Import Sigma rules" onClose={onClose} wide>
      <p style={{ color: 'var(--muted)' }}>Paste one rule or a <code>---</code>-separated collection. MITRE ATT&CK technique IDs are extracted automatically from <code>attack.t####</code> tags.</p>
      <div className="row" style={{ marginBottom: 8 }}>
        <button type="button" className="btn small" onClick={() => fileInput.current?.click()}><Upload size={14} /> Upload .yml file</button>
        <input ref={fileInput} type="file" accept=".yml,.yaml" hidden onChange={onFile} />
      </div>
      <Field label="Sigma YAML" id="sy"><textarea id="sy" rows={14} className="mono" value={yaml} onChange={(e) => setYaml(e.target.value)} placeholder="title: ...\nlogsource:\n  product: windows\ndetection:\n  ..." /></Field>
      {run.error && <ErrorBox error={run.error} />}
      {result && (
        <div className="notice">
          <b>{number.format(result.imported)} rule{result.imported === 1 ? '' : 's'} imported.</b>
          {result.duplicates.length > 0 && <p>Skipped as duplicates: {result.duplicates.join(', ')}</p>}
          {result.skipped.length > 0 && <p>Could not parse: {result.skipped.join('; ')}</p>}
        </div>
      )}
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn primary" disabled={run.isPending || yaml.trim().length < 10} onClick={() => { setResult(null); run.mutate(undefined); }}>Import</button>
        <button className="btn" onClick={onClose}>{result ? 'Done' : 'Cancel'}</button>
      </div>
    </Modal>
  );
}
