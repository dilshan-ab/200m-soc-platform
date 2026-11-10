import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager } from '../components/ui';
import { get, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Compliance() {
  const [fw, setFw] = useState('');
  const [status, setStatus] = useState('fail');
  const [page, setPage] = useState(1);
  const [exc, setExc] = useState<any>(null);
  const { can } = useAuth();
  const sum = useQuery({ queryKey: ['compliance-summary'], queryFn: () => get<any[]>('/api/compliance/summary') });
  const ctl = useQuery({ queryKey: ['controls', fw, status, page], queryFn: () => get<Page<any>>('/api/compliance/controls', { framework: fw, status, page, limit: 100 }) });
  const exs = useQuery({ queryKey: ['exceptions'], queryFn: () => get<any[]>('/api/compliance/exceptions') });
  return (
    <>
      <PageHead title="Compliance" sub="Control results from Wazuh SCA, scored per framework." />
      {sum.isLoading ? <Loading /> : sum.error ? <ErrorBox error={sum.error} /> : sum.data!.length === 0 ? <Empty>No compliance data yet. Enable the Wazuh integration to start collecting.</Empty> : (
        <div className="grid cols-4" style={{ marginBottom: 14 }}>{sum.data!.map((s) => (
          <button key={s.framework} className="stat" style={{ textAlign: 'left', cursor: 'pointer' }} onClick={() => { setFw(s.framework === fw ? '' : s.framework); setPage(1); }} aria-pressed={fw === s.framework}>
            <span className="label">{s.framework}</span><span className="value">{s.score}%</span><span style={{ color: 'var(--muted)' }}>{s.pass} pass · {s.fail} fail</span></button>))}</div>
      )}
      <div className="filters">
        <select aria-label="Result" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}><option value="">All results</option><option value="fail">Failing</option><option value="pass">Passing</option><option value="unknown">Unknown</option></select>
        {fw && <button className="btn small" onClick={() => setFw('')}>Clear framework: {fw} ✕</button>}
      </div>
      {ctl.isLoading ? <Loading /> : ctl.error ? <ErrorBox error={ctl.error} /> : ctl.data!.items.length === 0 ? <Empty>No controls match.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Result</th><th>Source</th><th>Checked</th><th /></tr></thead>
            <tbody>{ctl.data!.items.map((c) => <tr key={c.id}><td>{c.framework}</td><td className="mono">{c.control_id}</td><td className="wrap">{c.title}</td><td>{c.status}</td><td>{c.source}</td><td>{ago(c.checked_at)}</td>
              <td>{can('compliance.write') && c.status === 'fail' && <button className="btn small" onClick={() => setExc(c)}>Add exception</button>}</td></tr>)}</tbody></table></div>
          <Pager page={page} limit={100} total={ctl.data!.total} set={setPage} />
        </>
      )}
      <h2 style={{ margin: '22px 0 8px' }}>Approved exceptions</h2>
      {exs.data && exs.data.length > 0 ? (
        <div className="table-wrap"><table><thead><tr><th>Framework</th><th>Control</th><th>Reason</th><th>Approved by</th><th>Expires</th></tr></thead><tbody>{exs.data.map((e) => <tr key={e.id}><td>{e.framework}</td><td className="mono">{e.control_id}</td><td className="wrap">{e.reason}</td><td>{e.approved_by}</td><td>{when(e.expires_at)}</td></tr>)}</tbody></table></div>
      ) : <Empty>No exceptions.</Empty>}
      {exc && <Exception c={exc} onClose={() => setExc(null)} />}
    </>
  );
}

function Exception({ c, onClose }: { c: any; onClose: () => void }) {
  const [reason, setReason] = useState('');
  const [days, setDays] = useState(30);
  const m = useAct(() => post('/api/compliance/exceptions', { framework: c.framework, control_id: c.control_id, asset_id: c.asset_id, reason, expires_at: new Date(Date.now() + days * 86400000).toISOString() }), ['exceptions'], 'Exception recorded', onClose);
  return (
    <Modal title={`Exception · ${c.control_id}`} onClose={onClose}>
      <p>{c.title}</p>
      <Field label="Reason (min 10 characters)" id="er"><textarea id="er" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
      <Field label="Expires in (days)" id="ed"><input id="ed" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={reason.trim().length < 10 || days < 1 || m.isPending} onClick={() => m.mutate(undefined)}>Record exception</button>
    </Modal>
  );
}
