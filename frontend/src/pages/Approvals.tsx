import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, useToast } from '../components/ui';
import { get, post } from '../lib/api';
import { ago } from '../lib/format';

export default function Approvals() {
  const q = useQuery({ queryKey: ['approvals'], queryFn: () => get('/api/approvals') });
  const [sel, setSel] = useState<{ kind: 'action' | 'change'; item: any } | null>(null);
  const heading = <PageHead title="Approvals" sub="Risky actions and configuration changes wait here. You cannot approve your own requests." />;
  if (q.isLoading) return <>{heading}<Loading /></>;
  if (q.error) return <>{heading}<ErrorBox error={q.error} /></>;
  const { actions, changes } = q.data;
  return (
    <>
      {heading}
      <h2 style={{ margin: '8px 0' }}>Response actions</h2>
      {actions.length === 0 ? <Empty>No actions awaiting approval.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Action</th><th>Targets</th><th>Risk</th><th>Needs</th><th>Requested by</th><th>Reason</th><th>Age</th><th /></tr></thead>
          <tbody>{actions.map((a: any) => <tr key={a.id}><td>{a.label}</td><td className="mono">{a.targets.join(', ')}</td><td><span className={`badge sev-${a.risk}`}>{a.risk}</span></td><td>{a.approvals_required}</td><td>{a.requester}</td><td className="wrap">{a.reason}</td><td>{ago(a.created_at)}</td><td><button className="btn small primary" onClick={() => setSel({ kind: 'action', item: a })}>Review</button></td></tr>)}</tbody></table></div>
      )}
      <h2 style={{ margin: '22px 0 8px' }}>Configuration changes</h2>
      {changes.length === 0 ? <Empty>No changes awaiting approval.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Change</th><th>Details</th><th>Requested by</th><th>Age</th><th /></tr></thead>
          <tbody>{changes.map((c: any) => <tr key={c.id}><td>{c.kind}</td><td className="wrap">{c.reason}</td><td>{c.requester}</td><td>{ago(c.created_at)}</td><td><button className="btn small primary" onClick={() => setSel({ kind: 'change', item: c })}>Review</button></td></tr>)}</tbody></table></div>
      )}
      {sel && <Decide sel={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function Decide({ sel, onClose }: { sel: { kind: 'action' | 'change'; item: any }; onClose: () => void }) {
  const [reason, setReason] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const m = useMutation({
    mutationFn: (decision: 'approve' | 'reject') => post(sel.kind === 'action' ? `/api/response/requests/${sel.item.id}/decision` : `/api/approvals/changes/${sel.item.id}/decision`, { decision, reason }),
    onSuccess: (_r, d) => { toast(d === 'approve' ? 'Approved' : 'Rejected'); void qc.invalidateQueries({ queryKey: ['approvals'] }); void qc.invalidateQueries({ queryKey: ['requests'] }); onClose(); },
    onError: (e: Error) => toast(e.message, true),
  });
  const it = sel.item;
  return (
    <Modal title={sel.kind === 'action' ? it.label : it.kind} onClose={onClose}>
      <dl className="kv"><dt>Requested by</dt><dd>{it.requester}</dd>{sel.kind === 'action' ? <><dt>Targets</dt><dd className="mono">{it.targets.join(', ')}</dd><dt>Risk</dt><dd>{it.risk}</dd></> : <><dt>Payload</dt><dd className="mono">{JSON.stringify(it.payload)}</dd></>}<dt>Reason</dt><dd>{it.reason}</dd></dl>
      <div style={{ marginTop: 14 }}><Field label="Your decision reason (recorded in the audit log)" id="dr"><textarea id="dr" value={reason} onChange={(e) => setReason(e.target.value)} /></Field></div>
      <div className="row"><button className="btn primary" disabled={reason.trim().length < 3 || m.isPending} onClick={() => m.mutate('approve')}>Approve</button><button className="btn danger" disabled={reason.trim().length < 3 || m.isPending} onClick={() => m.mutate('reject')}>Reject</button></div>
    </Modal>
  );
}
