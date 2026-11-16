import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, useToast } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';

export default function Approvals() {
  const { me } = useAuth();
  const owner = me?.role === 'superadmin';
  const q = useQuery({ queryKey: ['approvals'], queryFn: () => get('/api/approvals') });
  const [sel, setSel] = useState<{ kind: 'action' | 'change'; item: any } | null>(null);
  const heading = <PageHead title="Approvals" sub={owner ? 'Your super-admin changes apply directly. You can apply or reject existing requests, including your own, after MFA confirmation.' : 'Risky actions and configuration changes wait here. Your own requests need another approver.'} />;
  if (q.isLoading) return <>{heading}<Loading /></>;
  if (q.error) return <>{heading}<ErrorBox error={q.error} /></>;
  const { actions, changes } = q.data;
  return (
    <>
      {heading}
      <h2 style={{ margin: '8px 0' }}>Response actions</h2>
      {actions.length === 0 ? <Empty>No actions awaiting approval.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Action</th><th>Targets</th><th>Risk</th><th>Needs</th><th>Requested by</th><th>Reason</th><th>Age</th><th /></tr></thead>
          <tbody>{actions.map((a: any) => <tr key={a.id}><td>{a.label}</td><td className="mono">{a.targets.join(', ')}</td><td><span className={`badge sev-${a.risk}`}>{a.risk}</span></td><td>{owner ? 'Super-admin override' : a.approvals_required}</td><td>{a.requester}</td><td className="wrap">{a.reason}</td><td>{ago(a.created_at)}</td><td><button className="btn small primary" disabled={!owner && a.requester_id === me?.id} onClick={() => setSel({ kind: 'action', item: a })}>{!owner && a.requester_id === me?.id ? 'Awaiting another approver' : 'Review'}</button></td></tr>)}</tbody></table></div>
      )}
      <h2 style={{ margin: '22px 0 8px' }}>Configuration changes</h2>
      {changes.length === 0 ? <Empty>No changes awaiting approval.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Change</th><th>Details</th><th>Requested by</th><th>Age</th><th /></tr></thead>
          <tbody>{changes.map((c: any) => <tr key={c.id}><td>{c.kind}</td><td className="wrap">{c.reason}</td><td>{c.requester}</td><td>{ago(c.created_at)}</td><td><button className="btn small primary" disabled={!owner && c.requester_id === me?.id} onClick={() => setSel({ kind: 'change', item: c })}>{!owner && c.requester_id === me?.id ? 'Awaiting another approver' : 'Review'}</button></td></tr>)}</tbody></table></div>
      )}
      {sel && <Decide sel={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function Decide({ sel, onClose }: { sel: { kind: 'action' | 'change'; item: any }; onClose: () => void }) {
  const owner = useAuth().me?.role === 'superadmin';
  const [reason, setReason] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const m = useMutation({
    mutationFn: (decision: 'approve' | 'reject') => post(sel.kind === 'action' ? `/api/response/requests/${sel.item.id}/decision` : `/api/approvals/changes/${sel.item.id}/decision`, { decision, reason }),
    onSuccess: (r) => { toast(r.status === 'failed' ? r.decision_reason || 'The change could not be applied' : r.status === 'applied' ? 'Change applied' : r.status === 'approved' ? 'Action queued' : r.status === 'rejected' ? 'Request rejected' : 'Decision recorded; awaiting another approver', r.status === 'failed'); ['approvals', 'requests', 'users', 'tools', 'retention'].forEach((key) => void qc.invalidateQueries({ queryKey: [key] })); onClose(); },
    onError: (e: Error) => toast(e.message, true),
  });
  const it = sel.item;
  return (
    <Modal title={sel.kind === 'action' ? it.label : it.kind} onClose={onClose}>
      <dl className="kv"><dt>Requested by</dt><dd>{it.requester}</dd>{sel.kind === 'action' ? <><dt>Targets</dt><dd className="mono">{it.targets.join(', ')}</dd><dt>Risk</dt><dd>{it.risk}</dd></> : <><dt>Payload</dt><dd className="mono">{JSON.stringify(it.payload)}</dd></>}<dt>Reason</dt><dd>{it.reason}</dd></dl>
      <div style={{ marginTop: 14 }}><Field label="Your decision reason (recorded in the audit log)" id="dr"><textarea id="dr" value={reason} onChange={(e) => setReason(e.target.value)} /></Field></div>
      <div className="row"><button className="btn primary" disabled={reason.trim().length < 3 || m.isPending} onClick={() => m.mutate('approve')}>{owner ? 'Apply now' : 'Approve'}</button><button className="btn danger" disabled={reason.trim().length < 3 || m.isPending} onClick={() => m.mutate('reject')}>Reject</button></div>
    </Modal>
  );
}
