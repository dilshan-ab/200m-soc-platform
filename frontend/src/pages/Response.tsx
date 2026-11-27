import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Status, useToast } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';

export function RequestActionModal({ initial, onClose }: { initial?: { action_key?: string; targets?: string; alert_id?: string; case_id?: string }; onClose: () => void }) {
  const cat = useQuery({ queryKey: ['response-catalogue'], queryFn: () => get<any[]>('/api/response/catalogue') });
  const [key, setKey] = useState(initial?.action_key ?? 'block_ip');
  const [targets, setTargets] = useState(initial?.targets ?? '');
  const [reason, setReason] = useState('');
  const [params, setParams] = useState<Record<string, string>>({});
  const toast = useToast();
  const qc = useQueryClient();
  const spec = cat.data?.find((a) => a.key === key);
  const m = useMutation({
    mutationFn: () => post('/api/response/requests', { action_key: key, targets: targets.split(/[\s,]+/).filter(Boolean), reason, params, alert_id: initial?.alert_id, case_id: initial?.case_id, idempotency_key: crypto.randomUUID() }),
    onSuccess: (r: any) => { toast(r.status === 'approved' ? 'Action approved automatically and queued' : 'Request submitted for approval'); void qc.invalidateQueries({ queryKey: ['requests'] }); onClose(); },
    onError: (e: Error) => toast(e.message, true),
  });
  return (
    <Modal title="Request response action" onClose={onClose}>
      {cat.isLoading ? <Loading /> : (
        <form onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
          <Field label="Action" id="ra-a"><select id="ra-a" value={key} onChange={(e) => setKey(e.target.value)}>{cat.data!.map((a) => <option key={a.key} value={a.key}>{a.label}</option>)}</select></Field>
          {spec && <p className="notice">Risk <b>{spec.risk}</b> · {spec.approvals === 0 ? 'no approval needed' : `${spec.approvals} approval(s) required`} · {spec.reversible ? 'reversible' : 'not automatically reversible'}</p>}
          <Field label={`Target ${spec?.target_kind ?? ''}(s)`} id="ra-t" hint="Separate several with spaces or commas"><input id="ra-t" value={targets} onChange={(e) => setTargets(e.target.value)} required /></Field>
          {spec?.params.map((p: string) => <Field key={p} label={p} id={`ra-${p}`}><input id={`ra-${p}`} value={params[p] ?? ''} onChange={(e) => setParams({ ...params, [p]: e.target.value })} required /></Field>)}
          {spec?.reversible && <Field label="Auto-revert after (minutes)" id="ra-r" hint="Optional: lifts the block/isolation automatically"><input id="ra-r" type="number" min={5} max={10080} onChange={(e) => setParams({ ...params, revert_minutes: e.target.value })} /></Field>}
          <Field label="Reason" id="ra-reason"><textarea id="ra-reason" value={reason} onChange={(e) => setReason(e.target.value)} minLength={5} required /></Field>
          <div className="row"><button className="btn primary" disabled={m.isPending}>Submit request</button><button type="button" className="btn" onClick={onClose}>Cancel</button></div>
        </form>
      )}
    </Modal>
  );
}

export default function Response() {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const q = useQuery({ queryKey: ['requests'], queryFn: () => get('/api/response/requests', { limit: 100 }) });
  const g = useQuery({ queryKey: ['guardrails'], queryFn: () => get('/api/response/guardrails') });
  const qc = useQueryClient();
  const toast = useToast();
  const kill = useMutation({
    mutationFn: (engaged: boolean) => post('/api/response/kill-switch', { engaged, reason: engaged ? 'Engaged from console' : 'Released from console' }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['guardrails'] }); toast('Kill switch updated'); }, onError: (e: Error) => toast(e.message, true),
  });
  const cancel = useMutation({ mutationFn: (id: string) => post(`/api/response/requests/${id}/cancel`), onSuccess: () => void qc.invalidateQueries({ queryKey: ['requests'] }), onError: (e: Error) => toast(e.message, true) });
  return (
    <>
      <PageHead title="Response" sub="Requests are scoped, approved, executed and audited">
        {can('admin.settings') && g.data && <button className={`btn ${g.data.kill_switch ? 'primary' : 'danger'}`} onClick={() => kill.mutate(!g.data.kill_switch)}>{g.data.kill_switch ? 'Release kill switch' : 'Engage kill switch'}</button>}
        {can('response.request') && <button className="btn primary" onClick={() => setOpen(true)}>New request</button>}
      </PageHead>
      {g.data?.kill_switch && <div className="error" style={{ marginBottom: 14 }} role="alert">Kill switch engaged: no new response actions can be requested or executed.</div>}
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? <Empty>No response requests yet.</Empty> : (
        <div className="table-wrap"><table>
          <thead><tr><th>Action</th><th>Targets</th><th>Risk</th><th>Status</th><th>Requested by</th><th>Created</th><th /></tr></thead>
          <tbody>{q.data.items.map((r: any) => (
            <tr key={r.id} className="clickable" onClick={() => setDetail(detail === r.id ? null : r.id)}>
              <td>{r.label}</td><td className="mono">{r.targets.join(', ')}</td><td><span className={`badge sev-${r.risk === 'medium' ? 'medium' : r.risk}`}>{r.risk}</span></td>
              <td><Status v={r.status} /></td><td>{r.requester}</td><td title={when(r.created_at)}>{ago(r.created_at)}</td>
              <td>{r.status === 'pending_approval' && <button className="btn small" onClick={(e) => { e.stopPropagation(); cancel.mutate(r.id); }}>Cancel</button>}</td>
            </tr>))}</tbody>
        </table></div>
      )}
      {detail && <RequestDetail id={detail} />}
      <p style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>{can('response.approve') ? <>Approvers: see <Link to="/app/approvals">Approvals</Link>. </> : 'Requests are approved by L2 analysts or above. '}Protected targets: {g.data?.protected_targets?.join(', ') || 'none'}.</p>
      {open && <RequestActionModal onClose={() => setOpen(false)} />}
    </>
  );
}

function RequestDetail({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['request', id], queryFn: () => get(`/api/response/requests/${id}`) });
  if (!q.data) return null;
  const r = q.data;
  return (
    <div className="card" style={{ marginTop: 14 }}>
      <h2>{r.label}</h2>
      <dl className="kv"><dt>Reason</dt><dd>{r.reason}</dd><dt>Params</dt><dd className="mono">{JSON.stringify(r.params)}</dd><dt>Approvals</dt><dd>{r.approvals.length ? r.approvals.map((a: any) => `${a.decision} — ${a.reason}`).join(' · ') : `0 of ${r.approvals_required}`}</dd><dt>Result</dt><dd className="mono">{JSON.stringify(r.result)}</dd><dt>Expires</dt><dd>{when(r.expires_at)}</dd></dl>
    </div>
  );
}
