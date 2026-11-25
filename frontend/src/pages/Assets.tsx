import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { SavedViews } from '../components/SavedViews';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Pager, SearchBox, Sev, Status, useToast } from '../components/ui';
import { get, patch, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Assets({ endpoint = false }: { endpoint?: boolean }) {
  const { can } = useAuth();
  const canSeeAlerts = can('alerts.read');
  const [page, setPage] = useState(1);
  const [params, setParams] = useSearchParams();
  const f = { q: params.get('q') ?? '', kind: params.get('kind') ?? '', agent_status: params.get('agent_status') ?? '', department: params.get('department') ?? '' };
  useEffect(() => { setPage(1); }, [f.q, f.kind, f.agent_status, f.department]);
  const sel = params.get('open');
  const setSel = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set('open', id); else next.delete('open');
    setParams(next);
  };
  const q = useQuery({ queryKey: ['assets', f, page], queryFn: () => get<Page<any>>('/api/assets', { ...f, page, limit: 50 }) });
  const upd = (k: string, v: string) => { const next = new URLSearchParams(params); if (v) next.set(k, v); else next.delete(k); setParams(next, { replace: true }); setPage(1); };
  const clear = () => { setParams(new URLSearchParams()); setPage(1); };
  return (
    <>
      <PageHead title={endpoint ? 'EDR' : 'Assets'} sub={endpoint ? 'Inspect endpoint agent health, patch state, and host inventory reported by Wazuh.' : 'Servers and workstations discovered from Wazuh agents, grouped by department or client.'}>
        {endpoint && <button className="btn" onClick={() => upd('agent_status', 'disconnected')}>Disconnected agents</button>}
      </PageHead>
      <div className="toolbar"><SavedViews area="assets" onApply={() => setPage(1)} /></div>
      <div className="filters">
        <SearchBox value={f.q} onChange={(v) => upd('q', v)} placeholder="Search name or hostname…" label="Search assets" />
        <select aria-label="Kind" value={f.kind} onChange={(e) => upd('kind', e.target.value)}><option value="">Any kind</option><option value="server">Server</option><option value="workstation">Workstation</option></select>
        <select aria-label="Agent status" value={f.agent_status} onChange={(e) => upd('agent_status', e.target.value)}><option value="">Any agent state</option>{['active', 'disconnected', 'never_connected', 'pending'].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</select>
        <input placeholder="Department" aria-label="Department" value={f.department} onChange={(e) => upd('department', e.target.value)} />
        {Object.values(f).some(Boolean) && <button className="btn small" onClick={clear}>Clear filters</button>}
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} /> : q.data!.items.length === 0 ? <Empty onAction={Object.values(f).some(Boolean) ? clear : undefined}>No assets match these filters. Try another name or agent state.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>Name</th><th>OS</th><th>Kind</th><th>Department</th><th>Agent</th><th>Criticality</th><th>Patch</th><th>Last seen</th>{endpoint && canSeeAlerts && <th>Activity</th>}</tr></thead>
            <tbody>{q.data!.items.map((a) => <tr key={a.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(a.id)} onKeyDown={(e) => { if (e.target === e.currentTarget && e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); setSel(a.id); } }}>
              <td>{a.name}</td><td>{a.os || '—'}</td><td>{a.kind}</td><td>{a.department || '—'}</td><td><Status v={a.agent_status} /></td><td><Sev v={a.criticality} /></td><td>{a.patch_status || '—'}</td><td>{ago(a.last_seen)}</td>
              {endpoint && canSeeAlerts && <td onClick={(e) => e.stopPropagation()}><Link className="record-link" to={`/app/siem?host=${encodeURIComponent(a.hostname || a.name)}`}>Hunt host</Link></td>}</tr>)}</tbody></table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={setPage} />
        </>
      )}
      {sel && <AssetDrawer key={sel} id={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function AssetDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['asset', id], queryFn: () => get<any>(`/api/assets/${id}`) });
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [undo, setUndo] = useState<{ previous: string; current: string } | null>(null);
  const [undoing, setUndoing] = useState(false);
  const [undoError, setUndoError] = useState<Error | null>(null);
  const save = useAct((b: Record<string, unknown>) => patch(`/api/assets/${id}`, b), ['asset', 'assets'], 'Asset criticality updated', (result) => {
    const previous = q.data?.criticality;
    setUndoError(null);
    if (previous && previous !== result.criticality) setUndo({ previous, current: result.criticality });
  });
  async function undoCriticality() {
    if (!undo) return;
    setUndoing(true); setUndoError(null);
    try {
      await patch(`/api/assets/${id}`, { criticality: undo.previous, expected_criticality: undo.current });
      await q.refetch();
      await qc.invalidateQueries({ queryKey: ['assets'] });
      setUndo(null);
      toast('Previous criticality restored');
    } catch (error) { setUndoError(error instanceof Error ? error : new Error('Could not undo the change')); }
    finally { setUndoing(false); }
  }
  if (q.isLoading) return <Drawer title="Asset" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Asset" onClose={onClose}><ErrorBox error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} /></Drawer>;
  const a = q.data;
  return (
    <Drawer title={a.name} onClose={onClose}>
      <dl className="kv"><dt>Hostname</dt><dd className="mono">{a.hostname || '—'}</dd><dt>IP addresses</dt><dd className="mono">{(a.ips ?? []).join(', ') || '—'}</dd><dt>OS</dt><dd>{a.os || '—'}</dd><dt>Owner</dt><dd>{a.owner || '—'}</dd>
        <dt>Compliance score</dt><dd>{a.sca_score ?? '—'}</dd><dt>Last backup</dt><dd>{when(a.last_backup_at)}</dd><dt>Open alerts</dt><dd>{a.open_alerts}</dd><dt>Open vulnerabilities</dt><dd>{a.open_vulns}</dd></dl>
      {can('assets.write') && (
        <div className="row" style={{ margin: '12px 0' }}>
          <label htmlFor="crit">Criticality</label>
          <select id="crit" disabled={save.isPending || undoing} value={a.criticality} onChange={(e) => save.mutate({ criticality: e.target.value, expected_criticality: a.criticality })}>{['low', 'medium', 'high', 'critical'].map((c) => <option key={c}>{c}</option>)}</select>
        </div>
      )}
      {undo && <div className="notice row"><span>Criticality changed from {undo.previous} to {undo.current}.</span><button className="btn small" disabled={undoing || save.isPending} onClick={() => void undoCriticality()}>{undoing ? 'Restoring…' : 'Undo criticality change'}</button></div>}
      {undoError && <ErrorBox error={undoError} onRetry={() => { setUndo(null); setUndoError(null); void q.refetch(); }} retrying={q.isFetching} />}
      <h3>Installed software</h3>
      {(a.software ?? []).length === 0 ? <Empty>No inventory reported.</Empty> : <ul>{a.software.slice(0, 40).map((s: any, i: number) => <li key={i}>{typeof s === 'string' ? s : `${s.name} ${s.version ?? ''}`}</li>)}</ul>}
    </Drawer>
  );
}
