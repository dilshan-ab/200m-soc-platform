import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Drawer, Empty, ErrorBox, Loading, PageHead, Pager, SearchBox, Sev, Status } from '../components/ui';
import { get, patch, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Assets({ endpoint = false }: { endpoint?: boolean }) {
  const { can } = useAuth();
  const canSeeAlerts = can('alerts.read');
  const [page, setPage] = useState(1);
  const [f, setF] = useState({ q: '', kind: '', agent_status: '', department: '' });
  const [sel, setSel] = useState<string | null>(null);
  const q = useQuery({ queryKey: ['assets', f, page], queryFn: () => get<Page<any>>('/api/assets', { ...f, page, limit: 50 }) });
  const upd = (k: string, v: string) => { setF({ ...f, [k]: v }); setPage(1); };
  return (
    <>
      <PageHead title={endpoint ? 'EDR' : 'Assets'} sub={endpoint ? 'Inspect endpoint agent health, patch state, and host inventory reported by Wazuh.' : 'Servers and workstations discovered from Wazuh agents, grouped by department or client.'}>
        {endpoint && <button className="btn" onClick={() => upd('agent_status', 'disconnected')}>Disconnected agents</button>}
      </PageHead>
      <div className="filters">
        <SearchBox value={f.q} onChange={(v) => upd('q', v)} placeholder="Search name or hostname…" label="Search assets" />
        <select aria-label="Kind" value={f.kind} onChange={(e) => upd('kind', e.target.value)}><option value="">Any kind</option><option value="server">Server</option><option value="workstation">Workstation</option></select>
        <select aria-label="Agent status" value={f.agent_status} onChange={(e) => upd('agent_status', e.target.value)}><option value="">Any agent state</option>{['active', 'disconnected', 'never_connected', 'pending'].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</select>
        <input placeholder="Department" aria-label="Department" value={f.department} onChange={(e) => upd('department', e.target.value)} />
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No assets found.</Empty> : (
        <>
          <div className="table-wrap"><table><thead><tr><th>Name</th><th>OS</th><th>Kind</th><th>Department</th><th>Agent</th><th>Criticality</th><th>Patch</th><th>Last seen</th>{endpoint && canSeeAlerts && <th>Activity</th>}</tr></thead>
            <tbody>{q.data!.items.map((a) => <tr key={a.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(a.id)} onKeyDown={(e) => e.target === e.currentTarget && e.key === 'Enter' && setSel(a.id)}>
              <td>{a.name}</td><td>{a.os || '—'}</td><td>{a.kind}</td><td>{a.department || '—'}</td><td><Status v={a.agent_status} /></td><td><Sev v={a.criticality} /></td><td>{a.patch_status || '—'}</td><td>{ago(a.last_seen)}</td>
              {endpoint && canSeeAlerts && <td onClick={(e) => e.stopPropagation()}><Link className="record-link" to={`/app/siem?host=${encodeURIComponent(a.hostname || a.name)}`}>Hunt host</Link></td>}</tr>)}</tbody></table></div>
          <Pager page={page} limit={50} total={q.data!.total} set={setPage} />
        </>
      )}
      {sel && <AssetDrawer id={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function AssetDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['asset', id], queryFn: () => get<any>(`/api/assets/${id}`) });
  const { can } = useAuth();
  const save = useAct((b: Record<string, unknown>) => patch(`/api/assets/${id}`, b), ['asset', 'assets'], 'Asset updated');
  if (q.isLoading) return <Drawer title="Asset" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Asset" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const a = q.data;
  return (
    <Drawer title={a.name} onClose={onClose}>
      <dl className="kv"><dt>Hostname</dt><dd className="mono">{a.hostname || '—'}</dd><dt>IP addresses</dt><dd className="mono">{(a.ips ?? []).join(', ') || '—'}</dd><dt>OS</dt><dd>{a.os || '—'}</dd><dt>Owner</dt><dd>{a.owner || '—'}</dd>
        <dt>Compliance score</dt><dd>{a.sca_score ?? '—'}</dd><dt>Last backup</dt><dd>{when(a.last_backup_at)}</dd><dt>Open alerts</dt><dd>{a.open_alerts}</dd><dt>Open vulnerabilities</dt><dd>{a.open_vulns}</dd></dl>
      {can('assets.write') && (
        <div className="row" style={{ margin: '12px 0' }}>
          <label htmlFor="crit">Criticality</label>
          <select id="crit" value={a.criticality} onChange={(e) => save.mutate({ criticality: e.target.value })}>{['low', 'medium', 'high', 'critical'].map((c) => <option key={c}>{c}</option>)}</select>
        </div>
      )}
      <h3>Installed software</h3>
      {(a.software ?? []).length === 0 ? <Empty>No inventory reported.</Empty> : <ul>{a.software.slice(0, 40).map((s: any, i: number) => <li key={i}>{typeof s === 'string' ? s : `${s.name} ${s.version ?? ''}`}</li>)}</ul>}
    </Drawer>
  );
}
