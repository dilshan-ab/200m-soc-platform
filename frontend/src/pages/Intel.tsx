import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Loading, Modal, PageHead, Status } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Intel() {
  return (
    <>
      <PageHead title="Threat intelligence" sub="Enrich indicators with Cortex and MISP." />
      <Enrich />
    </>
  );
}

function Enrich() {
  const { can } = useAuth();
  const [ind, setInd] = useState('');
  const sources = useQuery({ queryKey: ['intel-sources'], queryFn: () => get<any[]>('/api/intel/sources') });
  const jobs = useQuery({ queryKey: ['intel-jobs'], queryFn: () => get<any[]>('/api/intel/jobs'), refetchInterval: 15000 });
  const run = useAct(() => post('/api/intel/enrich', { indicator: ind.trim() }), ['intel-jobs'], 'Enrichment queued', () => setInd(''));
  const [view, setView] = useState<any>(null);
  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>{sources.data?.map((s) => <span key={s.id} className={`badge ${s.enabled ? 'st-ok' : 'st-down'}`}>{s.name}: {s.enabled ? 'enabled' : 'disabled'}</span>)}{sources.data?.length === 0 && <span style={{ color: 'var(--muted)' }}>No Cortex or MISP integration configured.</span>}</div>
      {can('intel.enrich') && (
        <form className="row" onSubmit={(e) => { e.preventDefault(); if (ind.trim().length >= 3) run.mutate(undefined); }} style={{ marginBottom: 6 }}>
          <input style={{ flex: 1 }} placeholder="IP, domain, URL or file hash" aria-label="Indicator" value={ind} onChange={(e) => setInd(e.target.value)} />
          <button className="btn primary" disabled={ind.trim().length < 3 || run.isPending}>Enrich</button>
        </form>
      )}
      {run.error && <ErrorBox error={run.error} />}
      {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data!.length === 0 ? <Empty>No enrichment jobs yet.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Type</th><th>Status</th><th>Verdict</th><th>When</th><th /></tr></thead>
          <tbody>{jobs.data!.map((j) => <tr key={j.id}><td className="mono wrap">{j.indicator}</td><td>{j.type}</td><td><Status v={j.status} /></td><td>{j.verdict ?? '—'}</td><td>{ago(j.created_at)}</td><td><button className="btn small" onClick={() => setView(j)}>Details</button></td></tr>)}</tbody></table></div>
      )}
      {view && <Modal title={view.indicator} onClose={() => setView(null)} wide><pre className="mono" style={{ whiteSpace: 'pre-wrap', maxHeight: '60vh', overflow: 'auto' }}>{JSON.stringify(view.results, null, 2)}</pre></Modal>}
    </>
  );
}
