import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Status } from '../components/ui';
import { get, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';

export default function Reports() {
  const { can } = useAuth();
  const jobs = useQuery({ queryKey: ['reports'], queryFn: () => get<Page<any>>('/api/reports', { limit: 50 }), refetchInterval: 15000 });
  const sch = useQuery({ queryKey: ['schedules'], queryFn: () => get<any[]>('/api/reports/schedules') });
  const [gen, setGen] = useState(false);
  const [sched, setSched] = useState(false);
  const pause = useAct((id: string) => post(`/api/reports/schedules/${id}/pause`), ['schedules']);
  return (
    <>
      <PageHead title="Reports" sub="Generate SOC, compliance, vulnerability and client reports.">
        {can('reports.generate') && <button className="btn primary" onClick={() => setGen(true)}>Generate report</button>}
      </PageHead>
      {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data!.items.length === 0 ? <Empty>No reports yet.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Report</th><th>Format</th><th>Status</th><th>Created</th><th /></tr></thead>
          <tbody>{jobs.data!.items.map((j) => <tr key={j.id}><td>{titleCase(j.kind)}</td><td>{j.fmt.toUpperCase()}</td><td><Status v={j.status} />{j.error && <span style={{ color: 'var(--muted)' }}> {j.error}</span>}</td><td>{ago(j.created_at)}</td>
            <td>{j.status === 'done' && <a className="btn small" href={`/api/reports/${j.id}/download`} download>Download</a>}</td></tr>)}</tbody></table></div>
      )}
      <div className="row" style={{ margin: '22px 0 8px' }}><h2>Schedules</h2><span className="spacer" />{can('reports.schedule') && <button className="btn small" onClick={() => setSched(true)}>New schedule</button>}</div>
      {sch.data && sch.data.length > 0 ? (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Report</th><th>Cadence</th><th>Next run</th><th>State</th><th /></tr></thead>
          <tbody>{sch.data.map((s) => <tr key={s.id}><td>{s.name}</td><td>{titleCase(s.kind)} ({s.fmt})</td><td>{s.cadence} at {String(s.hour).padStart(2, '0')}:00 {s.timezone}</td><td>{s.paused ? '—' : when(s.next_run_at)}</td><td>{s.paused ? 'Paused' : 'Active'}</td>
            <td>{can('reports.schedule') && <button className="btn small" onClick={() => pause.mutate(s.id)}>{s.paused ? 'Resume' : 'Pause'}</button>}</td></tr>)}</tbody></table></div>
      ) : <Empty>No schedules.</Empty>}
      <p style={{ color: 'var(--muted)', marginTop: 8 }}>Scheduled reports are generated and stored here. Email delivery of reports is not yet wired.</p>
      {gen && <Generate onClose={() => setGen(false)} />}
      {sched && <Schedule onClose={() => setSched(false)} />}
    </>
  );
}

const KINDS = ['soc_metrics', 'compliance', 'vulnerabilities', 'client'];
function useClients() { return useQuery({ queryKey: ['clients'], queryFn: () => get<any[]>('/api/clients') }); }

function Generate({ onClose }: { onClose: () => void }) {
  const clients = useClients();
  const [v, setV] = useState({ kind: 'soc_metrics', fmt: 'html', client_id: '', days: 30 });
  const m = useAct(() => post('/api/reports', { kind: v.kind, fmt: v.fmt, client_id: v.client_id || null, params: { days: v.days } }), ['reports'], 'Report queued', onClose);
  return (
    <Modal title="Generate report" onClose={onClose}>
      <Field label="Report" id="gk"><select id="gk" value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })}>{KINDS.map((k) => <option key={k} value={k}>{titleCase(k)}</option>)}</select></Field>
      <Field label="Format" id="gf" hint="PDF requires WeasyPrint on the server."><select id="gf" value={v.fmt} onChange={(e) => setV({ ...v, fmt: e.target.value })}>{['html', 'csv', 'json', 'pdf'].map((k) => <option key={k} value={k}>{k.toUpperCase()}</option>)}</select></Field>
      <Field label="Client" id="gc"><select id="gc" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">All clients</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
      <Field label="Period (days)" id="gd"><input id="gd" type="number" min={1} max={365} value={v.days} onChange={(e) => setV({ ...v, days: Number(e.target.value) })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending} onClick={() => m.mutate(undefined)}>Generate</button>
    </Modal>
  );
}

function Schedule({ onClose }: { onClose: () => void }) {
  const clients = useClients();
  const [v, setV] = useState({ name: '', kind: 'soc_metrics', cadence: 'weekly', hour: 7, fmt: 'html', client_id: '' });
  const m = useAct(() => post('/api/reports/schedules', { ...v, client_id: v.client_id || null, timezone: 'Asia/Colombo' }), ['schedules'], 'Schedule created', onClose);
  return (
    <Modal title="New schedule" onClose={onClose}>
      <Field label="Name" id="sn"><input id="sn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <div className="grid cols-2">
        <Field label="Report" id="sk"><select id="sk" value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })}>{KINDS.map((k) => <option key={k} value={k}>{titleCase(k)}</option>)}</select></Field>
        <Field label="Cadence" id="sc"><select id="sc" value={v.cadence} onChange={(e) => setV({ ...v, cadence: e.target.value })}>{['daily', 'weekly', 'monthly', 'quarterly'].map((k) => <option key={k}>{k}</option>)}</select></Field>
        <Field label="Hour (Asia/Colombo)" id="sh"><input id="sh" type="number" min={0} max={23} value={v.hour} onChange={(e) => setV({ ...v, hour: Number(e.target.value) })} /></Field>
        <Field label="Format" id="sf"><select id="sf" value={v.fmt} onChange={(e) => setV({ ...v, fmt: e.target.value })}>{['html', 'csv', 'json', 'pdf'].map((k) => <option key={k} value={k}>{k.toUpperCase()}</option>)}</select></Field>
      </div>
      <Field label="Client" id="scl"><select id="scl" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">All clients</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2} onClick={() => m.mutate(undefined)}>Create</button>
    </Modal>
  );
}
