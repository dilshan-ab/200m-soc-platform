import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Status } from '../components/ui';
import { del, get, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type Template = { id: string; name: string; description: string; kind: string; fmt: string; params: Record<string, any>; client_id: string | null };

export default function Reports() {
  const { can } = useAuth();
  const jobs = useQuery({ queryKey: ['reports'], queryFn: () => get<Page<any>>('/api/reports', { limit: 50 }), refetchInterval: REFRESH_MS });
  const sch = useQuery({ queryKey: ['schedules'], queryFn: () => get<any[]>('/api/reports/schedules') });
  const templates = useQuery({ queryKey: ['report-templates'], queryFn: () => get<Template[]>('/api/report-templates') });
  const [gen, setGen] = useState<Template | null | 'new'>(null);
  const [sched, setSched] = useState(false);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const pause = useAct((id: string) => post(`/api/reports/schedules/${id}/pause`), ['schedules']);
  const runNow = useAct((id: string) => post(`/api/reports/schedules/${id}/run-now`), ['reports'], 'Report queued');
  const delSchedule = useAct((id: string) => del(`/api/reports/schedules/${id}`), ['schedules'], 'Schedule deleted');
  const delTemplate = useAct((id: string) => del(`/api/report-templates/${id}`), ['report-templates'], 'Template deleted');
  return (
    <>
      <PageHead title="Reports" sub="Generate SOC, compliance, vulnerability and client reports.">
        {can('reports.generate') && <button className="btn primary" onClick={() => setGen('new')}>Generate report</button>}
      </PageHead>
      {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data!.items.length === 0 ? <Empty>No reports yet.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Report</th><th>Format</th><th>Status</th><th>Created</th><th /></tr></thead>
          <tbody>{jobs.data!.items.map((j) => <tr key={j.id}><td>{titleCase(j.kind)}</td><td>{j.fmt.toUpperCase()}</td><td><Status v={j.status} />{j.error && <span style={{ color: 'var(--muted)' }}> {j.error}</span>}</td><td>{ago(j.created_at)}</td>
            <td>{j.status === 'done' && <a className="btn small" href={`/api/reports/${j.id}/download`} download>Download</a>}</td></tr>)}</tbody></table></div>
      )}

      <div className="row" style={{ margin: '22px 0 8px' }}><h2>Templates</h2><span className="spacer" />{can('reports.generate') && <button className="btn small" onClick={() => setSavingTemplate(true)}>New template</button>}</div>
      {templates.isLoading ? <Loading /> : templates.error ? <ErrorBox error={templates.error} /> : templates.data && templates.data.length > 0 ? (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Report</th><th>Format</th><th /></tr></thead>
          <tbody>{templates.data.map((t) => <tr key={t.id}><td>{t.name}<div style={{ fontSize: 12, color: 'var(--muted)' }}>{t.description}</div></td><td>{titleCase(t.kind)}</td><td>{t.fmt.toUpperCase()}</td>
            <td className="row" style={{ gap: 4 }}>
              {can('reports.generate') && <button className="btn small primary" onClick={() => setGen(t)}>Use</button>}
              {can('reports.generate') && <button className="btn small danger" onClick={() => { if (confirm(`Delete template "${t.name}"?`)) delTemplate.mutate(t.id); }}>Delete</button>}
            </td></tr>)}</tbody></table></div>
      ) : <Empty>No templates yet. Save a template to reuse a report configuration.</Empty>}

      <div className="row" style={{ margin: '22px 0 8px' }}><h2>Schedules</h2><span className="spacer" />{can('reports.schedule') && <button className="btn small" onClick={() => setSched(true)}>New schedule</button>}</div>
      {sch.isLoading ? <Loading /> : sch.error ? <ErrorBox error={sch.error} /> : sch.data && sch.data.length > 0 ? (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Report</th><th>Cadence</th><th>Next run</th><th>State</th><th /></tr></thead>
          <tbody>{sch.data.map((s) => <tr key={s.id}><td>{s.name}</td><td>{titleCase(s.kind)} ({s.fmt})</td><td>{s.cadence} at {String(s.hour).padStart(2, '0')}:00 {s.timezone}</td><td>{s.paused ? '—' : when(s.next_run_at)}</td><td>{s.paused ? 'Paused' : 'Active'}</td>
            <td className="row" style={{ gap: 4 }}>{can('reports.schedule') && <>
              <button className="btn small" onClick={() => runNow.mutate(s.id)}>Run now</button>
              <button className="btn small" onClick={() => pause.mutate(s.id)}>{s.paused ? 'Resume' : 'Pause'}</button>
              <button className="btn small danger" onClick={() => { if (confirm(`Delete schedule "${s.name}"?`)) delSchedule.mutate(s.id); }}>Delete</button>
            </>}</td></tr>)}</tbody></table></div>
      ) : <Empty>No schedules.</Empty>}
      <p style={{ color: 'var(--muted)', marginTop: 8 }}>Scheduled reports are generated and stored here. Email delivery of reports is not yet wired.</p>
      {gen && <Generate template={gen === 'new' ? null : gen} onClose={() => setGen(null)} />}
      {sched && <Schedule onClose={() => setSched(false)} />}
      {savingTemplate && <SaveTemplate onClose={() => setSavingTemplate(false)} />}
    </>
  );
}

const KINDS = ['soc_metrics', 'compliance', 'vulnerabilities', 'client'];
function useClients() { return useQuery({ queryKey: ['clients'], queryFn: () => get<any[]>('/api/clients') }); }

function Generate({ template, onClose }: { template: Template | null; onClose: () => void }) {
  const clients = useClients();
  const [v, setV] = useState({ kind: template?.kind ?? 'soc_metrics', fmt: template?.fmt ?? 'html', client_id: template?.client_id ?? '', days: template?.params.days ?? 30 });
  const m = useAct(() => post('/api/reports', { kind: v.kind, fmt: v.fmt, client_id: v.client_id || null, params: { days: v.days } }), ['reports'], 'Report queued', onClose);
  return (
    <Modal title={template ? `Generate from "${template.name}"` : 'Generate report'} onClose={onClose}>
      <Field label="Report" id="gk"><select id="gk" value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })}>{KINDS.map((k) => <option key={k} value={k}>{titleCase(k)}</option>)}</select></Field>
      <Field label="Format" id="gf" hint="PDF requires WeasyPrint on the server."><select id="gf" value={v.fmt} onChange={(e) => setV({ ...v, fmt: e.target.value })}>{['html', 'csv', 'json', 'pdf'].map((k) => <option key={k} value={k}>{k.toUpperCase()}</option>)}</select></Field>
      <Field label="Client" id="gc"><select id="gc" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">All clients</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
      <Field label="Period (days)" id="gd"><input id="gd" type="number" min={1} max={365} value={v.days} onChange={(e) => setV({ ...v, days: Number(e.target.value) })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !Number.isInteger(v.days) || v.days < 1 || v.days > 365} onClick={() => m.mutate(undefined)}>Generate</button>
    </Modal>
  );
}

function SaveTemplate({ onClose }: { onClose: () => void }) {
  const clients = useClients();
  const [v, setV] = useState({ name: '', description: '', kind: 'soc_metrics', fmt: 'html', client_id: '', days: 30 });
  const m = useAct(() => post('/api/report-templates', { name: v.name, description: v.description, kind: v.kind, fmt: v.fmt, client_id: v.client_id || null, params: { days: v.days } }), ['report-templates'], 'Template saved', onClose);
  return (
    <Modal title="New report template" onClose={onClose}>
      <Field label="Name" id="tn"><input id="tn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Description" id="td"><input id="td" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      <div className="grid cols-2">
        <Field label="Report" id="tk"><select id="tk" value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })}>{KINDS.map((k) => <option key={k} value={k}>{titleCase(k)}</option>)}</select></Field>
        <Field label="Format" id="tf"><select id="tf" value={v.fmt} onChange={(e) => setV({ ...v, fmt: e.target.value })}>{['html', 'csv', 'json', 'pdf'].map((k) => <option key={k} value={k}>{k.toUpperCase()}</option>)}</select></Field>
      </div>
      <div className="grid cols-2">
        <Field label="Client" id="tc"><select id="tc" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">All clients</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
        <Field label="Default period (days)" id="tdy"><input id="tdy" type="number" min={1} max={365} value={v.days} onChange={(e) => setV({ ...v, days: Number(e.target.value) })} /></Field>
      </div>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2 || !Number.isInteger(v.days) || v.days < 1 || v.days > 365} onClick={() => m.mutate(undefined)}>Save template</button>
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
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2 || !Number.isInteger(v.hour) || v.hour < 0 || v.hour > 23} onClick={() => m.mutate(undefined)}>Create</button>
    </Modal>
  );
}
