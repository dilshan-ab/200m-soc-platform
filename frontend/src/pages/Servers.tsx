import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Summary } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, SearchBox, Sev, Status } from '../components/ui';
import { get, patch, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { titleCase, ago } from '../lib/format';
import { useAct } from '../lib/mut';

const CONTROLS = ['wazuh_agent', 'uptime_kuma', 'prometheus_exporter', 'velociraptor_client', 'bareos_job', 'opsi_client', 'suricata', 'zeek', 'fail2ban', 'osquery'];

export default function Servers() {
  const q = useQuery({ queryKey: ['servers'], queryFn: () => get<any[]>('/api/servers') });
  const { can } = useAuth();
  const [sel, setSel] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [fq, setFq] = useState('');
  const [fs, setFs] = useState('');
  const all = q.data ?? [];
  const up = all.filter((s) => s.status === 'up');
  const gaps = all.filter((s) => s.coverage.missing.length > 0);
  const down = all.filter((s) => s.status !== 'up');
  const rows = all.filter((s) => (!fq || `${s.name} ${s.host}`.toLowerCase().includes(fq.toLowerCase())) && (!fs || (fs === 'gaps' ? gaps.includes(s) : down.includes(s))));
  return (
    <>
      <PageHead title="Servers" sub="Every server in the estate, its role, health and monitoring coverage.">
        {can('servers.write') && <button className="btn primary" onClick={() => setAdding(true)}>Add server</button>}
      </PageHead>
      {all.length > 0 && <Summary items={[
        { label: 'Servers', value: all.length, onClick: () => setFs(''), active: !fs },
        { label: 'Up', value: up.length, tone: 'ok' },
        { label: 'Not up', value: down.length, tone: down.length ? 'bad' : 'ok', onClick: () => setFs(fs === 'down' ? '' : 'down'), active: fs === 'down' },
        { label: 'Monitoring gaps', value: gaps.length, tone: gaps.length ? 'warn' : 'ok', onClick: () => setFs(fs === 'gaps' ? '' : 'gaps'), active: fs === 'gaps' },
      ]} />}
      {all.length > 0 && <div className="filters"><SearchBox value={fq} onChange={setFq} placeholder="Search servers…" label="Search servers" /></div>}
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.length === 0 ? <Empty>No servers registered yet.</Empty> : (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>Role</th><th>Environment</th><th>Criticality</th><th>Status</th><th>Coverage</th></tr></thead>
          <tbody>{rows.map((s) => <tr key={s.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(s.id)} onKeyDown={(e) => e.key === 'Enter' && setSel(s.id)}>
            <td>{s.name}</td><td className="mono">{s.host}</td><td>{titleCase(s.role)}</td><td>{s.environment}</td><td><Sev v={s.criticality} /></td><td><Status v={s.status} /></td>
            <td><span style={{ fontWeight: 600 }}>{s.coverage.score}%</span>{s.coverage.missing.length > 0 && <span style={{ color: 'var(--muted)' }}> · {s.coverage.missing.length} missing</span>}</td></tr>)}</tbody></table></div>
      )}
      {sel && <ServerDrawer id={sel} onClose={() => setSel(null)} />}
      {adding && <AddServer onClose={() => setAdding(false)} />}
    </>
  );
}

function ServerDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['server', id], queryFn: () => get<any>(`/api/servers/${id}`) });
  const { can } = useAuth();
  const save = useAct((coverage: Record<string, boolean>) => patch(`/api/servers/${id}`, { coverage }), ['server', 'servers'], 'Coverage updated');
  if (q.isLoading) return <Drawer title="Server" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Server" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const s = q.data;
  const have = new Set<string>(s.coverage.expected.filter((c: string) => !s.coverage.missing.includes(c)));
  return (
    <Drawer title={s.name} onClose={onClose}>
      <dl className="kv"><dt>Host</dt><dd className="mono">{s.host}</dd><dt>Role</dt><dd>{titleCase(s.role)}</dd><dt>OS</dt><dd>{s.os || '—'}</dd><dt>Owner</dt><dd>{s.owner || '—'}</dd><dt>Status</dt><dd><Status v={s.status} /> since {ago(s.status_changed_at)}</dd><dt>Open alerts</dt><dd>{s.open_alerts}</dd><dt>Agents / assets</dt><dd>{s.agents}</dd></dl>
      <h3 style={{ marginTop: 16 }}>Monitoring coverage · {s.coverage.score}%</h3>
      <ul style={{ listStyle: 'none', padding: 0 }}>{s.coverage.expected.map((c: string) => (
        <li key={c} className="row"><input type="checkbox" id={`cv-${c}`} disabled={!can('servers.write')} checked={have.has(c)} onChange={(e) => save.mutate(Object.fromEntries(s.coverage.expected.map((x: string) => [x, x === c ? e.target.checked : have.has(x)])))} /><label htmlFor={`cv-${c}`}>{titleCase(c)}</label></li>))}</ul>
      <h3 style={{ marginTop: 16 }}>Hosted tools</h3>
      {s.tools.length === 0 ? <Empty>No tools linked to this server.</Empty> : <ul>{s.tools.map((t: any) => <li key={t.id}>{t.name} ({t.type}) <Status v={t.status} /></li>)}</ul>}
    </Drawer>
  );
}

function AddServer({ onClose }: { onClose: () => void }) {
  const clients = useQuery({ queryKey: ['clients'], queryFn: () => get<any[]>('/api/clients') });
  const [step, setStep] = useState(0);
  const [v, setV] = useState({ name: '', host: '', role: 'monitored', environment: 'production', owner: '', criticality: 'medium', os: '', client_id: '', expected_controls: ['wazuh_agent', 'uptime_kuma', 'prometheus_exporter', 'bareos_job'] as string[] });
  const m = useAct(() => post('/api/servers', { ...v, client_id: v.client_id || null }), ['servers'], 'Server added', onClose);
  const toggle = (c: string) => setV({ ...v, expected_controls: v.expected_controls.includes(c) ? v.expected_controls.filter((x) => x !== c) : [...v.expected_controls, c] });
  return (
    <Modal title={`Add server · step ${step + 1} of 2`} onClose={onClose} wide>
      {step === 0 ? (
        <>
          <div className="grid cols-2">
            <Field label="Name" id="sn"><input id="sn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
            <Field label="Hostname or IP" id="sh"><input id="sh" value={v.host} onChange={(e) => setV({ ...v, host: e.target.value })} /></Field>
            <Field label="Role" id="sr"><select id="sr" value={v.role} onChange={(e) => setV({ ...v, role: e.target.value })}>{['soc_core', 'monitored', 'workstation_group', 'proxy', 'dns'].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}</select></Field>
            <Field label="Environment" id="se"><select id="se" value={v.environment} onChange={(e) => setV({ ...v, environment: e.target.value })}>{['production', 'staging', 'development'].map((r) => <option key={r}>{r}</option>)}</select></Field>
            <Field label="Criticality" id="sc"><select id="sc" value={v.criticality} onChange={(e) => setV({ ...v, criticality: e.target.value })}>{['low', 'medium', 'high', 'critical'].map((r) => <option key={r}>{r}</option>)}</select></Field>
            <Field label="Operating system" id="so"><input id="so" value={v.os} onChange={(e) => setV({ ...v, os: e.target.value })} /></Field>
            <Field label="Owner" id="sw"><input id="sw" value={v.owner} onChange={(e) => setV({ ...v, owner: e.target.value })} /></Field>
            <Field label="Client / business unit" id="sl"><select id="sl" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })}><option value="">None</option>{clients.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
          </div>
          <button className="btn primary" disabled={!v.name.trim() || !/^[A-Za-z0-9_.\-:]+$/.test(v.host)} onClick={() => setStep(1)}>Next</button>
        </>
      ) : (
        <>
          <p>Choose the controls this server is expected to have. Coverage is scored against this list.</p>
          <ul style={{ listStyle: 'none', padding: 0 }}>{CONTROLS.map((c) => <li key={c} className="row"><input type="checkbox" id={`ec-${c}`} checked={v.expected_controls.includes(c)} onChange={() => toggle(c)} /><label htmlFor={`ec-${c}`}>{titleCase(c)}</label></li>)}</ul>
          {m.error && <ErrorBox error={m.error} />}
          <div className="row"><button className="btn" onClick={() => setStep(0)}>Back</button><button className="btn primary" disabled={m.isPending} onClick={() => m.mutate(undefined)}>Add server</button></div>
        </>
      )}
    </Modal>
  );
}
