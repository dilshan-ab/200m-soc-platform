import { useQuery } from '@tanstack/react-query';
import { Fragment, useRef, useState } from 'react';
import { CheckCircle, XCircle, Loader, RotateCw, Zap, ArrowLeft, ArrowRight, Play, Pause, RefreshCw, Trash2, Settings, Map as MapIcon, Key, Power, Shield, Eye, EyeOff } from 'lucide-react';
import { Summary } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, SearchBox, Status, useToast } from '../components/ui';
import { del, get, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase, when } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type FieldSpec = { name: string; label: string; type: string; required: boolean; secret: boolean; help: string; default: unknown };
type Manifest = { type: string; label: string; category: string; link_method: string; direction: string; auth: string; capabilities: string[]; test_checks: string[]; webhook: boolean; setup_hint: string; fields: FieldSpec[] };

const STEPS = ['Choose integration', 'Configure', 'Verify'];
const BUILT_IN_WORKFLOWS = new Map([
  ['thehive', 'Use Cases to manage investigations.'],
  ['shuffle', 'Use Playbooks to automate response workflows.'],
  ['keycloak', 'Company SSO is configured in the deployment settings.'],
]);

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="wizard-steps">
      {STEPS.map((label, i) => (
        <Fragment key={i}>
          {i > 0 && <div className={`wizard-step-line${i <= current ? ' done' : ''}`} />}
          <div className={`wizard-step${i === current ? ' active' : ''}${i < current ? ' done' : ''}`}>
            <span className="wizard-step-num">{i < current ? <CheckCircle size={16} /> : i + 1}</span>
            <span className="wizard-step-label">{label}</span>
          </div>
        </Fragment>
      ))}
    </div>
  );
}

export default function Integrations() {
  const tools = useQuery({ queryKey: ['tools'], queryFn: () => get<any[]>('/api/integrations/tools'), refetchInterval: REFRESH_MS });
  const { can } = useAuth();
  const [sel, setSel] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const canAdd = can('integrations.write');
  const showAdd = canAdd && adding;
  const addTab = useRef<HTMLButtonElement>(null);
  const [fq, setFq] = useState('');
  const [fs, setFs] = useState('');
  const all = tools.data ?? [];
  const failing = all.filter((t) => (t.health?.error_count ?? 0) > 0 || ['error', 'degraded', 'down', 'failed'].includes(t.status));
  const paused = all.filter((t) => ['paused', 'disabled'].includes(t.status));
  const healthy = all.filter((tool) => !failing.includes(tool) && !paused.includes(tool));
  const rows = all.filter((t) => (!fq || `${t.name} ${t.label}`.toLowerCase().includes(fq.trim().toLowerCase())) && (!fs || (fs === 'failing' ? failing.includes(t) : paused.includes(t))));
  return (
    <>
      <PageHead title="Integrations" sub="Connect external data sources, services, and tools.">
        {canAdd && <button type="button" className="btn primary" onClick={() => { setAdding(true); addTab.current?.focus(); }}>
          <Zap size={15} aria-hidden="true" /> Add tool
        </button>}
      </PageHead>
      {canAdd && (
        <div className="tabs" role="tablist" aria-label="Integrations" onKeyDown={(event) => {
          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
          event.preventDefault();
          const next = event.key === 'Home' ? false : event.key === 'End' ? true : !showAdd;
          setAdding(next);
          event.currentTarget.querySelector<HTMLButtonElement>(next ? '#integrations-add-tab' : '#integrations-connected-tab')?.focus();
        }}>
          <button type="button" role="tab" className={`tab${!showAdd ? ' active' : ''}`} id="integrations-connected-tab"
            aria-controls="integrations-connected" aria-selected={!showAdd} tabIndex={showAdd ? -1 : 0} onClick={() => setAdding(false)}>Connected</button>
          <button type="button" role="tab" className={`tab${showAdd ? ' active' : ''}`} id="integrations-add-tab" ref={addTab}
            aria-controls="integrations-add" aria-selected={showAdd} tabIndex={showAdd ? 0 : -1} onClick={() => setAdding(true)}>Add integrations</button>
        </div>
      )}
      <div id="integrations-connected" role={canAdd ? 'tabpanel' : undefined} aria-labelledby={canAdd ? 'integrations-connected-tab' : undefined} hidden={showAdd}>
        {all.length > 0 && <Summary items={[
          { label: 'Tools linked', value: all.length, onClick: () => setFs(''), active: !fs },
          { label: 'Healthy', value: healthy.length, tone: 'ok' },
          { label: 'Needs attention', value: failing.length, tone: failing.length ? 'bad' : 'ok', onClick: () => setFs(fs === 'failing' ? '' : 'failing'), active: fs === 'failing' },
          { label: 'Paused', value: paused.length, tone: paused.length ? 'warn' : 'ok', onClick: () => setFs(fs === 'paused' ? '' : 'paused'), active: fs === 'paused' },
        ]} />}
        {all.length > 0 && <div className="filters"><SearchBox value={fq} onChange={setFq} placeholder="Search tools…" label="Search tools" />{(fq || fs) && <button className="btn" onClick={() => { setFq(''); setFs(''); }}>Clear filters</button>}</div>}
        {tools.isLoading ? <Loading /> : tools.error ? <ErrorBox error={tools.error} /> : tools.data!.length === 0 ? <Empty>{canAdd ? 'No integrations connected yet. Open Add integrations to connect a tool.' : 'No integrations connected yet.'}</Empty> : rows.length === 0 ? <Empty>No tools match these filters.</Empty> : (
          <div className="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Last sync</th><th>Lag</th><th>Today</th><th>Errors</th></tr></thead>
            <tbody>{rows.map((t) => <tr key={t.id} tabIndex={0} className="clickable" onClick={() => setSel(t.id)} onKeyDown={(e) => e.key === 'Enter' && setSel(t.id)}>
              <td><strong>{t.name}</strong></td><td>{t.label}</td><td><Status v={t.status} /></td><td>{ago(t.health?.last_success_at)}</td><td>{t.health?.lag_seconds != null ? `${Math.round(t.health.lag_seconds)}s` : '—'}</td><td>{t.health?.items_today ?? 0}</td><td>{t.health?.error_count ? <span className="text-bad">{t.health.error_count}</span> : 0}</td></tr>)}</tbody></table></div>
        )}
      </div>
      {canAdd && <div id="integrations-add" role="tabpanel" aria-labelledby="integrations-add-tab" hidden={!showAdd}>
        {showAdd && <Wizard configuredTypes={new Set(all.map((tool) => tool.type))} onDone={(id) => { setAdding(false); setSel(id); }} />}
      </div>}
      {sel && <ToolDrawer id={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function FieldInput({ f, value, onChange, editing }: { f: FieldSpec; value: any; onChange: (v: any) => void; editing?: boolean }) {
  const id = `f-${f.name}`;
  const hint = [f.help, f.secret && editing ? 'Leave blank to keep the stored secret.' : ''].filter(Boolean).join(' ');
  let input;
  if (f.type === 'textarea' || f.type === 'file') input = <textarea id={id} className="mono" value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={f.secret && editing ? '••••••••' : ''} />;
  else if (f.type === 'bool') input = <input id={id} type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />;
  else if (f.type === 'list') input = <input id={id} value={Array.isArray(value) ? value.join(', ') : value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder="comma separated" />;
  else input = <input id={id} type={f.secret || f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text'} autoComplete="off" value={value ?? ''} onChange={(e) => onChange(f.type === 'number' ? (e.target.value === '' ? '' : Number(e.target.value)) : e.target.value)} placeholder={f.secret && editing ? '••••••••' : ''} />;
  return <Field label={`${f.label}${f.required && !(f.secret && editing) ? ' *' : ''}`} hint={hint || undefined} id={id}>{input}</Field>;
}

function cleanValues(m: Manifest, v: Record<string, any>) {
  const out: Record<string, any> = {};
  for (const f of m.fields) {
    let x = v[f.name];
    if (x === undefined || x === '' || x === null) continue;
    if (f.type === 'list') x = typeof x === 'string' ? x.split(',').map((s: string) => s.trim()).filter(Boolean) : x;
    out[f.name] = x;
  }
  return out;
}

function pickTool(c: Manifest, name: string, setM: (m: Manifest) => void, setVals: (v: Record<string, any>) => void, setName: (n: string) => void, setStep: (s: number) => void) {
  setM(c);
  setVals(Object.fromEntries(c.fields.filter((f) => f.default != null).map((f) => [f.name, f.default])));
  setName(name);
  setStep(1);
}

function Wizard({ configuredTypes, onDone }: { configuredTypes: ReadonlySet<string>; onDone: (id: string) => void }) {
  const cat = useQuery({ queryKey: ['catalogue'], queryFn: () => get<Manifest[]>('/api/integrations/catalogue') });
  const servers = useQuery({ queryKey: ['servers'], queryFn: () => get<any[]>('/api/servers') });
  const [step, setStep] = useState(0);
  const [q, setQ] = useState('');
  const [m, setM] = useState<Manifest | null>(null);
  const [name, setName] = useState('');
  const [server, setServer] = useState('');
  const [interval, setIntervalS] = useState(30);
  const [vals, setVals] = useState<Record<string, any>>({});
  const [created, setCreated] = useState<any>(null);
  const create = useAct(() => post('/api/integrations/tools', { type: m!.type, name, server_id: server || null, values: cleanValues(m!, vals), poll_interval: interval }), ['tools'], 'Tool created', (r) => { setCreated(r); setStep(2); });
  const missing = m ? m.fields.filter((f) => f.required && (vals[f.name] === undefined || vals[f.name] === '')).map((f) => f.label) : [];
  const term = q.trim().toLowerCase();
  const matches = cat.data?.filter((c) => !BUILT_IN_WORKFLOWS.has(c.type) && (!term || c.label.toLowerCase().includes(term))) ?? [];
  const builtInMatch = cat.data?.find((c) => BUILT_IN_WORKFLOWS.has(c.type) && c.label.toLowerCase() === term);
  const custom = cat.data?.find((c) => c.type === 'custom');
  return (
    <section className="panel integration-wizard" aria-label="Connect an integration">
      <StepIndicator current={step} />
      {step === 0 && (cat.isLoading ? <Loading /> : cat.error ? <ErrorBox error={cat.error} /> : (
        <>
          <div className="wizard-search"><SearchBox value={q} onChange={setQ} placeholder="Search by name, or type a tool that isn't listed…" label="Find a tool" /></div>
          <div className="tool-pick-grid">{matches.map((c) => {
            const configured = configuredTypes.has(c.type);
            return (
              <button key={c.type} type="button" className={`tool-pick${configured ? ' tool-pick-configured' : ''}`} onClick={() => pickTool(c, c.label, setM, setVals, setName, setStep)}>
                {configured ? <CheckCircle size={18} aria-hidden="true" /> : <Shield size={18} aria-hidden="true" />}
                <span>{c.label}</span>
                {configured && <small className="tool-pick-status">Configured</small>}
              </button>
            );
          })}</div>
          {builtInMatch && matches.length === 0 && <Empty>{BUILT_IN_WORKFLOWS.get(builtInMatch.type)}</Empty>}
          {term && matches.length === 0 && custom && !builtInMatch && (
            <div className="notice wizard-custom-notice">
              <b>No built-in connector for "{q.trim()}".</b>
              <button type="button" className="btn primary" onClick={() => pickTool(custom, q.trim(), setM, setVals, setName, setStep)}>Add "{q.trim()}" as a custom tool <ArrowRight size={14} /></button>
            </div>
          )}
        </>
      ))}
      {step === 1 && m && (
        <>
          <div className="wizard-meta">
            <span className="badge">{m.auth}</span>
            <span className="muted">{m.label}: {m.link_method}</span>
          </div>
          <div className="grid cols-2">
            <Field label="Name *" id="tn"><input id="tn" value={name} onChange={(e) => setName(e.target.value)} /></Field>
            <Field label="Host server" id="ts"><select id="ts" value={server} onChange={(e) => setServer(e.target.value)}><option value="">Not linked to a server</option>{servers.data?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
          </div>
          <div className="grid cols-2">{m.fields.map((f) => <FieldInput key={f.name} f={f} value={vals[f.name]} onChange={(v) => setVals({ ...vals, [f.name]: v })} />)}</div>
          {m.capabilities.some((c) => ['poll', 'pull'].includes(c)) && <Field label="Poll interval (seconds)" id="tpi"><input id="tpi" type="number" min={5} max={3600} value={interval} onChange={(e) => setIntervalS(Number(e.target.value))} /></Field>}
          {create.error && <ErrorBox error={create.error} />}
          {missing.length > 0 && <p className="muted">Required: {missing.join(', ')}</p>}
          <div className="wizard-actions">
            <button className="btn" onClick={() => setStep(0)}><ArrowLeft size={14} /> Back</button>
            <span className="spacer" />
            <button className="btn primary" disabled={create.isPending || name.trim().length < 2 || missing.length > 0} onClick={() => create.mutate(undefined)}>
              {create.isPending ? <><Loader size={14} className="spin" /> Creating…</> : <>Create & verify <ArrowRight size={14} /></>}
            </button>
          </div>
        </>
      )}
      {step === 2 && created && <PostCreate tool={created} manifest={m!} onDone={() => onDone(created.id)} />}
    </section>
  );
}

function PostCreate({ tool, manifest, onDone }: { tool: any; manifest: Manifest; onDone: () => void }) {
  const toast = useToast();
  const [checks, setChecks] = useState<any[] | null>(null);
  const test = useAct(() => post('/api/integrations/tools/' + tool.id + '/test'), ['tools'], undefined, (r) => setChecks(r.checks));
  const enable = useAct(() => post('/api/integrations/tools/' + tool.id + '/enable'), ['tools', 'approvals'], undefined, (r) => { toast(r.pending_approval ? 'Enable request sent for second-admin approval' : 'Tool enabled'); onDone(); });
  const ok = checks && checks.length > 0 && checks.every((c) => c.ok);
  const hasFails = checks && checks.some((c) => !c.ok);
  return (
    <>
      {tool.webhook?.enabled && (
        <div className="notice wizard-webhook">
          <div className="wizard-webhook-header"><Key size={16} /> <b>Webhook details (shown once)</b></div>
          <dl className="kv"><dt>URL</dt><dd className="mono wrap">{tool.webhook.url}</dd><dt>Auth</dt><dd>{tool.webhook.auth_mode}</dd><dt>Secret</dt><dd className="mono wrap">{tool.webhook.secret}</dd></dl>
          <p className="muted">Copy the secret now; it cannot be displayed again.</p>
        </div>
      )}
      {manifest.setup_hint && <div className="notice"><p className="wizard-hint">{manifest.setup_hint}</p></div>}
      <div className="wizard-test-section">
        <h3><Shield size={18} /> Test the connection</h3>
        {!checks && !test.isPending && <p className="muted">Run a connectivity test to verify the tool is reachable and credentials are valid.</p>}
        {test.isPending && (
          <div className="wizard-testing">
            <Loader size={20} className="spin" />
            <span>Testing connection…</span>
          </div>
        )}
        {checks && (
          <div className="wizard-checks">
            {checks.map((c, i) => (
              <div key={i} className={`wizard-check ${c.ok ? 'pass' : 'fail'}`}>
                {c.ok ? <CheckCircle size={18} /> : <XCircle size={18} />}
                <div>
                  <strong>{c.name}</strong>
                  {c.detail && <span className="muted"> — {c.detail}</span>}
                </div>
              </div>
            ))}
          </div>
        )}
        {ok && <div className="wizard-result pass"><CheckCircle size={18} /> All checks passed. Ready to enable.</div>}
        {hasFails && <div className="wizard-result fail"><XCircle size={18} /> Some checks failed. Fix the configuration and re-test.</div>}
      </div>
      {test.error && <ErrorBox error={test.error} />}
      {enable.error && <ErrorBox error={enable.error} />}
      <div className="wizard-actions">
        <button className="btn" onClick={onDone}>Finish later</button>
        <span className="spacer" />
        <button className="btn" disabled={test.isPending} onClick={() => test.mutate(undefined)}>
          {test.isPending ? <Loader size={14} className="spin" /> : <RotateCw size={14} />}
          {checks ? ' Re-run' : ' Run test'}
        </button>
        <button className="btn primary" disabled={!ok || enable.isPending} onClick={() => enable.mutate(undefined)}>
          {enable.isPending ? <><Loader size={14} className="spin" /> Enabling…</> : <><Zap size={14} /> Enable</>}
        </button>
      </div>
    </>
  );
}

function MaskedValue({ value }: { value: string }) {
  const [shown, setShown] = useState(false);
  return (
    <span className="row" style={{ gap: 6, alignItems: 'flex-start' }}>
      <span className="mono wrap" style={{ flex: 1 }}>{shown ? value : '••••••••'}</span>
      <button type="button" className="btn small" style={{ padding: 4 }} aria-label={shown ? 'Hide' : 'Show'} onClick={() => setShown((s) => !s)}>
        {shown ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </span>
  );
}

function ToolDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['tool', id], queryFn: () => get<any>(`/api/integrations/tools/${id}`) });
  const cat = useQuery({ queryKey: ['catalogue'], queryFn: () => get<Manifest[]>('/api/integrations/catalogue') });
  const { can } = useAuth();
  const toast = useToast();
  const keys = ['tool', 'tools'];
  const [checks, setChecks] = useState<any[] | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [edit, setEdit] = useState(false);
  const [map, setMap] = useState(false);
  const test = useAct(() => post(`/api/integrations/tools/${id}/test`), keys, undefined, (r) => setChecks(r.checks));
  const useToolAct = (path: string, msg: string) => useAct(() => post(`/api/integrations/tools/${id}/${path}`), [...keys, 'approvals'], msg);
  const enable = useAct(() => post(`/api/integrations/tools/${id}/enable`), [...keys, 'approvals'], undefined, (r) => toast(r.pending_approval ? 'Enable request sent for second-admin approval' : 'Tool enabled'));
  const pause = useToolAct('pause', 'Paused');
  const resume = useToolAct('resume', 'Resumed');
  const resync = useToolAct('resync', 'Re-sync started');
  const rotate = useAct(() => post(`/api/integrations/tools/${id}/rotate-secret`), keys, undefined, (r) => setSecret(r.secret));
  const disable = useAct(() => del(`/api/integrations/tools/${id}`), keys, 'Disabled; history kept');
  const purge = useAct(() => del(`/api/integrations/tools/${id}/purge`), keys, 'Tool deleted', onClose);
  if (q.isLoading) return <Drawer title="Tool" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Tool" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const t = q.data;
  const manifest = cat.data?.find((m) => m.type === t.type);
  const w = can('integrations.write');
  const lt = t.last_test?.checks as any[] | undefined;
  return (
    <Drawer title={t.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 10 }}><Status v={t.status} /><span>{t.label}</span><span className="spacer" /><span className="muted">config v{t.config_version}</span></div>
      <dl className="kv"><dt>Last success</dt><dd>{when(t.health?.last_success_at)}</dd><dt>Lag</dt><dd>{t.health?.lag_seconds != null ? `${Math.round(t.health.lag_seconds)}s` : '—'}</dd><dt>Items today / total</dt><dd>{t.health?.items_today ?? 0} / {t.health?.items_total ?? 0}</dd><dt>Consecutive errors</dt><dd>{t.health?.error_count ?? 0}</dd>
        {t.health?.last_error && <><dt>Last error</dt><dd className="wrap text-bad">{t.health.last_error}</dd></>}<dt>Poll interval</dt><dd>{t.poll_interval}s</dd><dt>Capabilities</dt><dd>{t.capabilities.join(', ')}</dd></dl>
      <h3><Settings size={16} /> Configuration</h3>
      <dl className="kv">{Object.entries(t.config).map(([k, v]) => <Fragment key={k}><dt>{titleCase(k)}</dt><dd className="mono wrap">{k === 'ca_cert' ? <MaskedValue value={String(v)} /> : Array.isArray(v) ? v.join(', ') : String(v)}</dd></Fragment>)}
        {t.secrets_set.map((s: string) => <Fragment key={s}><dt>{titleCase(s)}</dt><dd className="muted">•••••••• (encrypted)</dd></Fragment>)}</dl>
      {t.webhook.enabled && <><h3><Key size={16} /> Webhook</h3><dl className="kv"><dt>URL</dt><dd className="mono wrap"><MaskedValue value={t.webhook.url} /></dd><dt>Auth</dt><dd>{t.webhook.auth_mode}</dd><dt>Secret</dt><dd>{t.webhook.secret_set ? 'set' : 'not set'}</dd></dl></>}
      {secret && <div className="notice"><div className="wizard-webhook-header"><Key size={16} /> <b>New webhook secret (shown once)</b></div><div className="mono wrap">{secret}</div><p className="muted">Update the sending system now.</p></div>}
      {t.setup_hint && <p className="muted wizard-hint">{t.setup_hint}</p>}
      {(checks ?? lt) && (
        <>
          <h3><Shield size={16} /> Last test {t.last_test?.at ? `· ${ago(t.last_test.at)}` : ''}</h3>
          <div className="wizard-checks drawer-checks">
            {(checks ?? lt)!.map((c, i) => (
              <div key={i} className={`wizard-check ${c.ok ? 'pass' : 'fail'}`}>
                {c.ok ? <CheckCircle size={16} /> : <XCircle size={16} />}
                <div><strong>{c.name}</strong>{c.detail && <span className="muted"> — {c.detail}</span>}</div>
              </div>
            ))}
          </div>
        </>
      )}
      {[test, enable, pause, resume, resync, rotate, disable, purge].map((m, i) => m.error ? <ErrorBox key={i} error={m.error} /> : null)}
      {w && (
        <div className="drawer-toolbar">
          <button className="btn small" onClick={() => test.mutate(undefined)} disabled={test.isPending}><Play size={13} /> Test</button>
          {!t.enabled && t.status !== 'paused' && <button className="btn small primary" onClick={() => enable.mutate(undefined)}><Power size={13} /> Enable</button>}
          {t.enabled && <button className="btn small" onClick={() => pause.mutate(undefined)}><Pause size={13} /> Pause</button>}
          {t.status === 'paused' && <button className="btn small primary" onClick={() => resume.mutate(undefined)}><Play size={13} /> Resume</button>}
          {t.enabled && <button className="btn small" onClick={() => resync.mutate(undefined)}><RefreshCw size={13} /> Re-sync</button>}
          {t.webhook.enabled && <button className="btn small" onClick={() => { if (confirm('Rotate the webhook secret? The sender must be updated.')) rotate.mutate(undefined); }}><RotateCw size={13} /> Rotate</button>}
          {manifest && <button className="btn small" onClick={() => setEdit(true)}><Settings size={13} /> Edit</button>}
          <button className="btn small" onClick={() => setMap(true)}><MapIcon size={13} /> Mapping</button>
          {t.status !== 'disabled' && <button className="btn small danger" onClick={() => { if (confirm('Disable this tool? History is kept.')) disable.mutate(undefined); }}><Power size={13} /> Disable</button>}
          <button className="btn small danger" disabled={purge.isPending} onClick={() => { if (confirm(`Permanently delete "${t.name}"? Its configuration and secrets cannot be recovered. Alerts already ingested are kept.`) && prompt(`Type the tool's name to confirm: ${t.name}`) === t.name) purge.mutate(undefined); }}><Trash2 size={13} /> Delete</button>
        </div>
      )}
      {edit && manifest && <EditConfig tool={t} manifest={manifest} onClose={() => setEdit(false)} />}
      {map && <Mapping tool={t} onClose={() => setMap(false)} />}
    </Drawer>
  );
}

function EditConfig({ tool, manifest, onClose }: { tool: any; manifest: Manifest; onClose: () => void }) {
  const [vals, setVals] = useState<Record<string, any>>({ ...tool.config });
  const save = useAct(() => put(`/api/integrations/tools/${tool.id}/config`, { values: cleanValues(manifest, vals) }), ['tool', 'tools'], 'Saved. Re-test and re-enable to apply.', onClose);
  return (
    <Modal title={`Edit ${tool.name}`} onClose={onClose} wide>
      <p className="muted">Saving disables the tool until it is re-tested and re-enabled.</p>
      <div className="grid cols-2">{manifest.fields.map((f) => <FieldInput key={f.name} f={f} editing value={vals[f.name]} onChange={(v) => setVals({ ...vals, [f.name]: v })} />)}</div>
      {save.error && <ErrorBox error={save.error} />}
      <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate(undefined)}>
        {save.isPending ? <><Loader size={14} className="spin" /> Saving…</> : 'Save'}
      </button>
    </Modal>
  );
}

function Mapping({ tool, onClose }: { tool: any; onClose: () => void }) {
  const [text, setText] = useState(Object.entries(tool.severity_map ?? {}).map(([k, v]) => `${k}=${v}`).join('\n'));
  const parse = () => Object.fromEntries(text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const [k, ...r] = l.split('='); return [k.trim(), r.join('=').trim()]; }));
  const save = useAct(() => put(`/api/integrations/tools/${tool.id}/mapping`, { severity_map: parse(), field_map: tool.field_map ?? {} }), ['tool', 'tools'], 'Mapping saved', onClose);
  return (
    <Modal title="Severity mapping" onClose={onClose}>
      <Field label="One mapping per line: source value = platform severity" hint="Platform severities: critical, high, medium, low, info. Example: 12=high" id="sm"><textarea id="sm" className="mono" value={text} onChange={(e) => setText(e.target.value)} /></Field>
      {save.error && <ErrorBox error={save.error} />}
      <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate(undefined)}>
        {save.isPending ? <><Loader size={14} className="spin" /> Saving…</> : 'Save'}
      </button>
    </Modal>
  );
}
