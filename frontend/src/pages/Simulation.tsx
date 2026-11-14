import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Crosshair, Play, Target, Zap } from 'lucide-react';
import { useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';
import { get, post } from '../lib/api';

type Platform = { system_type: string; name: string; description: string; configured: boolean; tool_id: string | null; capabilities: string[] };

const TYPE_ICONS: Record<string, typeof Target> = { caldera: Crosshair, atomic_red_team: Zap, attack_simulator: Target };
const TYPE_COLORS: Record<string, string> = { caldera: 'var(--red)', atomic_red_team: 'var(--yellow)', attack_simulator: 'var(--accent)' };

export default function Simulation() {
  const [tab, setTab] = useState<'platforms' | 'run' | 'results'>('platforms');
  return (
    <>
      <PageHead title="Attack Simulation" sub="Breach and attack simulation — validate detection coverage with MITRE ATT&CK techniques." />
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={tab === 'platforms' ? 'active' : ''} onClick={() => setTab('platforms')}>Platforms</button>
        <button className={tab === 'run' ? 'active' : ''} onClick={() => setTab('run')}>Run Simulation</button>
        <button className={tab === 'results' ? 'active' : ''} onClick={() => setTab('results')}>Results</button>
      </div>
      {tab === 'platforms' && <PlatformsPanel />}
      {tab === 'run' && <RunPanel />}
      {tab === 'results' && <ResultsPanel />}
    </>
  );
}

function PlatformsPanel() {
  const platforms = useQuery({ queryKey: ['sim-platforms'], queryFn: () => get<Platform[]>('/api/simulation/platforms') });
  if (platforms.isLoading) return <Loading />;
  if (platforms.error) return <ErrorBox error={platforms.error} />;

  const data = platforms.data!;
  if (!data.length) return <Empty>No attack simulation connectors available.</Empty>;

  return (
    <div className="grid cols-3" style={{ gap: 16 }}>
      {data.map((p) => {
        const Icon = TYPE_ICONS[p.system_type] || Target;
        return (
          <div key={p.system_type} className="card" style={{ padding: 20, borderTop: `3px solid ${p.configured ? TYPE_COLORS[p.system_type] ?? 'var(--accent)' : 'var(--border)'}` }}>
            <div className="row" style={{ gap: 8, marginBottom: 12 }}>
              <Icon size={24} style={{ color: TYPE_COLORS[p.system_type] ?? 'var(--accent)' }} />
              <div>
                <strong>{p.name}</strong>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>{p.system_type}</div>
              </div>
            </div>
            <p style={{ fontSize: 13, color: 'var(--muted)', margin: '0 0 12px' }}>{p.description}</p>
            <div className="row" style={{ gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
              {p.capabilities.map((c) => <span key={c} className="badge">{c}</span>)}
            </div>
            <span className="badge" style={{ background: p.configured ? 'var(--green)' : 'var(--muted)', color: '#fff' }}>
              {p.configured ? 'Configured' : 'Not configured'}
            </span>
            {!p.configured && <p style={{ fontSize: 12, color: 'var(--muted)', margin: '8px 0 0' }}>Configure via Integrations page to enable.</p>}
          </div>
        );
      })}
    </div>
  );
}

function RunPanel() {
  const platforms = useQuery({ queryKey: ['sim-platforms'], queryFn: () => get<Platform[]>('/api/simulation/platforms') });
  const [selectedTool, setSelectedTool] = useState('');
  const [actionKey, setActionKey] = useState('');
  const [targets, setTargets] = useState('');
  const [params, setParams] = useState('{}');
  const qc = useQueryClient();

  const run = useMutation({
    mutationFn: () => post('/api/simulation/run', {
      tool_id: selectedTool, action_key: actionKey, targets: targets.split(',').map((t) => t.trim()).filter(Boolean),
      params: (() => { try { return JSON.parse(params); } catch { return {}; } })(),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sim-results'] }); },
  });

  if (platforms.isLoading) return <Loading />;
  if (platforms.error) return <ErrorBox error={platforms.error} />;

  const configured = platforms.data!.filter((p) => p.configured);
  if (!configured.length) return <Empty>No simulation platforms configured. Set up a connector in the Integrations page first.</Empty>;

  const ACTION_OPTIONS: Record<string, { key: string; label: string }[]> = {
    caldera: [{ key: 'run_adversary', label: 'Run adversary emulation' }, { key: 'stop_operation', label: 'Stop operation' }],
    atomic_red_team: [{ key: 'run_atomic', label: 'Run atomic test' }, { key: 'cleanup_atomic', label: 'Cleanup test' }],
    attack_simulator: [{ key: 'run_simulation', label: 'Run simulation' }, { key: 'stop_simulation', label: 'Stop simulation' }],
  };

  const selected = configured.find((p) => p.tool_id === selectedTool);
  const actions = selected ? ACTION_OPTIONS[selected.system_type] ?? [] : [];

  return (
    <div className="card" style={{ padding: 20, maxWidth: 600 }}>
      <h3 style={{ marginTop: 0, marginBottom: 16 }}><Play size={18} style={{ verticalAlign: -3 }} /> Execute Simulation</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <label>
          <small>Platform</small>
          <select value={selectedTool} onChange={(e) => { setSelectedTool(e.target.value); setActionKey(''); }}>
            <option value="">Select platform…</option>
            {configured.map((p) => <option key={p.tool_id} value={p.tool_id!}>{p.name}</option>)}
          </select>
        </label>
        {selected && (
          <label>
            <small>Action</small>
            <select value={actionKey} onChange={(e) => setActionKey(e.target.value)}>
              <option value="">Select action…</option>
              {actions.map((a) => <option key={a.key} value={a.key}>{a.label}</option>)}
            </select>
          </label>
        )}
        <label>
          <small>Targets (comma-separated)</small>
          <input type="text" placeholder="e.g. 10.0.0.5, workstation-01" value={targets} onChange={(e) => setTargets(e.target.value)} />
        </label>
        <label>
          <small>Parameters (JSON)</small>
          <textarea rows={4} value={params} onChange={(e) => setParams(e.target.value)} style={{ fontFamily: 'monospace', fontSize: 12 }} />
        </label>
        <div className="row" style={{ gap: 8 }}>
          <button className="btn primary" onClick={() => run.mutate()} disabled={run.isPending || !selectedTool || !actionKey}>
            {run.isPending ? 'Running…' : 'Execute'}
          </button>
          <AlertTriangle size={14} style={{ color: 'var(--yellow)' }} />
          <small style={{ color: 'var(--muted)' }}>Requires approval for high-risk actions</small>
        </div>
        {run.error && <ErrorBox error={run.error} />}
        {run.data && (
          <div className="card" style={{ padding: 12, background: 'var(--surface-alt, var(--surface))', borderLeft: '3px solid var(--green)' }}>
            <strong>Simulation started</strong>
            <pre style={{ margin: '8px 0 0', fontSize: 12, whiteSpace: 'pre-wrap' }}>{JSON.stringify((run.data as any).result, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultsPanel() {
  const platforms = useQuery({ queryKey: ['sim-platforms'], queryFn: () => get<Platform[]>('/api/simulation/platforms') });
  const [selectedTool, setSelectedTool] = useState('');

  const results = useQuery({
    queryKey: ['sim-results', selectedTool],
    queryFn: () => post<{ findings: any[]; count: number }>('/api/simulation/results', { tool_id: selectedTool, action_key: '', targets: [], params: {} }),
    enabled: !!selectedTool,
  });

  if (platforms.isLoading) return <Loading />;
  const configured = platforms.data?.filter((p) => p.configured) ?? [];

  return (
    <>
      <div className="row" style={{ gap: 8, marginBottom: 16 }}>
        <select value={selectedTool} onChange={(e) => setSelectedTool(e.target.value)}>
          <option value="">Select platform…</option>
          {configured.map((p) => <option key={p.tool_id} value={p.tool_id!}>{p.name}</option>)}
        </select>
      </div>
      {!selectedTool && <Empty>Select a simulation platform to view results.</Empty>}
      {results?.isLoading && <Loading />}
      {results?.error && <ErrorBox error={results.error} />}
      {results?.data && (
        results.data.findings.length === 0 ? <Empty>No simulation results found.</Empty> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Technique</th>
                  <th>Status</th>
                  <th>Detected</th>
                  <th>Host</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {results.data.findings.map((f: any) => (
                  <tr key={f.id}>
                    <td className="mono" style={{ fontSize: 12 }}>{f.id}</td>
                    <td>
                      <span className="mono" style={{ fontSize: 12 }}>{f.technique_id}</span>
                      {f.technique_name && <div style={{ fontSize: 12, color: 'var(--muted)' }}>{f.technique_name}</div>}
                    </td>
                    <td>
                      <span className="badge" style={{ background: f.status === 'success' ? 'var(--green)' : f.status === 'failed' ? 'var(--red)' : 'var(--muted)', color: '#fff' }}>
                        {f.status}
                      </span>
                    </td>
                    <td>
                      {f.detected != null && (
                        <span className="badge" style={{ background: f.detected ? 'var(--green)' : 'var(--red)', color: '#fff' }}>
                          {f.detected ? 'Yes' : 'No'}
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>{f.host || f.hostname || '—'}</td>
                    <td style={{ fontSize: 12, color: 'var(--muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.tactic || f.scenario || f.test_name || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </>
  );
}
