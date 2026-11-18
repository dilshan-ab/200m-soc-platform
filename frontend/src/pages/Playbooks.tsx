import { useQuery } from '@tanstack/react-query';
import { Fragment, useCallback, useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
  type Node,
  type Edge,
  type Connection,
  type NodeProps,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Status } from '../components/ui';
import { del, get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useAct } from '../lib/mut';

type PB = { id: string; name: string; description: string; trigger: string; status: string; enabled: boolean; version: number; client_id: string | null; created_by: string; created_at: string; updated_at: string; nodes?: any[]; edges?: any[]; runs?: Run[] };
type Run = { id: string; playbook_id: string; trigger_ref: string; status: string; current_node: string; execution_log: any[]; error: string; started_at: string; finished_at: string | null };
type ActionSpec = { key: string; label: string; system: string; risk: string; reversible: boolean; approvals: number; target_kind: string; params: string[]; capability: string };
type Destination = { id: string; name: string; channel: string };

const CONDITION_FIELDS = ['severity', 'source', 'rule_id', 'host', 'category', 'title', 'client_id', 'src_ip', 'username', 'status'];
const CONDITION_OPS = ['eq', 'ne', 'in', 'gte', 'contains', 'startswith'];
const ALERT_STATUSES = ['acknowledged', 'investigating', 'false_positive', 'resolved'];
const ACTION_TYPES = [
  { value: 'set_status', label: 'Set alert status' },
  { value: 'add_note', label: 'Add a note to the alert' },
  { value: 'create_case', label: 'Create a case' },
  { value: 'enrich', label: 'Enrich the alert indicator' },
  { value: 'request_action', label: 'Request a response action' },
];

const NODE_COLORS: Record<string, string> = {
  trigger: '#3b82f6',
  condition: '#f59e0b',
  action: '#10b981',
  notification: '#8b5cf6',
  approval: '#ef4444',
  end: '#6b7280',
};

type NodeData = { label: string; description?: string;[key: string]: unknown };

function nodeSummary(type: string, data: NodeData): string | null {
  if (type === 'action') {
    if (!data.action_type) return 'not configured';
    if (data.action_type === 'request_action') return `request_action: ${data.action_key || '(no action chosen)'}`;
    return String(data.action_type);
  }
  if (type === 'condition') {
    if (!data.field || !data.op) return 'not configured';
    return `${data.field} ${data.op} ${JSON.stringify(data.value)}`;
  }
  if (type === 'notification') {
    return data.destination_id ? 'configured' : 'not configured';
  }
  return null;
}

function BaseNode({ data, type }: NodeProps<Node<NodeData>>) {
  const color = NODE_COLORS[type as string] ?? '#6b7280';
  const summary = nodeSummary(type as string, data);
  return (
    <div style={{ background: 'var(--card)', border: `2px solid ${color}`, borderRadius: 8, padding: '8px 14px', minWidth: 140, fontSize: 13 }}>
      <Handle type="target" position={Position.Top} style={{ background: color }} />
      <div style={{ fontWeight: 600, color, fontSize: 11, textTransform: 'uppercase', marginBottom: 2 }}>{type as string}</div>
      <div style={{ color: 'var(--fg)' }}>{data.label}</div>
      {data.description && <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>{data.description}</div>}
      {summary && <div style={{ color: summary === 'not configured' ? 'var(--danger)' : 'var(--muted)', fontSize: 11, marginTop: 2 }}>{summary}</div>}
      <Handle type="source" position={Position.Bottom} style={{ background: color }} />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  trigger: BaseNode,
  condition: BaseNode,
  action: BaseNode,
  notification: BaseNode,
  approval: BaseNode,
  end: BaseNode,
};

const DEFAULT_NODES: Node[] = [
  { id: 'trigger-1', type: 'trigger', position: { x: 250, y: 0 }, data: { label: 'Alert created', description: 'When a new alert fires' } },
  { id: 'action-1', type: 'action', position: { x: 250, y: 120 }, data: { label: 'Enrich IOC', description: 'VirusTotal/AbuseIPDB lookup on the alert indicator', action_type: 'enrich' } },
  { id: 'condition-1', type: 'condition', position: { x: 250, y: 240 }, data: { label: 'High severity+?', description: '', field: 'severity', op: 'gte', value: 'high' } },
  { id: 'action-2', type: 'action', position: { x: 80, y: 370 }, data: { label: 'Create case', description: 'Escalate to IR', action_type: 'create_case' } },
  { id: 'notification-1', type: 'notification', position: { x: 420, y: 370 }, data: { label: 'Notify analyst', description: '', destination_id: '' } },
  { id: 'end-1', type: 'end', position: { x: 250, y: 500 }, data: { label: 'Done' } },
];
const DEFAULT_EDGES: Edge[] = [
  { id: 'e1', source: 'trigger-1', target: 'action-1', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e2', source: 'action-1', target: 'condition-1', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e3', source: 'condition-1', target: 'action-2', label: 'Yes', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e4', source: 'condition-1', target: 'notification-1', label: 'No', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e5', source: 'action-2', target: 'end-1', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e6', source: 'notification-1', target: 'end-1', markerEnd: { type: MarkerType.ArrowClosed } },
];

export default function Playbooks() {
  const q = useQuery({ queryKey: ['playbooks'], queryFn: () => get<Page<PB>>('/api/playbooks') });
  const { can } = useAuth();
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [building, setBuilding] = useState<string | null>(null);

  return (
    <>
      <PageHead title="Playbooks">
        {can('playbooks.write') && <button className="btn primary" onClick={() => setCreating(true)}>New playbook</button>}
      </PageHead>

      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.items.length ? (
        <Empty>No playbooks yet. Create one to automate your incident response.</Empty>
      ) : (
        <div className="grid cols-3">
          {q.data.items.map((pb) => (
            <button key={pb.id} className="card" style={{ textAlign: 'left', cursor: 'pointer' }} onClick={() => setSelected(pb.id)}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <h3 style={{ margin: 0 }}>{pb.name}</h3>
                <Status v={pb.status} />
              </div>
              <p style={{ color: 'var(--muted)', fontSize: 13, margin: '4px 0' }}>{pb.description || 'No description'}</p>
              <div style={{ fontSize: 12, color: 'var(--muted)', display: 'flex', gap: 12, marginTop: 8 }}>
                <span>v{pb.version}</span>
                <span>{pb.trigger}</span>
                {pb.enabled && <span style={{ color: 'var(--ok)' }}>enabled</span>}
              </div>
            </button>
          ))}
        </div>
      )}

      {selected && <PlaybookDetail id={selected} onClose={() => setSelected(null)} onEdit={(id) => { setSelected(null); setBuilding(id); }} />}
      {creating && <CreatePlaybook onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setBuilding(id); }} />}
      {building && <PlaybookBuilder id={building} onClose={() => setBuilding(null)} />}
    </>
  );
}

function PlaybookDetail({ id, onClose, onEdit }: { id: string; onClose: () => void; onEdit: (id: string) => void }) {
  const q = useQuery({ queryKey: ['playbook', id], queryFn: () => get<PB>(`/api/playbooks/${id}`) });
  const { can } = useAuth();
  const [expanded, setExpanded] = useState<string | null>(null);
  const publish = useAct(() => patch(`/api/playbooks/${id}`, { status: 'published' }), ['playbooks', 'playbook'], 'Published');
  const execute = useAct(() => post(`/api/playbooks/${id}/execute`), ['playbooks', 'playbook'], 'Executed');
  const remove = useAct(() => del(`/api/playbooks/${id}`), ['playbooks'], 'Deleted', onClose);
  const resume = useAct(
    (vars: { runId: string; approved: boolean }) => post(`/api/playbooks/${id}/runs/${vars.runId}/resume`, { approved: vars.approved, reason: vars.approved ? 'approved from playbook run history' : 'rejected from playbook run history' }),
    ['playbooks', 'playbook'],
    'Resumed',
  );

  if (q.isLoading) return <Drawer title="Playbook" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Playbook" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const pb = q.data!;

  return (
    <Drawer title={pb.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 12, flexWrap: 'wrap', gap: 6 }}>
        <Status v={pb.status} />
        <span style={{ color: 'var(--muted)' }}>v{pb.version} · {pb.trigger}</span>
        <span className="spacer" />
        {can('playbooks.write') && <button className="btn small" onClick={() => onEdit(id)}>Edit in builder</button>}
        {can('playbooks.write') && pb.status === 'draft' && <button className="btn small primary" onClick={() => publish.mutate(undefined)}>Publish</button>}
        {can('playbooks.execute') && pb.status === 'published' && <button className="btn small" onClick={() => execute.mutate(undefined)}>Execute</button>}
        {can('playbooks.write') && <button className="btn small danger" onClick={() => { if (confirm('Delete this playbook?')) remove.mutate(undefined); }}>Delete</button>}
      </div>
      {pb.description && <p style={{ marginBottom: 16 }}>{pb.description}</p>}

      <h4 style={{ marginTop: 16 }}>Flow preview</h4>
      <div style={{ height: 300, border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <ReactFlow nodes={pb.nodes ?? []} edges={pb.edges ?? []} nodeTypes={nodeTypes} fitView nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} panOnDrag={false} zoomOnScroll={false}>
          <Background />
        </ReactFlow>
      </div>

      {pb.runs && pb.runs.length > 0 && (
        <>
          <h4 style={{ marginTop: 16 }}>Recent runs</h4>
          <table className="table">
            <thead><tr><th>Started</th><th>Trigger</th><th>Status</th><th>Duration</th><th /></tr></thead>
            <tbody>
              {pb.runs.map((r) => (
                <Fragment key={r.id}>
                  <tr>
                    <td>{new Date(r.started_at).toLocaleString()}</td>
                    <td>{r.trigger_ref}</td>
                    <td><Status v={r.status} /></td>
                    <td>{r.finished_at ? `${((new Date(r.finished_at).getTime() - new Date(r.started_at).getTime()) / 1000).toFixed(1)}s` : '—'}</td>
                    <td>
                      <button className="btn small" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>{expanded === r.id ? 'Hide' : 'Details'}</button>
                      {r.status === 'paused' && can('playbooks.execute') && (
                        <>
                          <button className="btn small primary" style={{ marginLeft: 6 }} onClick={() => resume.mutate({ runId: r.id, approved: true })}>Approve &amp; continue</button>
                          <button className="btn small danger" style={{ marginLeft: 6 }} onClick={() => resume.mutate({ runId: r.id, approved: false })}>Reject</button>
                        </>
                      )}
                    </td>
                  </tr>
                  {expanded === r.id && (
                    <tr>
                      <td colSpan={5}>
                        {r.error && <div style={{ color: 'var(--danger)', marginBottom: 6 }}>{r.error}</div>}
                        <table className="table">
                          <thead><tr><th>Node</th><th>Type</th><th>Status</th><th>Result</th></tr></thead>
                          <tbody>
                            {r.execution_log.map((l, i) => (
                              <tr key={i}>
                                <td>{l.node_id}</td>
                                <td>{l.type}</td>
                                <td><Status v={l.status} /></td>
                                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{JSON.stringify(l.result)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Drawer>
  );
}

function CreatePlaybook({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [v, setV] = useState({ name: '', description: '', trigger: 'manual' as string });
  const create = useAct(
    () => post('/api/playbooks', { ...v, nodes: DEFAULT_NODES, edges: DEFAULT_EDGES }),
    ['playbooks'],
    'Playbook created',
    (r: any) => onCreated(r.id),
  );

  return (
    <Modal title="New playbook" onClose={onClose}>
      <Field label="Name" id="pb-name"><input id="pb-name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="Alert triage workflow" /></Field>
      <Field label="Description" id="pb-desc"><textarea id="pb-desc" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} placeholder="Automated response for high-severity alerts" /></Field>
      <Field label="Trigger" id="pb-trigger">
        <select id="pb-trigger" value={v.trigger} onChange={(e) => setV({ ...v, trigger: e.target.value })}>
          <option value="manual">Manual</option>
          <option value="alert.created">Alert created</option>
          <option value="case.created">Case created</option>
          <option value="scheduled">Scheduled</option>
        </select>
      </Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || v.name.trim().length < 2} onClick={() => create.mutate(undefined)}>Create and open builder</button>
    </Modal>
  );
}

const ADD_NODES = [
  { type: 'action', label: 'Action', desc: 'Run an automated action' },
  { type: 'condition', label: 'Condition', desc: 'Branch on a boolean check' },
  { type: 'notification', label: 'Notification', desc: 'Send alert/email/Slack' },
  { type: 'approval', label: 'Approval', desc: 'Pause until approved' },
  { type: 'end', label: 'End', desc: 'Terminal node' },
];

function PlaybookBuilder({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['playbook', id], queryFn: () => get<PB>(`/api/playbooks/${id}`) });
  if (q.isLoading) return <div className="overlay" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Loading /></div>;
  if (q.error) return <div className="overlay" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ErrorBox error={q.error} /></div>;
  return <BuilderInner pb={q.data!} onClose={onClose} />;
}

function BuilderInner({ pb, onClose }: { pb: PB; onClose: () => void }) {
  const [nodes, setNodes, onNodesChange] = useNodesState(pb.nodes as Node[] ?? []);
  const [edges, setEdges, onEdgesChange] = useEdgesState(pb.edges as Edge[] ?? []);
  const [dirty, setDirty] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [configuring, setConfiguring] = useState<Node | null>(null);

  const onConnect = useCallback((conn: Connection) => {
    setEdges((eds) => addEdge({ ...conn, markerEnd: { type: MarkerType.ArrowClosed } }, eds));
    setDirty(true);
  }, [setEdges]);

  const handleNodesChange: typeof onNodesChange = useCallback((changes) => {
    onNodesChange(changes);
    if (changes.some((c) => c.type === 'position' || c.type === 'remove')) setDirty(true);
  }, [onNodesChange]);

  const handleEdgesChange: typeof onEdgesChange = useCallback((changes) => {
    onEdgesChange(changes);
    if (changes.some((c) => c.type === 'remove')) setDirty(true);
  }, [onEdgesChange]);

  const save = useAct(
    () => patch(`/api/playbooks/${pb.id}`, { nodes, edges }),
    ['playbooks', 'playbook'],
    'Saved',
    () => setDirty(false),
  );

  const addNode = useCallback((type: string) => {
    const id = `${type}-${Date.now()}`;
    const newNode: Node = {
      id,
      type,
      position: { x: 250, y: (nodes.length) * 120 },
      data: { label: ADD_NODES.find((n) => n.type === type)?.label ?? type },
    };
    setNodes((nds) => [...nds, newNode]);
    setDirty(true);
    setAddOpen(false);
    setConfiguring(newNode);
  }, [nodes.length, setNodes]);

  const saveNodeData = useCallback((nodeId: string, data: Record<string, unknown>) => {
    setNodes((nds) => nds.map((n) => (n.id === nodeId ? { ...n, data } : n)));
    setDirty(true);
    setConfiguring(null);
  }, [setNodes]);

  const memoTypes = useMemo(() => nodeTypes, []);

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 100, background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', padding: '8px 16px', borderBottom: '1px solid var(--border)', gap: 12 }}>
        <button className="btn small" onClick={onClose}>&larr; Back</button>
        <h2 style={{ margin: 0, fontSize: 16 }}>{pb.name}</h2>
        <Status v={pb.status} />
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>v{pb.version}</span>
        <span className="spacer" />
        <div style={{ position: 'relative' }}>
          <button className="btn small" onClick={() => setAddOpen(!addOpen)}>+ Add node</button>
          {addOpen && (
            <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: 4, background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: 4, minWidth: 180, zIndex: 10 }}>
              {ADD_NODES.map((n) => (
                <button key={n.type} style={{ display: 'block', width: '100%', textAlign: 'left', padding: '6px 10px', border: 'none', background: 'none', cursor: 'pointer', borderRadius: 4, fontSize: 13, color: 'var(--fg)' }} onClick={() => addNode(n.type)}
                  onMouseOver={(e) => (e.currentTarget.style.background = 'var(--hover)')} onMouseOut={(e) => (e.currentTarget.style.background = 'none')}>
                  <div style={{ fontWeight: 600, color: NODE_COLORS[n.type] }}>{n.label}</div>
                  <div style={{ color: 'var(--muted)', fontSize: 11 }}>{n.desc}</div>
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="btn small primary" disabled={!dirty || save.isPending} onClick={() => save.mutate(undefined)}>
          {save.isPending ? 'Saving…' : dirty ? 'Save changes' : 'Saved'}
        </button>
      </div>
      <div style={{ flex: 1 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={handleNodesChange}
          onEdgesChange={handleEdgesChange}
          onConnect={onConnect}
          onNodeDoubleClick={(_, n) => setConfiguring(n)}
          nodeTypes={memoTypes}
          fitView
          deleteKeyCode="Delete"
          style={{ background: 'var(--bg)' }}
        >
          <Background />
          <Controls />
          <MiniMap nodeColor={(n) => NODE_COLORS[n.type ?? ''] ?? '#6b7280'} style={{ background: 'var(--card)' }} />
        </ReactFlow>
      </div>
      {configuring && <NodeConfigModal node={configuring} onClose={() => setConfiguring(null)} onSave={saveNodeData} />}
    </div>
  );
}

function NodeConfigModal({ node, onClose, onSave }: { node: Node; onClose: () => void; onSave: (id: string, data: Record<string, unknown>) => void }) {
  const [data, setData] = useState<Record<string, unknown>>({ ...node.data });
  const set = (patch: Record<string, unknown>) => setData((d) => ({ ...d, ...patch }));
  const type = node.type as string;

  const catalogue = useQuery({ queryKey: ['response-catalogue'], queryFn: () => get<ActionSpec[]>('/api/response/catalogue'), enabled: type === 'action' && data.action_type === 'request_action' });
  const destinations = useQuery({ queryKey: ['notification-destinations'], queryFn: () => get<Destination[]>('/api/ops/notifications/destinations'), enabled: type === 'notification' });
  const chosenAction = catalogue.data?.find((a) => a.key === data.action_key);

  return (
    <Modal title={`Configure: ${type}`} onClose={onClose} wide>
      <Field label="Label" id="nc-label"><input id="nc-label" value={String(data.label ?? '')} onChange={(e) => set({ label: e.target.value })} /></Field>
      <Field label="Description" id="nc-desc" hint="optional"><input id="nc-desc" value={String(data.description ?? '')} onChange={(e) => set({ description: e.target.value })} /></Field>

      {type === 'action' && (
        <>
          <Field label="Action type" id="nc-atype">
            <select id="nc-atype" value={String(data.action_type ?? '')} onChange={(e) => set({ action_type: e.target.value })}>
              <option value="">Select…</option>
              {ACTION_TYPES.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
            </select>
          </Field>
          {data.action_type === 'set_status' && (
            <Field label="New status" id="nc-status">
              <select id="nc-status" value={String(data.status ?? '')} onChange={(e) => set({ status: e.target.value })}>
                <option value="">Select…</option>
                {ALERT_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          )}
          {data.action_type === 'add_note' && (
            <Field label="Note text" id="nc-text"><textarea id="nc-text" value={String(data.text ?? '')} onChange={(e) => set({ text: e.target.value })} /></Field>
          )}
          {data.action_type === 'create_case' && (
            <>
              <Field label="Case title" id="nc-title" hint="optional, defaults to the alert title"><input id="nc-title" value={String(data.title ?? '')} onChange={(e) => set({ title: e.target.value })} /></Field>
              <Field label="Template" id="nc-template" hint="optional case template id"><input id="nc-template" value={String(data.template ?? '')} onChange={(e) => set({ template: e.target.value })} /></Field>
            </>
          )}
          {data.action_type === 'enrich' && (
            <p style={{ color: 'var(--muted)', fontSize: 13 }}>Enriches the triggering alert's src_ip or file_hash via the configured intel connectors.</p>
          )}
          {data.action_type === 'request_action' && (
            <>
              <Field label="Response action" id="nc-action-key" hint="from the response-action catalogue, with its own approval/risk guardrails">
                <select id="nc-action-key" value={String(data.action_key ?? '')} onChange={(e) => set({ action_key: e.target.value, params: {} })}>
                  <option value="">Select…</option>
                  {catalogue.data?.map((a) => <option key={a.key} value={a.key}>{a.label} ({a.risk}{a.approvals ? `, ${a.approvals} approval${a.approvals > 1 ? 's' : ''}` : ''})</option>)}
                </select>
              </Field>
              <Field label="Target field" id="nc-target-field" hint="which alert field supplies the target">
                <select id="nc-target-field" value={String(data.target_field ?? 'src_ip')} onChange={(e) => set({ target_field: e.target.value })}>
                  <option value="src_ip">src_ip</option>
                  <option value="host">host</option>
                  <option value="username">username</option>
                </select>
              </Field>
              {chosenAction?.params.map((p) => (
                <Field key={p} label={`Param: ${p}`} id={`nc-param-${p}`}>
                  <input id={`nc-param-${p}`} value={String((data.params as Record<string, unknown> | undefined)?.[p] ?? '')}
                    onChange={(e) => set({ params: { ...(data.params as Record<string, unknown> | undefined), [p]: e.target.value } })} />
                </Field>
              ))}
            </>
          )}
        </>
      )}

      {type === 'condition' && (
        <>
          <Field label="Field" id="nc-field">
            <select id="nc-field" value={String(data.field ?? '')} onChange={(e) => set({ field: e.target.value })}>
              <option value="">Select…</option>
              {CONDITION_FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </Field>
          <Field label="Operator" id="nc-op">
            <select id="nc-op" value={String(data.op ?? '')} onChange={(e) => set({ op: e.target.value })}>
              <option value="">Select…</option>
              {CONDITION_OPS.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </Field>
          <Field label="Value" id="nc-value" hint="outgoing edges labelled 'Yes'/'No' are followed based on this check">
            <input id="nc-value" value={String(data.value ?? '')} onChange={(e) => set({ value: e.target.value })} />
          </Field>
        </>
      )}

      {type === 'notification' && (
        <>
          <Field label="Destination" id="nc-dest">
            <select id="nc-dest" value={String(data.destination_id ?? '')} onChange={(e) => set({ destination_id: e.target.value })}>
              <option value="">Select…</option>
              {destinations.data?.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.channel})</option>)}
            </select>
          </Field>
          <Field label="Message" id="nc-message"><textarea id="nc-message" value={String(data.message ?? '')} onChange={(e) => set({ message: e.target.value })} /></Field>
        </>
      )}

      <button className="btn primary" style={{ marginTop: 12 }} onClick={() => onSave(node.id, data)}>Save node</button>
    </Modal>
  );
}
