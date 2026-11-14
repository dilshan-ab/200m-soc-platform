import { useQuery, useQueryClient } from '@tanstack/react-query';
import { BookOpen, FileSearch, Flag, Plus, Search, StickyNote, Tag, Target, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead } from '../components/ui';
import { del, get, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago } from '../lib/format';
import { useAct } from '../lib/mut';

type Cell = { id: string; type: 'note' | 'query' | 'finding' | 'ioc'; content: string; filters: Record<string, any>; result_count: number | null; result_sample: any[]; ran_at: string | null; created_by: string; created_at: string };
type Notebook = { id: string; title: string; description: string; case_id: string | null; client_id: string | null; tags: string[]; cells: Cell[]; created_by: string; version: number; created_at: string; updated_at: string };

const CELL_ICONS: Record<string, typeof StickyNote> = { note: StickyNote, query: Search, finding: Flag, ioc: Target };
const CELL_LABELS: Record<string, string> = { note: 'Note', query: 'Query', finding: 'Finding', ioc: 'IOC' };

export default function Notebooks() {
  const { can } = useAuth();
  const list = useQuery({ queryKey: ['notebooks'], queryFn: () => get<Notebook[]>('/api/notebooks') });
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  return (
    <>
      <PageHead title="Investigation Notebooks" sub="Capture notes, saved queries and findings as you work an investigation.">
        {can('notebooks.write') && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={16} /> New notebook</button>}
      </PageHead>
      <div className="row" style={{ gap: 24, alignItems: 'flex-start' }}>
        <div style={{ width: 280, flexShrink: 0 }}>
          {list.isLoading ? <Loading /> : list.error ? <ErrorBox error={list.error} /> : list.data!.length === 0 ? <Empty>No notebooks yet.</Empty> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {list.data!.map((nb) => (
                <button key={nb.id} type="button" className="card" style={{ textAlign: 'left', padding: 12, border: selected === nb.id ? '2px solid var(--accent)' : undefined, cursor: 'pointer' }} onClick={() => setSelected(nb.id)}>
                  <div className="row" style={{ gap: 6, alignItems: 'center' }}><BookOpen size={14} /><strong style={{ fontSize: 13 }}>{nb.title}</strong></div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>{nb.cells.length} cells · {ago(nb.updated_at)}</div>
                  {nb.tags.length > 0 && <div className="row" style={{ gap: 4, marginTop: 6, flexWrap: 'wrap' }}>{nb.tags.map((t) => <span key={t} className="badge" style={{ fontSize: 10 }}>{t}</span>)}</div>}
                </button>
              ))}
            </div>
          )}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          {selected ? <NotebookEditor id={selected} onDeleted={() => setSelected(null)} /> : <Empty>Select a notebook, or create a new one.</Empty>}
        </div>
      </div>
      {creating && <CreateNotebook onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setSelected(id); }} />}
    </>
  );
}

function CreateNotebook({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [caseId, setCaseId] = useState('');
  const create = useAct(() => post<Notebook>('/api/notebooks', { title, description, case_id: caseId || null, tags: [] }), ['notebooks'], 'Notebook created', (r) => onCreated(r.id));
  return (
    <Modal title="New investigation notebook" onClose={onClose}>
      <Field label="Title" id="nt"><input id="nt" value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
      <Field label="Description" id="nd"><textarea id="nd" value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      <Field label="Linked case ID (optional)" id="nc" hint="Leave blank for a standalone notebook."><input id="nc" value={caseId} onChange={(e) => setCaseId(e.target.value)} /></Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || title.trim().length < 2} onClick={() => create.mutate(undefined)}>Create</button>
    </Modal>
  );
}

function NotebookEditor({ id, onDeleted }: { id: string; onDeleted: () => void }) {
  const qc = useQueryClient();
  const { can } = useAuth();
  const q = useQuery({ queryKey: ['notebook', id], queryFn: () => get<Notebook>(`/api/notebooks/${id}`) });
  const [adding, setAdding] = useState<'note' | 'query' | 'finding' | 'ioc' | null>(null);
  const writable = can('notebooks.write');

  const saveCells = useAct((cells: Cell[]) => put(`/api/notebooks/${id}/cells`, { version: q.data!.version, cells }), ['notebook', 'notebooks']);
  const delNotebook = useAct(() => del(`/api/notebooks/${id}`), ['notebooks'], 'Notebook deleted', onDeleted);

  function updateCell(cellId: string, patchFn: (c: Cell) => Cell) {
    const nb = q.data!;
    saveCells.mutate(nb.cells.map((c) => (c.id === cellId ? patchFn(c) : c)));
  }
  function removeCell(cellId: string) {
    const nb = q.data!;
    saveCells.mutate(nb.cells.filter((c) => c.id !== cellId));
  }
  function moveCell(cellId: string, dir: -1 | 1) {
    const nb = q.data!;
    const i = nb.cells.findIndex((c) => c.id === cellId);
    const j = i + dir;
    if (j < 0 || j >= nb.cells.length) return;
    const next = [...nb.cells];
    [next[i], next[j]] = [next[j], next[i]];
    saveCells.mutate(next);
  }
  async function runQuery(cellId: string) {
    const cell = q.data!.cells.find((c) => c.id === cellId);
    if (!cell) return;
    try {
      const result = await get<any>('/api/alerts', { ...cell.filters, limit: 10 });
      updateCell(cellId, (c) => ({ ...c, result_count: result.total, result_sample: result.items.slice(0, 10), ran_at: new Date().toISOString() }));
    } catch { /* surfaced via saveCells error state on next save attempt */ }
  }

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const nb = q.data!;

  return (
    <div className="card" style={{ padding: 20 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 4 }}>
        <h2 style={{ margin: 0 }}>{nb.title}</h2>
        {writable && <button className="btn small danger" onClick={() => { if (confirm(`Delete notebook "${nb.title}"? This cannot be undone.`)) delNotebook.mutate(undefined); }}><Trash2 size={14} /> Delete</button>}
      </div>
      {nb.description && <p style={{ color: 'var(--muted)', marginTop: 4 }}>{nb.description}</p>}
      {nb.case_id && <p style={{ fontSize: 12, color: 'var(--muted)' }}><Tag size={12} style={{ verticalAlign: -2 }} /> Linked to case {nb.case_id}</p>}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
        {nb.cells.length === 0 && <Empty>No cells yet. Add a note, saved query, or finding below.</Empty>}
        {nb.cells.map((cell, i) => {
          const Icon = CELL_ICONS[cell.type];
          return (
            <div key={cell.id} className="card" style={{ padding: 14, borderLeft: `3px solid var(--accent)` }}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
                <span className="row" style={{ gap: 6, alignItems: 'center' }}><Icon size={14} /><strong style={{ fontSize: 12 }}>{CELL_LABELS[cell.type]}</strong><small style={{ color: 'var(--muted)' }}>{ago(cell.created_at)} · {cell.created_by}</small></span>
                {writable && (
                  <span className="row" style={{ gap: 4 }}>
                    <button className="btn small" disabled={i === 0} onClick={() => moveCell(cell.id, -1)}>↑</button>
                    <button className="btn small" disabled={i === nb.cells.length - 1} onClick={() => moveCell(cell.id, 1)}>↓</button>
                    <button className="btn small danger" onClick={() => removeCell(cell.id)}><Trash2 size={12} /></button>
                  </span>
                )}
              </div>
              {cell.type === 'query' ? (
                <>
                  <div className="mono" style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>{JSON.stringify(cell.filters)}</div>
                  <button className="btn small" onClick={() => runQuery(cell.id)}><FileSearch size={12} /> Run query</button>
                  {cell.ran_at && <div style={{ marginTop: 8, fontSize: 12 }}>
                    {cell.result_count} matching alert(s) · last run {ago(cell.ran_at)}
                    {cell.result_sample.length > 0 && (
                      <ul style={{ marginTop: 6 }}>{cell.result_sample.map((a: any) => <li key={a.id} style={{ fontSize: 12 }}>[{a.severity}] {a.title}</li>)}</ul>
                    )}
                  </div>}
                </>
              ) : (
                <div style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{cell.content || <em style={{ color: 'var(--muted)' }}>Empty</em>}</div>
              )}
            </div>
          );
        })}
      </div>

      {writable && (
        <div className="row" style={{ gap: 8, marginTop: 16, flexWrap: 'wrap' }}>
          <button className="btn small" onClick={() => setAdding('note')}>+ Note</button>
          <button className="btn small" onClick={() => setAdding('query')}>+ Saved query</button>
          <button className="btn small" onClick={() => setAdding('finding')}>+ Finding</button>
          <button className="btn small" onClick={() => setAdding('ioc')}>+ IOC</button>
        </div>
      )}
      {saveCells.error && <ErrorBox error={saveCells.error} />}
      {adding && <AddCellModal type={adding} onClose={() => setAdding(null)} onAdd={async (content, filters) => {
        await post(`/api/notebooks/${id}/cells/new`, { type: adding, content, filters });
        setAdding(null);
        void qc.invalidateQueries({ queryKey: ['notebook', id] });
      }} />}
    </div>
  );
}

function AddCellModal({ type, onClose, onAdd }: { type: 'note' | 'query' | 'finding' | 'ioc'; onClose: () => void; onAdd: (content: string, filters: Record<string, any>) => void | Promise<void> }) {
  const [content, setContent] = useState('');
  const [severity, setSeverity] = useState('');
  const [host, setHost] = useState('');
  const [status, setStatus] = useState('');
  return (
    <Modal title={`Add ${CELL_LABELS[type]} cell`} onClose={onClose}>
      {type === 'query' ? (
        <>
          <Field label="Severity" id="qs"><select id="qs" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">Any</option>{['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
          <Field label="Host contains" id="qh"><input id="qh" value={host} onChange={(e) => setHost(e.target.value)} /></Field>
          <Field label="Status" id="qst"><select id="qst" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Any</option>{['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'].map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
          <button className="btn primary" onClick={() => onAdd('', { ...(severity ? { severity: [severity] } : {}), ...(host ? { host } : {}), ...(status ? { status: [status] } : {}) })}>Add</button>
        </>
      ) : (
        <>
          <Field label="Content" id="cc" hint={type === 'ioc' ? 'One indicator per line.' : undefined}><textarea id="cc" rows={6} value={content} onChange={(e) => setContent(e.target.value)} autoFocus /></Field>
          <button className="btn primary" disabled={!content.trim()} onClick={() => onAdd(content, {})}>Add</button>
        </>
      )}
    </Modal>
  );
}
