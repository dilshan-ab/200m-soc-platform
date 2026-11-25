import { useQuery } from '@tanstack/react-query';
import { CheckCircle2, ClipboardList, Eye, Plus, Send, UserCheck } from 'lucide-react';
import { useId, useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Status } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useAct } from '../lib/mut';
import { REFRESH_MS } from '../lib/refresh';

type Item = { title: string; priority?: 'high' | 'medium' | 'low'; note?: string };
type Handoff = {
  id: string; shift_name: string; status: 'draft' | 'submitted' | 'acknowledged'; summary: string; open_items: Item[]; watch_items: Item[];
  handoff_notes: string; from_analyst: string | null; to_analyst: string | null; submitted_at: string | null; acknowledged_at: string | null;
  acknowledged_by: string | null; created_by: string | null; created_at: string; updated_at: string;
};

export default function ShiftHandoff() {
  const { can } = useAuth();
  const pending = useQuery({ queryKey: ['handoffs-pending'], queryFn: () => get<Handoff[]>('/api/handoffs/pending'), refetchInterval: REFRESH_MS });
  const recent = useQuery({ queryKey: ['handoffs'], queryFn: () => get<Handoff[]>('/api/handoffs') });
  const [creating, setCreating] = useState(false);
  const [viewing, setViewing] = useState<string | null>(null);

  return (
    <>
      <PageHead title="Shift Handoff" sub="Hand off open items, watch items, and context to the next analyst — cleanly." eyebrow="RESPOND">
        {can('handoff.write') && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={16} /> New handoff</button>}
      </PageHead>

      <h3 style={{ marginBottom: 10 }}>Awaiting your acknowledgement</h3>
      {pending.isLoading ? <Loading /> : pending.error ? <ErrorBox error={pending.error} /> : pending.data!.length === 0 ? <Empty>Nothing waiting on you right now.</Empty> : (
        <div className="handoff-grid" style={{ marginBottom: 28 }}>
          {pending.data!.map((h) => <HandoffCard key={h.id} h={h} onOpen={() => setViewing(h.id)} />)}
        </div>
      )}

      <h3 style={{ marginBottom: 10 }}>Recent handoffs</h3>
      {recent.isLoading ? <Loading /> : recent.error ? <ErrorBox error={recent.error} /> : recent.data!.length === 0 ? <Empty>No handoffs yet.</Empty> : (
        <div className="handoff-grid">{recent.data!.map((h) => <HandoffCard key={h.id} h={h} onOpen={() => setViewing(h.id)} />)}</div>
      )}

      {creating && <CreateHandoff onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setViewing(id); }} />}
      {viewing && <HandoffDrawer id={viewing} onClose={() => setViewing(null)} />}
    </>
  );
}

function HandoffCard({ h, onOpen }: { h: Handoff; onOpen: () => void }) {
  return (
    <button type="button" className={`card handoff-card status-${h.status}`} style={{ cursor: 'pointer', textAlign: 'left' }} onClick={onOpen}>
      <div className="row" style={{ justifyContent: 'space-between' }}><strong>{h.shift_name || 'Shift handoff'}</strong><Status v={h.status} /></div>
      <p style={{ margin: 0, color: 'var(--muted)', fontSize: 13 }}>{h.summary || <em>No summary</em>}</p>
      <div className="row" style={{ gap: 12, fontSize: 11, color: 'var(--muted)' }}>
        <span><ClipboardList size={12} style={{ verticalAlign: -2 }} /> {h.open_items.length} open</span>
        <span><Eye size={12} style={{ verticalAlign: -2 }} /> {h.watch_items.length} watching</span>
        <span className="spacer" />
        <span>{ago(h.submitted_at || h.created_at)}</span>
      </div>
    </button>
  );
}

function ItemsEditor({ label, hint, value, onChange }: { label: string; hint: string; value: Item[]; onChange: (v: Item[]) => void }) {
  const id = useId();
  const [text, setText] = useState(() => value.map((i) => i.title).join('\n'));
  return <Field id={id} label={label} hint={hint}><textarea id={id} rows={4} value={text} onChange={(e) => {
    setText(e.target.value);
    onChange(e.target.value.split('\n').filter((line) => line.trim()).map((title) => ({ title: title.trim(), priority: 'medium' as const })));
  }} /></Field>;
}

function CreateHandoff({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [v, setV] = useState({ shift_name: '', summary: '', handoff_notes: '', open_items: [] as Item[], watch_items: [] as Item[] });
  const create = useAct(() => post<Handoff>('/api/handoffs', v), ['handoffs'], 'Handoff saved as draft', (r) => onCreated(r.id));
  return (
    <Modal title="New shift handoff" onClose={onClose} wide>
      <Field label="Shift" id="hn" hint="e.g. Night Shift, Weekend On-call"><input id="hn" value={v.shift_name} onChange={(e) => setV({ ...v, shift_name: e.target.value })} /></Field>
      <Field label="Summary" id="hs"><textarea id="hs" rows={3} value={v.summary} onChange={(e) => setV({ ...v, summary: e.target.value })} /></Field>
      <div className="grid cols-2">
        <ItemsEditor label="Open items" hint="One per line." value={v.open_items} onChange={(open_items) => setV({ ...v, open_items })} />
        <ItemsEditor label="Watch items" hint="One per line." value={v.watch_items} onChange={(watch_items) => setV({ ...v, watch_items })} />
      </div>
      <Field label="Notes for the incoming analyst" id="hnotes"><textarea id="hnotes" rows={3} value={v.handoff_notes} onChange={(e) => setV({ ...v, handoff_notes: e.target.value })} /></Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending} onClick={() => create.mutate(undefined)}>Save as draft</button>
    </Modal>
  );
}

function HandoffDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['handoff', id], queryFn: () => get<Handoff>(`/api/handoffs/${id}`) });
  const { can, me } = useAuth();
  const submit = useAct(() => post(`/api/handoffs/${id}/submit`), ['handoffs', 'handoff', 'handoffs-pending'], 'Handoff submitted');
  const ack = useAct(() => post(`/api/handoffs/${id}/acknowledge`), ['handoffs', 'handoff', 'handoffs-pending'], 'Acknowledged — you now own this shift’s open items');

  if (q.isLoading) return <Drawer title="Handoff" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Handoff" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const h = q.data!;
  const mine = h.created_by === me?.name || h.created_by === me?.email;

  return (
    <Drawer title={h.shift_name || 'Shift handoff'} onClose={onClose}>
      <div className="row" style={{ marginBottom: 14 }}><Status v={h.status} /><span style={{ color: 'var(--muted)', fontSize: 12 }}>from {h.from_analyst ?? 'unknown'}{h.to_analyst ? ` to ${h.to_analyst}` : ''}</span></div>
      {h.summary && <p>{h.summary}</p>}

      {h.open_items.length > 0 && <>
        <h4 style={{ marginTop: 18, marginBottom: 8 }}>Open items</h4>
        <ul className="item-list">{h.open_items.map((i, idx) => <li key={idx}><span className={`item-priority-dot ${i.priority ?? 'medium'}`} />{i.title}</li>)}</ul>
      </>}
      {h.watch_items.length > 0 && <>
        <h4 style={{ marginTop: 18, marginBottom: 8 }}>Watch items</h4>
        <ul className="item-list">{h.watch_items.map((i, idx) => <li key={idx}><Eye size={12} style={{ marginTop: 3, flex: 'none' }} />{i.title}</li>)}</ul>
      </>}
      {h.handoff_notes && <><h4 style={{ marginTop: 18, marginBottom: 8 }}>Notes</h4><p style={{ whiteSpace: 'pre-wrap' }}>{h.handoff_notes}</p></>}

      <h4 style={{ marginTop: 18, marginBottom: 8 }}>Timeline</h4>
      <ul className="handoff-timeline">
        <li>Created {ago(h.created_at)}</li>
        {h.submitted_at && <li>Submitted {when(h.submitted_at)}</li>}
        {h.acknowledged_at && <li>Acknowledged by {h.acknowledged_by} {when(h.acknowledged_at)}</li>}
      </ul>

      {(submit.error || ack.error) && <ErrorBox error={(submit.error || ack.error)!} />}
      <div className="row" style={{ marginTop: 20, gap: 8 }}>
        {h.status === 'draft' && mine && can('handoff.write') && <button className="btn primary" disabled={submit.isPending} onClick={() => submit.mutate(undefined)}><Send size={14} /> Submit handoff</button>}
        {h.status === 'submitted' && can('handoff.write') && <button className="btn primary" disabled={ack.isPending} onClick={() => ack.mutate(undefined)}><UserCheck size={14} /> Acknowledge — I've got it</button>}
        {h.status === 'acknowledged' && <span className="row" style={{ color: 'var(--ok)', gap: 6 }}><CheckCircle2 size={16} /> Handed off cleanly</span>}
      </div>
    </Drawer>
  );
}
