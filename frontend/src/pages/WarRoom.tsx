import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Flame, Pin, Plus, Send, ShieldCheck, Trash2, Users } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, PageHead, Sev } from '../components/ui';
import { del, get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useLive } from '../lib/live';
import { useAct } from '../lib/mut';

type Message = { id: string; author_id: string | null; author_label: string; kind: string; content: string; pinned: boolean; created_at: string };
type WarRoomSummary = { id: string; created_by: string; title: string; status: 'active' | 'stood_down'; severity: string; participants: { user_id: string; label: string; role: string }[]; message_count: number; created_at: string; closed_at: string | null; summary: string };
type WarRoomDetail = WarRoomSummary & { messages: Message[] };

const initials = (name: string) => name.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((x) => x[0]?.toUpperCase()).join('') || '?';

export default function WarRoom() {
  const { can } = useAuth();
  const live = useLive(can('alerts.read'));
  const rooms = useQuery({ queryKey: ['warrooms'], queryFn: () => get<WarRoomSummary[]>('/api/warrooms'), refetchInterval: 10000 });
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const current = rooms.data?.find((room) => room.id === selected) ?? rooms.data?.find((room) => room.status === 'active') ?? rooms.data?.[0];

  const active = rooms.data?.filter((r) => r.status === 'active') ?? [];
  const stoodDown = rooms.data?.filter((r) => r.status === 'stood_down') ?? [];

  return (
    <>
      <PageHead title="War Room" sub="Real-time collaboration space for a major incident — chat, pinned actions, and a clean record for the post-mortem." eyebrow="OPERATIONS">
        <span className={'demo-pill' + (live ? '' : ' off')}>{live ? 'Live' : 'Offline'}</span>
        {can('warroom.write') && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={16} /> Start war room</button>}
      </PageHead>

      {rooms.isLoading ? <Loading /> : rooms.error ? <ErrorBox error={rooms.error} /> : rooms.data!.length === 0 ? <Empty>No war rooms yet. Start one when an incident needs real-time coordination.</Empty> : (
        <div className="warroom-layout">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {active.length > 0 && <div>
              <div className="nav-label" style={{ padding: '0 0 8px' }}>ACTIVE</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>{active.map((r) => <RoomListItem key={r.id} r={r} selected={r.id === current?.id} onClick={() => setSelected(r.id)} />)}</div>
            </div>}
            {stoodDown.length > 0 && <div>
              <div className="nav-label" style={{ padding: '0 0 8px' }}>STOOD DOWN</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>{stoodDown.map((r) => <RoomListItem key={r.id} r={r} selected={r.id === current?.id} onClick={() => setSelected(r.id)} />)}</div>
            </div>}
          </div>
          {current ? <ChatPanel key={current.id} id={current.id} onDeleted={() => setSelected(null)} /> : <Empty>Select a war room.</Empty>}
        </div>
      )}
      {creating && <CreateWarRoom onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setSelected(id); }} />}
    </>
  );
}

function RoomListItem({ r, selected, onClick }: { r: WarRoomSummary; selected: boolean; onClick: () => void }) {
  return (
    <button type="button" className={'warroom-list-item' + (selected ? ' selected' : '')} onClick={onClick}>
      <span className="row" style={{ gap: 6 }}>{r.status === 'active' && <span className="live-dot" />}<span className="wr-title">{r.title}</span></span>
      <span className="row" style={{ gap: 8, fontSize: 11, color: 'var(--muted)' }}><Sev v={r.severity} /><span>{r.message_count} messages</span><span className="spacer" /><span>{ago(r.created_at)}</span></span>
    </button>
  );
}

function CreateWarRoom({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [v, setV] = useState({ title: '', severity: 'critical', case_id: '' });
  const create = useAct(() => post<WarRoomSummary>('/api/warrooms', { title: v.title, severity: v.severity, case_id: v.case_id || null }), ['warrooms'], 'War room opened', (r) => onCreated(r.id));
  return (
    <Modal title="Start a war room" onClose={onClose}>
      <Field label="Title" id="wt" hint="What's happening, in a few words."><input id="wt" value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} placeholder="Ransomware activity on finance segment" /></Field>
      <Field label="Severity" id="ws"><select id="ws" value={v.severity} onChange={(e) => setV({ ...v, severity: e.target.value })}>{['critical', 'high', 'medium'].map((s) => <option key={s}>{s}</option>)}</select></Field>
      <Field label="Linked case ID (optional)" id="wc"><input id="wc" value={v.case_id} onChange={(e) => setV({ ...v, case_id: e.target.value })} /></Field>
      {create.error && <ErrorBox error={create.error} />}
      <button className="btn primary" disabled={create.isPending || v.title.trim().length < 2} onClick={() => create.mutate(undefined)}><Flame size={14} /> Open war room</button>
    </Modal>
  );
}

function ChatPanel({ id, onDeleted }: { id: string; onDeleted: () => void }) {
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['warroom', id], queryFn: () => get<WarRoomDetail>(`/api/warrooms/${id}`), refetchInterval: 4000 });
  const [draft, setDraft] = useState('');
  const [standingDown, setStandingDown] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const send = useAct(() => post(`/api/warrooms/${id}/messages`, { content: draft }), ['warroom'], undefined, () => setDraft(''));
  const remove = useAct(() => del(`/api/warrooms/${id}`), [], 'War room deleted', () => {
    qc.setQueryData<WarRoomSummary[]>(['warrooms'], (rooms) => rooms?.filter((room) => room.id !== id));
    qc.removeQueries({ queryKey: ['warroom', id], exact: true });
    onDeleted();
    void qc.invalidateQueries({ queryKey: ['warrooms'] });
  });
  const pin = useAct((mid: string) => post(`/api/warrooms/${id}/messages/${mid}/pin`), ['warroom']);

  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight }); }, [q.data?.messages.length]);

  if (q.isLoading) return <div className="chat-panel"><Loading /></div>;
  if (q.error) return <div className="chat-panel"><ErrorBox error={q.error} /></div>;
  const room = q.data!;
  const pinned = room.messages.filter((m) => m.pinned);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (draft.trim() && !send.isPending) send.mutate(undefined);
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div>
          <strong>{room.title}</strong>
          <div className="row" style={{ gap: 8, marginTop: 4 }}><Sev v={room.severity} /><span style={{ fontSize: 11, color: 'var(--muted)' }}>{room.status === 'active' ? 'Active' : `Stood down ${when(room.closed_at)}`}</span></div>
        </div>
        <div className="row" style={{ gap: 10 }}>
          <div className="participant-row">{room.participants.slice(0, 5).map((p) => <span key={p.user_id} className="participant-chip" title={p.label}>{initials(p.label)}</span>)}</div>
          {can('warroom.write') && (room.created_by === me?.id || can('warroom.manage')) && <button className="btn small danger" onClick={() => setDeleting(true)}><Trash2 size={13} /> Delete room</button>}
          {room.status === 'active' && can_manage(me) && <button className="btn small" onClick={() => setStandingDown(true)}><ShieldCheck size={13} /> Stand down</button>}
        </div>
      </div>
      {pinned.length > 0 && <div className="chat-pinned"><Pin size={13} style={{ flex: 'none', marginTop: 1 }} /><span>{pinned[pinned.length - 1].content}</span></div>}
      {room.status === 'stood_down' && room.summary && <div className="notice" style={{ margin: '12px 18px 0' }}>Stand-down summary: {room.summary}</div>}
      <div className="chat-messages" ref={scrollRef}>
        {room.messages.map((m) => m.kind === 'system' ? (
          <div key={m.id} className="chat-system">{m.content} · {ago(m.created_at)}</div>
        ) : (
          <div key={m.id} className={'chat-bubble' + (m.author_label === me?.name || m.author_label === me?.email ? ' own' : '')}>
            <div className="chat-author row" style={{ justifyContent: 'space-between', gap: 8 }}>
              <span>{m.author_label}</span>
              {can('warroom.write') && <button type="button" disabled={pin.isPending} onClick={() => pin.mutate(m.id)} style={{ border: 0, background: 'none', cursor: 'pointer', opacity: m.pinned ? 1 : 0.4, color: 'inherit' }} aria-label={m.pinned ? 'Unpin' : 'Pin'}><Pin size={11} /></button>}
            </div>
            {m.content}
            <span className="chat-time">{ago(m.created_at)}</span>
          </div>
        ))}
        {room.messages.length === 0 && <Empty>No messages yet. Say what you're seeing.</Empty>}
      </div>
      {room.status === 'active' && can('warroom.write') && (
        <form className="chat-composer" onSubmit={submit}>
          <textarea rows={1} aria-label="Message" maxLength={10000} disabled={send.isPending} value={draft} placeholder="Share an update…" onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); if (draft.trim() && !send.isPending) send.mutate(undefined); } }} />
          <button className="btn primary" type="submit" aria-label="Send message" disabled={send.isPending || !draft.trim()}><Send size={15} /></button>
        </form>
      )}
      {(send.error || pin.error) && <ErrorBox error={send.error || pin.error} />}
      {deleting && <Modal title="Delete war room" onClose={() => { if (!remove.isPending) setDeleting(false); }}>
        <p>Permanently delete “{room.title}” and all its messages? This action cannot be undone.</p>
        {remove.error && <ErrorBox error={remove.error} />}
        <div className="row">
          <button className="btn" disabled={remove.isPending} onClick={() => setDeleting(false)}>Cancel</button>
          <button className="btn danger" disabled={remove.isPending} onClick={() => remove.mutate(undefined)}>{remove.isPending ? 'Deleting…' : 'Delete war room'}</button>
        </div>
      </Modal>}
      {standingDown && <StandDownModal id={id} onClose={() => setStandingDown(false)} onDone={() => { setStandingDown(false); void qc.invalidateQueries({ queryKey: ['warrooms'] }); }} />}
    </div>
  );
}

function can_manage(me: { capabilities: string[] } | null): boolean {
  return !!me?.capabilities.includes('warroom.manage');
}

function StandDownModal({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const [summary, setSummary] = useState('');
  const m = useAct(() => post(`/api/warrooms/${id}/stand-down`, { summary }), ['warroom', 'warrooms'], 'War room stood down', onDone);
  return (
    <Modal title="Stand down this war room" onClose={onClose}>
      <p style={{ color: 'var(--muted)' }}>The chat stays as a record. Summarize the outcome for anyone reading this back later.</p>
      <Field label="Closing summary" id="sds"><textarea id="sds" rows={4} value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending} onClick={() => m.mutate(undefined)}><Users size={14} /> Confirm stand-down</button>
    </Modal>
  );
}
