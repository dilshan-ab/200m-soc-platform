import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead } from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useAct } from '../lib/mut';

export default function Runbooks() {
  const q = useQuery({ queryKey: ['runbooks'], queryFn: () => get<any[]>('/api/runbooks') });
  const { can } = useAuth();
  const [slug, setSlug] = useState<string | null>(null);
  const [editing, setEditing] = useState<any>(null);
  return (
    <>
      <PageHead title="Runbooks" sub="Operator guides and procedures. Edits create a new version; a second person publishes it.">
        {can('runbooks.write') && <button className="btn primary" onClick={() => setEditing({ slug: '', title: '', kind: 'guide', body: '' })}>New runbook</button>}
      </PageHead>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data!.length === 0 ? <Empty>No runbooks yet.</Empty> : (
        <div className="grid cols-4">{q.data!.map((r) => (
          <button key={r.id} className="card" style={{ textAlign: 'left', cursor: 'pointer' }} onClick={() => setSlug(r.slug)}>
            <h3>{r.title}</h3><span style={{ color: 'var(--muted)' }}>{r.kind} · v{r.version} · {r.status}</span></button>))}</div>
      )}
      {slug && <View slug={slug} onClose={() => setSlug(null)} onEdit={(r) => { setSlug(null); setEditing(r); }} />}
      {editing && <Edit r={editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function View({ slug, onClose, onEdit }: { slug: string; onClose: () => void; onEdit: (r: any) => void }) {
  const q = useQuery({ queryKey: ['runbook', slug], queryFn: () => get<any>(`/api/runbooks/${slug}`) });
  const { can } = useAuth();
  const pub = useAct(() => post(`/api/runbooks/${q.data.id}/publish`), ['runbooks', 'runbook'], 'Published', onClose);
  if (q.isLoading) return <Drawer title="Runbook" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Runbook" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const r = q.data;
  return (
    <Drawer title={r.title} onClose={onClose}>
      <div className="row" style={{ marginBottom: 10 }}><span>v{r.version} · {r.status}</span><span className="spacer" />
        {can('runbooks.write') && <button className="btn small" onClick={() => onEdit(r)}>Edit</button>}
        {can('runbooks.write') && r.status === 'draft' && <button className="btn small primary" onClick={() => pub.mutate(undefined)}>Publish</button>}</div>
      {pub.error && <ErrorBox error={pub.error} />}
      {/* Rendered as plain text on purpose: never inject runbook content as HTML. */}
      <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>{r.body}</div>
    </Drawer>
  );
}

function Edit({ r, onClose }: { r: any; onClose: () => void }) {
  const [v, setV] = useState({ slug: r.slug, title: r.title, kind: r.kind, body: r.body });
  const m = useAct(() => post('/api/runbooks', v), ['runbooks', 'runbook'], 'Saved as a new draft version', onClose);
  return (
    <Modal title={r.slug ? `Edit ${r.title}` : 'New runbook'} onClose={onClose} wide>
      <div className="grid cols-2">
        <Field label="Slug (lowercase, dashes)" id="rs"><input id="rs" disabled={!!r.slug} value={v.slug} onChange={(e) => setV({ ...v, slug: e.target.value })} /></Field>
        <Field label="Title" id="rt"><input id="rt" value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} /></Field>
      </div>
      <Field label="Content" id="rb"><textarea id="rb" style={{ minHeight: 280 }} value={v.body} onChange={(e) => setV({ ...v, body: e.target.value })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || !/^[a-z0-9-]{2,}$/.test(v.slug) || v.title.trim().length < 2} onClick={() => m.mutate(undefined)}>Save draft</button>
    </Modal>
  );
}
