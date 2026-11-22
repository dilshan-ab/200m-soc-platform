import { useQuery } from '@tanstack/react-query';
import { Download, File, FileCode, FileImage, FileText, Package, Trash2, Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { Skeleton } from '../components/Interactive';
import { Chips, Summary } from '../components/manage';
import { Drawer, Empty, ErrorBox, Field, Modal, PageHead, Pager, SearchBox } from '../components/ui';
import { del, get, upload, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useAct } from '../lib/mut';

type Custody = { actor: string; action: string; at: string; note: string };
type EvidenceItem = {
  id: string; case_id: string; name: string; type: string; description: string;
  hash_sha256: string; file_size: number; storage_ref: string; has_file: boolean;
  tags: string[]; collected_by: string; collected_at: string; chain_of_custody: Custody[];
};
type Stats = { total_items: number; total_size_bytes: number; items_with_files: number; items_metadata_only: number; by_type: Record<string, number> };

const TYPE_ICONS: Record<string, typeof File> = { file: File, screenshot: FileImage, pcap: FileCode, log: FileText, artifact: Package, note: FileText };
const UPLOAD_TYPES = ['file', 'screenshot', 'pcap', 'log', 'artifact'];
const KEYS = ['evidence', 'evidence-stats'];

function formatSize(bytes: number): string {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

export default function EvidenceVault() {
  const { can } = useAuth();
  const [q, setQ] = useState('');
  const [type, setType] = useState('');
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<EvidenceItem | null>(null);
  const [uploading, setUploading] = useState(false);
  const limit = 50;

  const list = useQuery({ queryKey: ['evidence', q, type, page], queryFn: () => get<Page<EvidenceItem>>('/api/evidence/', { q, type, page, size: limit }) });
  const stats = useQuery({ queryKey: ['evidence-stats'], queryFn: () => get<Stats>('/api/evidence/stats') });
  const remove = useAct((e: EvidenceItem) => del(`/api/evidence/${e.id}`), KEYS, 'Evidence deleted', () => setOpen(null));
  const confirmDelete = (e: EvidenceItem) => { if (confirm(`Delete "${e.name}"? This also removes its stored file.`)) remove.mutate(e); };
  const filter = (v: string) => { setType(v); setPage(1); };
  const st = stats.data;

  return (
    <>
      <PageHead title="Evidence Vault" sub="Forensic files attached to cases, with hashes and a full chain of custody.">
        {can('evidence.write') && <button className="btn primary" onClick={() => setUploading(true)}><Upload size={14} /> Upload evidence</button>}
      </PageHead>
      {st && <Summary items={[
        { label: 'Total items', value: st.total_items },
        { label: 'With files', value: st.items_with_files, tone: 'ok' },
        { label: 'Metadata only', value: st.items_metadata_only },
        { label: 'Stored size', value: formatSize(st.total_size_bytes) },
      ]} />}
      <Chips items={[
        { label: 'All', active: !type, onClick: () => filter(''), count: st?.total_items },
        ...Object.entries(st?.by_type ?? {}).map(([t, c]) => ({ label: t, active: type === t, onClick: () => filter(t), count: c })),
      ]} />
      <div className="filters">
        <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search name, description or tags…" label="Search evidence" />
        {(q || type) && <button className="btn" onClick={() => { setQ(''); filter(''); }}>Clear filters</button>}
      </div>
      {list.isLoading ? <Skeleton lines={6} /> : list.error ? <ErrorBox error={list.error} onRetry={() => void list.refetch()} retrying={list.isFetching} /> : list.data!.items.length === 0 ? (
        <Empty action={q || type ? 'Clear filters' : undefined} onAction={q || type ? () => { setQ(''); filter(''); } : undefined}>{q || type ? 'No evidence matches these filters.' : 'No evidence yet. Upload a file to a case to start the chain of custody.'}</Empty>
      ) : (
        <>
          <div className="table-wrap"><table>
            <thead><tr><th>Name</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Collected by</th><th>Collected</th><th /></tr></thead>
            <tbody>{list.data!.items.map((e) => {
              const Icon = TYPE_ICONS[e.type] ?? File;
              return (
                <tr key={e.id} tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setOpen(e)} onKeyDown={(ev) => { if (ev.target === ev.currentTarget && ev.key === 'Enter') { ev.preventDefault(); setOpen(e); } }}>
                  <td className="wrap"><span className="row" style={{ gap: 8 }}><Icon size={15} style={{ color: 'var(--muted)', flexShrink: 0 }} />{e.name}</span></td>
                  <td><span className="badge">{e.type}</span></td>
                  <td>{e.file_size ? formatSize(e.file_size) : '—'}</td>
                  <td className="mono">{e.hash_sha256 ? `${e.hash_sha256.slice(0, 12)}…` : '—'}</td>
                  <td>{e.collected_by}</td>
                  <td title={when(e.collected_at)}>{ago(e.collected_at)}</td>
                  <td>
                    <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                      {e.has_file && <a className="btn small" href={`/api/evidence/download/${e.id}`} aria-label={`Download ${e.name}`} onClick={(ev) => ev.stopPropagation()}><Download size={13} /></a>}
                      {can('evidence.write') && <button className="btn small danger" aria-label={`Delete ${e.name}`} onClick={(ev) => { ev.stopPropagation(); confirmDelete(e); }}><Trash2 size={13} /></button>}
                    </span>
                  </td>
                </tr>
              );
            })}</tbody>
          </table></div>
          <Pager page={page} limit={limit} total={list.data!.total} set={setPage} />
        </>
      )}
      {open && <EvidenceDrawer item={open} onClose={() => setOpen(null)} onDelete={can('evidence.write') ? () => confirmDelete(open) : undefined} />}
      {uploading && <UploadModal onClose={() => setUploading(false)} />}
    </>
  );
}

function Meta({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return <div style={{ marginBottom: 12 }}><div className="hint" style={{ marginBottom: 2 }}>{label}</div><div className={mono ? 'mono' : undefined} style={{ wordBreak: 'break-all' }}>{children}</div></div>;
}

function EvidenceDrawer({ item: e, onClose, onDelete }: { item: EvidenceItem; onClose: () => void; onDelete?: () => void }) {
  const Icon = TYPE_ICONS[e.type] ?? File;
  return (
    <Drawer title={e.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 12, flexWrap: 'wrap', gap: 6 }}>
        <Icon size={16} style={{ color: 'var(--muted)' }} /><span className="badge">{e.type}</span>
        {e.tags?.map((t) => <span key={t} className="badge">{t}</span>)}
        <span className="spacer" />
        {e.has_file && <a className="btn small" href={`/api/evidence/download/${e.id}`}><Download size={13} /> Download</a>}
        {onDelete && <button className="btn small danger" onClick={onDelete}>Delete</button>}
      </div>
      {e.description && <p style={{ whiteSpace: 'pre-wrap' }}>{e.description}</p>}
      <Meta label="Collected">{e.collected_by} · {when(e.collected_at)}</Meta>
      <Meta label="Size">{e.file_size ? formatSize(e.file_size) : 'Metadata only'}</Meta>
      <Meta label="SHA-256" mono>{e.hash_sha256 || '—'}</Meta>
      <Meta label="Case" mono>{e.case_id}</Meta>
      <h4 style={{ margin: '16px 0 8px' }}>Chain of custody ({e.chain_of_custody?.length ?? 0})</h4>
      {!e.chain_of_custody?.length ? <Empty>No custody events recorded.</Empty> : (
        <div style={{ position: 'relative', paddingLeft: 24 }}>
          <div style={{ position: 'absolute', left: 8, top: 0, bottom: 0, width: 2, background: 'var(--border)' }} />
          {e.chain_of_custody.map((c, i) => (
            <div key={i} style={{ position: 'relative', marginBottom: 12 }}>
              <div style={{ position: 'absolute', left: -20, top: 4, width: 12, height: 12, borderRadius: '50%', background: 'var(--surface)', border: '2px solid var(--accent)' }} />
              <div className="row" style={{ gap: 6, fontSize: 13 }}><strong>{c.actor}</strong><span className="badge">{c.action}</span><span className="spacer" /><span style={{ color: 'var(--muted)', fontSize: 12 }}>{when(c.at)}</span></div>
              {c.note && <div style={{ fontSize: 13, marginTop: 2 }}>{c.note}</div>}
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}

function UploadModal({ onClose }: { onClose: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [v, setV] = useState({ case_id: '', evidence_type: 'file', tags: '', description: '' });
  const [file, setFile] = useState<File | null>(null);
  const cases = useQuery({ queryKey: ['cases-for-evidence'], queryFn: () => get<Page<any>>('/api/cases', { limit: 50 }) });
  const send = useAct(
    () => { const f = new FormData(); f.append('file', file!); return upload(`/api/evidence/upload/${v.case_id}`, f, { evidence_type: v.evidence_type, description: v.description, tags: v.tags }); },
    KEYS, 'Evidence uploaded', onClose,
  );
  return (
    <Modal title="Upload evidence" onClose={onClose}>
      <Field label="Case" id="ev-case" hint="Evidence is stored against a case and recorded in its timeline.">
        <select id="ev-case" value={v.case_id} onChange={(e) => setV({ ...v, case_id: e.target.value })}>
          <option value="">{cases.isLoading ? 'Loading cases…' : 'Select a case…'}</option>
          {cases.data?.items.map((c) => <option key={c.id} value={c.id}>#{c.number} {c.title}</option>)}
        </select>
      </Field>
      <Field label="Type" id="ev-type"><select id="ev-type" value={v.evidence_type} onChange={(e) => setV({ ...v, evidence_type: e.target.value })}>{UPLOAD_TYPES.map((t) => <option key={t}>{t}</option>)}</select></Field>
      <Field label="File" id="ev-file" hint={file ? `${file.name} · ${formatSize(file.size)}` : undefined}><input id="ev-file" ref={fileRef} type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></Field>
      <Field label="Description" id="ev-desc" hint="optional"><textarea id="ev-desc" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} placeholder="What is this evidence and where did it come from?" /></Field>
      <Field label="Tags" id="ev-tags" hint="comma-separated, optional"><input id="ev-tags" value={v.tags} onChange={(e) => setV({ ...v, tags: e.target.value })} placeholder="malware, memory-dump" /></Field>
      {send.error && <div className="error" role="alert">{send.error.message}</div>}
      <button className="btn primary" disabled={send.isPending || !file || !v.case_id} onClick={() => send.mutate(undefined)}>{send.isPending ? 'Uploading…' : 'Upload'}</button>
    </Modal>
  );
}
