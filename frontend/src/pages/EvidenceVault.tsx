import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Download, File, FileCode, FileImage, FileText, HardDrive, Package, Search, Shield, Trash2, Upload } from 'lucide-react';
import { Fragment, useRef, useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';
import { del, get } from '../lib/api';
import { useAuth } from '../lib/auth';

type EvidenceItem = {
  id: string; case_id: string; name: string; type: string; description: string;
  hash_sha256: string; file_size: number; storage_ref: string; has_file: boolean;
  tags: string[]; collected_by: string; collected_at: string;
  chain_of_custody: { actor: string; action: string; at: string; note: string }[];
  observable_id: string | null; alert_id: string | null; client_id: string | null; created_at: string;
};
type Stats = { total_items: number; total_size_bytes: number; items_with_files: number; items_metadata_only: number; by_type: Record<string, number> };

const TYPE_ICONS: Record<string, typeof File> = { file: File, screenshot: FileImage, pcap: FileCode, log: FileText, artifact: Package, note: FileText };

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

export default function EvidenceVault() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [q, setQ] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [page, setPage] = useState(1);
  const [size] = useState(50);
  const [showUpload, setShowUpload] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const params = new URLSearchParams();
  if (submitted) params.set('q', submitted);
  if (typeFilter) params.set('type', typeFilter);
  params.set('page', String(page));
  params.set('size', String(size));

  const items = useQuery({
    queryKey: ['evidence', submitted, typeFilter, page],
    queryFn: () => get<{ total: number; items: EvidenceItem[] }>(`/api/evidence/?${params.toString()}`),
  });
  const stats = useQuery({ queryKey: ['evidence-stats'], queryFn: () => get<Stats>('/api/evidence/stats') });

  const deleteMut = useMutation({
    mutationFn: (id: string) => del(`/api/evidence/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['evidence'] }); qc.invalidateQueries({ queryKey: ['evidence-stats'] }); },
  });

  const totalPages = items.data ? Math.ceil(items.data.total / size) : 0;

  return (
    <>
      <PageHead title="Evidence Vault" sub="Upload, browse, and download forensic evidence files attached to cases. Full chain-of-custody tracking." />

      {stats.data && (
        <div className="kpi-strip" style={{ marginBottom: 16 }}>
          <div className="kpi"><HardDrive size={18} /><div><strong>{stats.data.total_items}</strong><small>Total items</small></div></div>
          <div className="kpi"><Upload size={18} /><div><strong>{stats.data.items_with_files}</strong><small>With files</small></div></div>
          <div className="kpi"><Shield size={18} /><div><strong>{formatSize(stats.data.total_size_bytes)}</strong><small>Total size</small></div></div>
          {Object.entries(stats.data.by_type).map(([t, c]) => {
            const Icon = TYPE_ICONS[t] || File;
            return <div className="kpi" key={t}><Icon size={18} /><div><strong>{c}</strong><small>{t}</small></div></div>;
          })}
        </div>
      )}

      <form className="row" onSubmit={e => { e.preventDefault(); setSubmitted(q); setPage(1); }} style={{ gap: 8, marginBottom: 12 }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)' }} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search evidence by name, description, or tags..." style={{ paddingLeft: 32, width: '100%' }} />
        </div>
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }} style={{ width: 140 }}>
          <option value="">All types</option>
          <option value="file">File</option><option value="screenshot">Screenshot</option>
          <option value="pcap">PCAP</option><option value="log">Log</option>
          <option value="artifact">Artifact</option><option value="note">Note</option>
        </select>
        <button className="btn primary" type="submit"><Search size={14} /> Search</button>
        {can('evidence.write') && <button className="btn" type="button" onClick={() => setShowUpload(!showUpload)}><Upload size={14} /> Upload</button>}
      </form>

      {showUpload && <UploadPanel onDone={() => { setShowUpload(false); qc.invalidateQueries({ queryKey: ['evidence'] }); qc.invalidateQueries({ queryKey: ['evidence-stats'] }); }} />}

      {items.isLoading ? <Loading /> : items.error ? <ErrorBox error={items.error} /> : items.data!.items.length === 0 ? (
        <Empty>{submitted ? `No evidence matching "${submitted}"` : 'No evidence items found. Upload evidence files to get started.'}</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Size</th>
                <th>Hash (SHA-256)</th>
                <th>Collected by</th>
                <th>Collected at</th>
                <th>Tags</th>
                <th style={{ width: 90 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.data!.items.map(e => {
                const Icon = TYPE_ICONS[e.type] || File;
                return (
                  <Fragment key={e.id}>
                    <tr onClick={() => setExpanded(expanded === e.id ? null : e.id)} style={{ cursor: 'pointer' }} className={expanded === e.id ? 'selected' : ''}>
                      <td style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Icon size={15} /> {e.name}</td>
                      <td><span className="badge">{e.type}</span></td>
                      <td style={{ fontSize: 12 }}>{e.file_size ? formatSize(e.file_size) : '—'}</td>
                      <td><span className="mono" style={{ fontSize: 11 }}>{e.hash_sha256 ? e.hash_sha256.slice(0, 16) + '...' : '—'}</span></td>
                      <td style={{ fontSize: 12 }}>{e.collected_by}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{e.collected_at ? new Date(e.collected_at).toLocaleString() : '—'}</td>
                      <td>{e.tags?.map(t => <span key={t} className="badge" style={{ marginRight: 3 }}>{t}</span>)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 4 }}>
                          {e.has_file && (
                            <a href={`/api/evidence/download/${e.id}`} className="btn small" title="Download" onClick={ev => ev.stopPropagation()}>
                              <Download size={13} />
                            </a>
                          )}
                          {can('evidence.write') && (
                            <button className="btn small danger" title="Delete" onClick={ev => { ev.stopPropagation(); if (confirm(`Delete "${e.name}"?`)) deleteMut.mutate(e.id); }}>
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expanded === e.id && (
                      <tr>
                        <td colSpan={8} style={{ padding: 0 }}>
                          <EvidenceDetail item={e} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="row" style={{ justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button className="btn small" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
          <span style={{ fontSize: 13, color: 'var(--muted)', padding: '6px 12px' }}>Page {page} of {totalPages}</span>
          <button className="btn small" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </>
  );
}

function EvidenceDetail({ item }: { item: EvidenceItem }) {
  return (
    <div style={{ padding: '12px 16px', background: 'var(--soft)', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8, marginBottom: 12 }}>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Case ID</span><div className="mono" style={{ fontSize: 12 }}>{item.case_id}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Full SHA-256</span><div className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{item.hash_sha256 || '—'}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Storage Reference</span><div className="mono" style={{ fontSize: 11 }}>{item.storage_ref || 'metadata only'}</div></div>
        {item.description && <div style={{ gridColumn: '1 / -1' }}><span style={{ fontSize: 11, color: 'var(--muted)' }}>Description</span><div style={{ fontSize: 13 }}>{item.description}</div></div>}
      </div>

      {item.chain_of_custody?.length > 0 && (
        <div>
          <span style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Chain of custody</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {item.chain_of_custody.map((c, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12 }}>
                <span style={{ color: 'var(--muted)', whiteSpace: 'nowrap' }}>{c.at ? new Date(c.at).toLocaleString() : '—'}</span>
                <span className="badge">{c.action}</span>
                <span>{c.actor}</span>
                {c.note && <span style={{ color: 'var(--muted)' }}>— {c.note}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function UploadPanel({ onDone }: { onDone: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [caseId, setCaseId] = useState('');
  const [evidenceType, setEvidenceType] = useState('file');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const handleUpload = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file || !caseId.trim()) { setError('Select a file and enter a case ID'); return; }
    setUploading(true); setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      const params = new URLSearchParams({ evidence_type: evidenceType });
      if (description) params.set('description', description);
      if (tags) params.set('tags', tags);
      const resp = await fetch(`/api/evidence/upload/${caseId.trim()}?${params.toString()}`, {
        method: 'POST', body: form, credentials: 'include',
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(data.detail || resp.statusText);
      }
      onDone();
    } catch (e: any) {
      setError(e.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="card" style={{ padding: 16, marginBottom: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 8 }}>Upload evidence file</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8 }}>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>Case ID *</label>
          <input value={caseId} onChange={e => setCaseId(e.target.value)} placeholder="Paste case UUID" />
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>Type</label>
          <select value={evidenceType} onChange={e => setEvidenceType(e.target.value)}>
            <option value="file">File</option><option value="screenshot">Screenshot</option>
            <option value="pcap">PCAP</option><option value="log">Log</option><option value="artifact">Artifact</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>Tags (comma-separated)</label>
          <input value={tags} onChange={e => setTags(e.target.value)} placeholder="malware, forensics" />
        </div>
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>Description</label>
          <input value={description} onChange={e => setDescription(e.target.value)} placeholder="What is this evidence?" />
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>File *</label>
          <input ref={fileRef} type="file" />
        </div>
      </div>
      {error && <div className="error" style={{ marginTop: 8, fontSize: 13 }}>{error}</div>}
      <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
        <button className="btn primary" onClick={handleUpload} disabled={uploading}>{uploading ? 'Uploading...' : 'Upload'}</button>
        <button className="btn" onClick={onDone}>Cancel</button>
      </div>
    </div>
  );
}
