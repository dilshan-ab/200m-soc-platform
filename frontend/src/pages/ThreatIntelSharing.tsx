import { useQuery } from '@tanstack/react-query';
import { AtSign, Copy, Download, FileJson, Fingerprint, Globe2, Plug, Plus, RefreshCw, Shield, Trash2, Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { Empty, ErrorBox, Field, Loading, Modal, Pager, PageHead, SearchBox, useToast } from '../components/ui';
import { del, get, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, titleCase } from '../lib/format';
import { useAct } from '../lib/mut';

type Indicator = { id: string; type: string; value: string; pattern: string; labels: string[]; confidence: number; tlp: string; verdict: string; source: string; sightings: number; revoked: boolean; last_seen: string };
type Stats = { total: number; active: number; revoked: number; by_type: Record<string, number>; by_verdict: Record<string, number> };
type Feed = { id: string; name: string; direction: string; taxii_discovery_url: string; taxii_collection_id: string; enabled: boolean; last_sync_at: string | null; last_sync_status: string; last_sync_count: number; last_error: string };

const TYPE_ICON: Record<string, typeof Globe2> = { ip: Globe2, domain: Globe2, url: Globe2, hash: Fingerprint, email: AtSign };
const TLP_STYLE: Record<string, { background: string; color: string }> = {
  WHITE: { background: 'var(--soft)', color: 'var(--muted)' }, GREEN: { background: 'var(--ok-bg)', color: 'var(--ok)' },
  AMBER: { background: 'var(--warn-bg)', color: 'var(--warn)' }, RED: { background: 'var(--bad-bg)', color: 'var(--bad)' },
};
const VERDICT_STYLE: Record<string, { background: string; color: string }> = {
  malicious: { background: 'var(--bad-bg)', color: 'var(--bad)' }, suspicious: { background: 'var(--warn-bg)', color: 'var(--warn)' },
  benign: { background: 'var(--ok-bg)', color: 'var(--ok)' }, unknown: { background: 'var(--soft)', color: 'var(--muted)' },
};

export default function ThreatIntelSharing() {
  const { can } = useAuth();
  const [tab, setTab] = useState<'indicators' | 'share' | 'feeds'>('indicators');
  const stats = useQuery({ queryKey: ['intel-share-stats'], queryFn: () => get<Stats>('/api/threat-intel/stats'), refetchInterval: 20000 });

  return (
    <>
      <PageHead title="Threat Intel Sharing" sub="A durable indicator store you can exchange with partners as STIX 2.1 bundles, or over TAXII." eyebrow="THREAT INTELLIGENCE" />
      {stats.data && (
        <div className="kpi-row" style={{ marginBottom: 16 }}>
          <div className="kpi"><Shield size={18} /><div><strong>{stats.data.total}</strong><small>Total indicators</small></div></div>
          <div className="kpi"><Shield size={18} style={{ color: 'var(--ok)' }} /><div><strong>{stats.data.active}</strong><small>Active</small></div></div>
          <div className="kpi"><Trash2 size={18} style={{ color: 'var(--muted)' }} /><div><strong>{stats.data.revoked}</strong><small>Revoked</small></div></div>
          <div className="kpi"><Fingerprint size={18} style={{ color: 'var(--bad)' }} /><div><strong>{stats.data.by_verdict.malicious ?? 0}</strong><small>Malicious</small></div></div>
        </div>
      )}
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={tab === 'indicators' ? 'active' : ''} onClick={() => setTab('indicators')}>Indicators</button>
        <button className={tab === 'share' ? 'active' : ''} onClick={() => setTab('share')}>Share &amp; Import</button>
        {can('threat_intel.admin') && <button className={tab === 'feeds' ? 'active' : ''} onClick={() => setTab('feeds')}>TAXII Feeds</button>}
      </div>
      {tab === 'indicators' && <IndicatorsPanel />}
      {tab === 'share' && <SharePanel />}
      {tab === 'feeds' && <FeedsPanel />}
    </>
  );
}

function IndicatorsPanel() {
  const { can } = useAuth();
  const [type, setType] = useState('');
  const [verdict, setVerdict] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const [adding, setAdding] = useState(false);
  const list = useQuery({ queryKey: ['indicators', type, verdict, q, page], queryFn: () => get<Page<Indicator>>('/api/threat-intel/indicators', { type: type || undefined, verdict: verdict || undefined, q: q || undefined, page, limit: 25 }) });
  const revoke = useAct((id: string) => post(`/api/threat-intel/indicators/${id}/revoke`), ['indicators', 'intel-share-stats'], 'Indicator revoked');

  return (
    <>
      <div className="filters" style={{ marginBottom: 12 }}>
        <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search by value…" label="Search indicators" />
        <select aria-label="Indicator type" value={type} onChange={(e) => { setType(e.target.value); setPage(1); }}><option value="">All types</option>{['ip', 'domain', 'url', 'hash', 'email'].map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select>
        <select aria-label="Verdict" value={verdict} onChange={(e) => { setVerdict(e.target.value); setPage(1); }}><option value="">Any verdict</option>{['malicious', 'suspicious', 'benign', 'unknown'].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}</select>
        <span className="spacer" />
        {can('threat_intel.write') && <button className="btn small primary" onClick={() => setAdding(true)}><Plus size={14} /> Add indicator</button>}
      </div>
      {list.isLoading ? <Loading /> : list.error ? <ErrorBox error={list.error} /> : list.data!.items.length === 0 ? <Empty>No indicators match these filters.</Empty> : (
        <>
          <div className="table-wrap">
            <table>
              <thead><tr><th /><th>Value</th><th>TLP</th><th>Verdict</th><th>Confidence</th><th>Sightings</th><th>Source</th><th>Last seen</th><th /></tr></thead>
              <tbody>{list.data!.items.map((i) => {
                const Icon = TYPE_ICON[i.type] || Globe2;
                return (
                  <tr key={i.id} style={{ opacity: i.revoked ? 0.5 : 1 }}>
                    <td><span className="ioc-type-icon"><Icon size={13} /></span></td>
                    <td className="mono wrap">{i.value}{i.revoked && <small style={{ display: 'block', color: 'var(--muted)' }}>revoked</small>}</td>
                    <td><span className="badge" style={TLP_STYLE[i.tlp]}>{i.tlp}</span></td>
                    <td><span className="badge" style={VERDICT_STYLE[i.verdict]}>{i.verdict}</span></td>
                    <td><span className="confidence-bar"><span style={{ width: `${i.confidence}%` }} /></span></td>
                    <td>{i.sightings}</td>
                    <td style={{ fontSize: 12, color: 'var(--muted)' }}>{i.source}</td>
                    <td>{ago(i.last_seen)}</td>
                    <td>{!i.revoked && can('threat_intel.write') && <button className="btn small" onClick={() => revoke.mutate(i.id)}>Revoke</button>}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
          <Pager page={page} limit={list.data!.limit} total={list.data!.total} set={setPage} />
        </>
      )}
      {adding && <AddIndicatorModal onClose={() => setAdding(false)} />}
    </>
  );
}

function AddIndicatorModal({ onClose }: { onClose: () => void }) {
  const [v, setV] = useState({ type: 'ip', value: '', confidence: 70, tlp: 'AMBER' });
  const m = useAct(() => post('/api/threat-intel/indicators', v), ['indicators', 'intel-share-stats'], 'Indicator added', onClose);
  return (
    <Modal title="Add indicator" onClose={onClose}>
      <div className="grid cols-2">
        <Field label="Type" id="it"><select id="it" value={v.type} onChange={(e) => setV({ ...v, type: e.target.value })}>{['ip', 'domain', 'url', 'hash', 'email'].map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select></Field>
        <Field label="TLP" id="itlp"><select id="itlp" value={v.tlp} onChange={(e) => setV({ ...v, tlp: e.target.value })}>{['WHITE', 'GREEN', 'AMBER', 'RED'].map((t) => <option key={t}>{t}</option>)}</select></Field>
      </div>
      <Field label="Value" id="iv" hint="e.g. 203.0.113.9, evil.example.com, or a file hash"><input id="iv" value={v.value} onChange={(e) => setV({ ...v, value: e.target.value })} /></Field>
      <Field label={`Confidence (${v.confidence}%)`} id="ic"><input id="ic" type="range" min={0} max={100} value={v.confidence} onChange={(e) => setV({ ...v, confidence: Number(e.target.value) })} /></Field>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.value.trim().length < 1} onClick={() => m.mutate(undefined)}>Add</button>
    </Modal>
  );
}

function SharePanel() {
  const toast = useToast();
  const { can } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);
  const [bundleText, setBundleText] = useState('');
  const [importResult, setImportResult] = useState<{ imported: number; skipped: number } | null>(null);
  const [exportType, setExportType] = useState('');
  const [exportDays, setExportDays] = useState(90);
  const importMut = useAct(() => post<{ imported: number; skipped: number }>('/api/threat-intel/import', { bundle: bundleText }), ['indicators', 'intel-share-stats'], undefined, (r) => { setImportResult(r); setBundleText(''); });

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then(setBundleText);
  }
  async function doExport() {
    try {
      const bundle = await get<any>('/api/threat-intel/export', { type: exportType || undefined, days: exportDays });
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `threat-indicators-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast(`Exported ${bundle.objects.length} indicator(s)`);
    } catch (e: any) { toast(e.message, true); }
  }
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied');
    } catch { toast('Could not copy. Select and copy the discovery URL manually.', true); }
  }

  const taxiiBase = `${location.origin}/taxii2/`;
  return (
    <div className="intel-share-grid">
      {can('threat_intel.write') && <div className="card">
        <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}><Upload size={16} /> Import a STIX bundle</h3>
        <p style={{ color: 'var(--muted)', fontSize: 13 }}>Paste STIX 2.1 JSON, or upload a <code>.json</code> file. Indicator objects are upserted by type + value.</p>
        <input ref={fileRef} type="file" aria-label="STIX bundle file" accept="application/json,.json" onChange={onFile} style={{ marginBottom: 10 }} />
        <textarea aria-label="STIX bundle JSON" rows={8} className="mono" placeholder='{"type":"bundle","objects":[...]}' value={bundleText} onChange={(e) => setBundleText(e.target.value)} style={{ marginBottom: 10 }} />
        {importMut.error && <ErrorBox error={importMut.error} />}
        {importResult && <div className="notice" style={{ marginBottom: 10 }}>Imported {importResult.imported}, skipped {importResult.skipped} non-indicator object(s).</div>}
        <button className="btn primary" disabled={importMut.isPending || !bundleText.trim()} onClick={() => importMut.mutate(undefined)}><FileJson size={15} /> Import bundle</button>
      </div>}

      <div className="card">
        <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}><Download size={16} /> Export for a partner</h3>
        <p style={{ color: 'var(--muted)', fontSize: 13 }}>Download your active indicators as a STIX 2.1 bundle to send to a partner or another platform.</p>
        <div className="grid cols-2">
          <Field label="Type" id="et"><select id="et" value={exportType} onChange={(e) => setExportType(e.target.value)}><option value="">All types</option>{['ip', 'domain', 'url', 'hash', 'email'].map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select></Field>
          <Field label="Seen in last (days)" id="ed"><input id="ed" type="number" min={1} max={365} value={exportDays} onChange={(e) => setExportDays(Number(e.target.value))} /></Field>
        </div>
        <button className="btn primary" disabled={!Number.isInteger(exportDays) || exportDays < 1 || exportDays > 365} onClick={() => void doExport()}><Download size={15} /> Download bundle</button>

        <h3 style={{ marginTop: 24, display: 'flex', alignItems: 'center', gap: 8 }}><Plug size={16} /> Our TAXII 2.1 feed</h3>
        <p style={{ color: 'var(--muted)', fontSize: 13 }}>Give a partner this discovery URL so their TAXII client can pull our indicators directly, continuously.</p>
        <div className="taxii-info">
          <div className="taxii-info-row"><label>Discovery</label><code>{taxiiBase}</code><button className="btn small" aria-label="Copy TAXII discovery URL" onClick={() => void copy(taxiiBase)}><Copy size={12} /></button></div>
          <div className="taxii-info-row"><label>Collection</label><code>200M SOC shared indicators</code></div>
          <div className="taxii-info-row"><label>Auth</label><code>Bearer API token (see Admin → API tokens)</code></div>
        </div>
      </div>
    </div>
  );
}

function FeedsPanel() {
  const { can } = useAuth();
  const [adding, setAdding] = useState(false);
  const feeds = useQuery({ queryKey: ['threat-feeds'], queryFn: () => get<Feed[]>('/api/threat-intel/feeds') });
  const sync = useAct((id: string) => post(`/api/threat-intel/feeds/${id}/sync`), ['threat-feeds', 'indicators', 'intel-share-stats']);
  const remove = useAct((id: string) => del(`/api/threat-intel/feeds/${id}`), ['threat-feeds'], 'Feed removed');

  if (feeds.isLoading) return <Loading />;
  if (feeds.error) return <ErrorBox error={feeds.error} />;

  return (
    <>
      <div className="row" style={{ marginBottom: 14 }}><span className="spacer" />{can('threat_intel.admin') && <button className="btn small primary" onClick={() => setAdding(true)}><Plus size={14} /> Add TAXII feed</button>}</div>
      {feeds.data!.length === 0 ? <Empty>No inbound feeds configured. Add a TAXII feed to pull indicators from a partner.</Empty> : (
        <div className="feed-grid">{feeds.data!.map((f) => (
          <div key={f.id} className="card feed-card">
            <span className={`feed-status-dot ${!f.last_sync_at ? 'unsynced' : f.last_sync_status === 'ok' ? 'ok' : 'error'}`} />
            <strong>{f.name}</strong>
            <div className="mono wrap" style={{ fontSize: 11, color: 'var(--muted)' }}>{f.taxii_discovery_url}</div>
            {f.last_sync_at ? (
              <div style={{ fontSize: 12 }}>{f.last_sync_status === 'ok' ? `${f.last_sync_count} indicator(s)` : <span style={{ color: 'var(--bad)' }}>{f.last_error || 'sync failed'}</span>} · {ago(f.last_sync_at)}</div>
            ) : <div style={{ fontSize: 12, color: 'var(--muted)' }}>Never synced</div>}
            {can('threat_intel.admin') && (
              <div className="row" style={{ gap: 6, marginTop: 4 }}>
                <button className="btn small" disabled={sync.isPending} onClick={() => sync.mutate(f.id)}><RefreshCw size={12} /> Sync now</button>
                <button className="btn small danger" aria-label={`Remove feed ${f.name}`} onClick={() => { if (confirm(`Remove feed "${f.name}"?`)) remove.mutate(f.id); }}><Trash2 size={12} /></button>
              </div>
            )}
          </div>
        ))}</div>
      )}
      {adding && <AddFeedModal onClose={() => setAdding(false)} />}
    </>
  );
}

function AddFeedModal({ onClose }: { onClose: () => void }) {
  const [v, setV] = useState({ name: '', taxii_discovery_url: '', taxii_collection_id: '', taxii_username: '', taxii_password: '' });
  const m = useAct(() => post('/api/threat-intel/feeds', v), ['threat-feeds'], 'Feed added', onClose);
  return (
    <Modal title="Add a TAXII feed" onClose={onClose}>
      <Field label="Name" id="fn"><input id="fn" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
      <Field label="Discovery URL" id="fu" hint="The partner's TAXII 2.1 discovery endpoint (must be a public host)."><input id="fu" value={v.taxii_discovery_url} onChange={(e) => setV({ ...v, taxii_discovery_url: e.target.value })} placeholder="https://partner.example.com/taxii2/" /></Field>
      <Field label="Collection ID" id="fc"><input id="fc" value={v.taxii_collection_id} onChange={(e) => setV({ ...v, taxii_collection_id: e.target.value })} /></Field>
      <div className="grid cols-2">
        <Field label="Username (optional)" id="fun"><input id="fun" value={v.taxii_username} onChange={(e) => setV({ ...v, taxii_username: e.target.value })} /></Field>
        <Field label="Password (optional)" id="fpw"><input id="fpw" type="password" value={v.taxii_password} onChange={(e) => setV({ ...v, taxii_password: e.target.value })} /></Field>
      </div>
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn primary" disabled={m.isPending || v.name.trim().length < 2 || !v.taxii_discovery_url} onClick={() => m.mutate(undefined)}>Add feed</button>
    </Modal>
  );
}
