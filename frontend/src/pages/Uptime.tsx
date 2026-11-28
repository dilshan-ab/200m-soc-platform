import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Drawer, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pager, SearchBox, Status } from '../components/ui';
import { del, get, patch, post, type Page } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ago, when } from '../lib/format';
import { useAct } from '../lib/mut';

type Monitor = {
  id: string; name: string; url: string; method: string;
  interval_seconds: number; timeout_seconds: number; expected_status: number;
  headers: Record<string, string>; tags: string[]; notify_channels: string[];
  enabled: boolean; status: string; last_checked_at: string | null;
  last_status_change: string | null; consecutive_failures: number;
  fail_threshold: number; client_id: string | null; created_by: string;
  created_at: string; updated_at: string;
};
type Check = {
  id: string; monitor_id: string; status: string; status_code: number | null;
  response_time_ms: number | null; error: string | null; checked_at: string;
};
type UptimeSummary = { total: number; up: number; down: number; degraded: number; unknown: number; avg_response_time_ms: number | null };

const STATUS_COLORS: Record<string, string> = { up: 'var(--ok)', down: 'var(--danger)', degraded: 'var(--warning)', unknown: 'var(--muted)' };

function StatusDot({ status }: { status: string }) {
  return <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: STATUS_COLORS[status] || 'var(--muted)', marginRight: 6, flexShrink: 0 }} />;
}

export default function Uptime() {
  const { can } = useAuth();
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);

  const summary = useQuery({ queryKey: ['uptime-summary'], queryFn: () => get<UptimeSummary>('/api/uptime/summary'), refetchInterval: 30000 });
  const monitors = useQuery({
    queryKey: ['uptime-monitors', statusFilter, q, page],
    queryFn: () => get<Page<Monitor>>('/api/uptime/monitors', { status: statusFilter || undefined, q: q || undefined, page, limit: 50 }),
    refetchInterval: 30000,
  });

  const s = summary.data;

  return (
    <>
      <PageHead title="Uptime Monitoring" sub="Monitor website availability and get instant alerts when sites go down.">
        {can('uptime.write') && <button className="btn primary" onClick={() => setCreating(true)}>Add monitor</button>}
      </PageHead>

      {s && (
        <div className="grid cols-4" style={{ marginBottom: 20 }}>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700 }}>{s.total}</div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Total monitors</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--ok)' }}>{s.up}</div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Up</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--danger)' }}>{s.down}</div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Down</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--warning)' }}>{s.degraded}</div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Degraded</div>
          </div>
        </div>
      )}

      <div className="filters" style={{ marginBottom: 12 }}>
        <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search monitors…" label="Search" />
        <select aria-label="Status filter" value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          <option value="up">Up</option>
          <option value="down">Down</option>
          <option value="degraded">Degraded</option>
          <option value="unknown">Unknown</option>
        </select>
        {s && s.avg_response_time_ms != null && <span style={{ color: 'var(--muted)', fontSize: 13, marginLeft: 'auto' }}>Avg response: {s.avg_response_time_ms}ms</span>}
      </div>

      {monitors.isLoading ? <Loading /> : monitors.error ? <ErrorBox error={monitors.error} /> : !monitors.data?.items.length ? (
        <Empty>{q || statusFilter ? 'No monitors match your filters.' : 'No monitors yet. Add one to start tracking uptime.'}</Empty>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 40 }} />
                  <th>Name</th>
                  <th>URL</th>
                  <th>Status</th>
                  <th>Response</th>
                  <th>Last checked</th>
                  <th>Failures</th>
                </tr>
              </thead>
              <tbody>
                {monitors.data.items.map((m) => (
                  <tr key={m.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(m.id)}>
                    <td><StatusDot status={m.status} /></td>
                    <td style={{ fontWeight: 500 }}>{m.name}</td>
                    <td style={{ color: 'var(--muted)', fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.url}</td>
                    <td><Status v={m.status} /></td>
                    <td style={{ fontSize: 13 }}>{m.last_checked_at ? '—' : '—'}</td>
                    <td style={{ fontSize: 13 }}>{m.last_checked_at ? ago(m.last_checked_at) : 'Never'}</td>
                    <td>{m.consecutive_failures > 0 ? <span style={{ color: 'var(--danger)', fontWeight: 600 }}>{m.consecutive_failures}</span> : '0'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} limit={50} total={monitors.data.total} set={setPage} />
        </>
      )}

      {selected && <MonitorDetail id={selected} onClose={() => setSelected(null)} />}
      {creating && <MonitorForm onClose={() => setCreating(false)} />}
    </>
  );
}

function MonitorDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useAuth();
  const [editing, setEditing] = useState(false);
  const [checkPage, setCheckPage] = useState(1);

  const q = useQuery({ queryKey: ['uptime-monitor', id], queryFn: () => get<Monitor & { checks: Check[] }>(`/api/uptime/monitors/${id}`), refetchInterval: 30000 });
  const checks = useQuery({ queryKey: ['uptime-checks', id, checkPage], queryFn: () => get<Page<Check>>(`/api/uptime/monitors/${id}/checks`, { page: checkPage, limit: 50 }) });
  const remove = useAct(() => del(`/api/uptime/monitors/${id}`), ['uptime-monitors', 'uptime-summary'], 'Monitor deleted', onClose);

  if (q.isLoading) return <Drawer title="Monitor" onClose={onClose}><Loading /></Drawer>;
  if (q.error) return <Drawer title="Monitor" onClose={onClose}><ErrorBox error={q.error} /></Drawer>;
  const m = q.data!;

  const sparkData = (m.checks || []).slice(0, 50).reverse();
  const maxMs = Math.max(1, ...sparkData.map((c) => c.response_time_ms || 0));

  return (
    <Drawer title={m.name} onClose={onClose}>
      <div className="row" style={{ marginBottom: 12, flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
        <StatusDot status={m.status} />
        <Status v={m.status} />
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>{m.method} · timeout {m.timeout_seconds}s · expect {m.expected_status}</span>
        <span className="spacer" />
        {can('uptime.write') && <button className="btn small" onClick={() => setEditing(true)}>Edit</button>}
        {can('uptime.write') && <button className="btn small danger" onClick={() => { if (confirm('Delete this monitor?')) remove.mutate(undefined); }}>Delete</button>}
      </div>

      <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 16 }}>
        <a href={m.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>{m.url}</a>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>Last checked</div>
          <div style={{ fontSize: 13 }}>{m.last_checked_at ? ago(m.last_checked_at) : 'Never'}</div>
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>Status changed</div>
          <div style={{ fontSize: 13 }}>{m.last_status_change ? ago(m.last_status_change) : '—'}</div>
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>Consecutive failures</div>
          <div style={{ fontSize: 13, color: m.consecutive_failures > 0 ? 'var(--danger)' : undefined }}>{m.consecutive_failures}</div>
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>Fail threshold</div>
          <div style={{ fontSize: 13 }}>{m.fail_threshold}</div>
        </div>
      </div>

      {m.tags.length > 0 && (
        <div style={{ marginBottom: 16, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {m.tags.map((t) => <span key={t} className="badge">{t}</span>)}
        </div>
      )}

      {sparkData.length > 1 && (
        <>
          <h4 style={{ marginTop: 0 }}>Response time</h4>
          <svg viewBox={`0 0 ${sparkData.length * 10} 60`} style={{ width: '100%', height: 60, marginBottom: 16 }}>
            <polyline
              fill="none"
              stroke="var(--accent)"
              strokeWidth="1.5"
              points={sparkData.map((c, i) => `${i * 10},${60 - ((c.response_time_ms || 0) / maxMs) * 55}`).join(' ')}
            />
            {sparkData.map((c, i) => (
              <circle
                key={i}
                cx={i * 10}
                cy={60 - ((c.response_time_ms || 0) / maxMs) * 55}
                r="2"
                fill={c.status === 'up' ? 'var(--ok)' : c.status === 'down' ? 'var(--danger)' : 'var(--warning)'}
              />
            ))}
          </svg>
        </>
      )}

      <h4>Recent checks</h4>
      {checks.isLoading ? <Loading /> : checks.error ? <ErrorBox error={checks.error} /> : !checks.data?.items.length ? (
        <Empty>No checks recorded yet.</Empty>
      ) : (
        <>
          <table className="table">
            <thead><tr><th>Time</th><th>Status</th><th>Code</th><th>Response</th><th>Error</th></tr></thead>
            <tbody>
              {checks.data.items.map((c) => (
                <tr key={c.id}>
                  <td style={{ fontSize: 12 }}>{when(c.checked_at)}</td>
                  <td><Status v={c.status} /></td>
                  <td>{c.status_code ?? '—'}</td>
                  <td>{c.response_time_ms != null ? `${c.response_time_ms}ms` : '—'}</td>
                  <td style={{ color: 'var(--danger)', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.error || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={checkPage} limit={50} total={checks.data.total} set={setCheckPage} />
        </>
      )}

      {editing && <MonitorForm monitor={m} onClose={() => setEditing(false)} />}
    </Drawer>
  );
}

function MonitorForm({ monitor, onClose }: { monitor?: Monitor; onClose: () => void }) {
  const [v, setV] = useState({
    name: monitor?.name || '',
    url: monitor?.url || '',
    method: monitor?.method || 'HEAD',
    expected_status: monitor?.expected_status || 200,
    timeout_seconds: monitor?.timeout_seconds || 10,
    fail_threshold: monitor?.fail_threshold || 2,
    tags: (monitor?.tags || []).join(', '),
    enabled: monitor?.enabled ?? true,
  });

  const save = useAct(
    () => monitor
      ? patch(`/api/uptime/monitors/${monitor.id}`, { ...v, tags: v.tags.split(',').map((t) => t.trim()).filter(Boolean) })
      : post('/api/uptime/monitors', { ...v, tags: v.tags.split(',').map((t) => t.trim()).filter(Boolean) }),
    ['uptime-monitors', 'uptime-monitor', 'uptime-summary'],
    monitor ? 'Monitor updated' : 'Monitor created',
    onClose,
  );

  const valid = v.name.trim().length >= 2 && /^https?:\/\/.+/.test(v.url);

  return (
    <Modal title={monitor ? `Edit: ${monitor.name}` : 'Add monitor'} onClose={onClose}>
      <Field label="Name" id="mon-name"><input id="mon-name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="My Website" /></Field>
      <Field label="URL" id="mon-url"><input id="mon-url" value={v.url} onChange={(e) => setV({ ...v, url: e.target.value })} placeholder="https://example.com" /></Field>
      <Field label="Method" id="mon-method">
        <select id="mon-method" value={v.method} onChange={(e) => setV({ ...v, method: e.target.value })}>
          <option value="HEAD">HEAD</option>
          <option value="GET">GET</option>
        </select>
      </Field>
      <Field label="Expected status code" id="mon-status">
        <input id="mon-status" type="number" min={100} max={599} value={v.expected_status} onChange={(e) => setV({ ...v, expected_status: Number(e.target.value) })} />
      </Field>
      <Field label="Timeout (seconds)" id="mon-timeout">
        <input id="mon-timeout" type="number" min={1} max={60} value={v.timeout_seconds} onChange={(e) => setV({ ...v, timeout_seconds: Number(e.target.value) })} />
      </Field>
      <Field label="Alert after N consecutive failures" id="mon-threshold">
        <input id="mon-threshold" type="number" min={1} max={10} value={v.fail_threshold} onChange={(e) => setV({ ...v, fail_threshold: Number(e.target.value) })} />
      </Field>
      <Field label="Tags (comma-separated)" id="mon-tags">
        <input id="mon-tags" value={v.tags} onChange={(e) => setV({ ...v, tags: e.target.value })} placeholder="production, frontend, api" />
      </Field>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, fontSize: 13 }}>
        <input type="checkbox" checked={v.enabled} onChange={(e) => setV({ ...v, enabled: e.target.checked })} />
        Enabled
      </label>
      {save.error && <ErrorBox error={save.error} />}
      <button className="btn primary" disabled={save.isPending || !valid} onClick={() => save.mutate(undefined as any)} style={{ marginTop: 12 }}>
        {save.isPending ? 'Saving…' : monitor ? 'Save changes' : 'Add monitor'}
      </button>
    </Modal>
  );
}
