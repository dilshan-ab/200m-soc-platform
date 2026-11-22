import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, Clock, Code2, Filter, List, RefreshCw, Terminal } from 'lucide-react';
import { Fragment, useCallback, useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead, SearchBox } from '../components/ui';
import { get } from '../lib/api';

type LogEntry = {
  id: string; index: string; timestamp: string; rule_id: string; rule_level: number;
  rule_description: string; rule_groups: string[]; mitre: Record<string, any>;
  agent_id: string; agent_name: string; agent_ip: string;
  src_ip: string; dst_ip: string; src_port: number | null; dst_port: number | null;
  username: string; location: string; full_log: string; raw: Record<string, any>;
};
type SearchResult = { source: string; total: number; from: number; size: number; logs: LogEntry[] };

function levelColor(level: number): string {
  if (level >= 12) return 'var(--bad)';
  if (level >= 7) return 'var(--warn)';
  if (level >= 3) return 'var(--muted)';
  return 'var(--ok)';
}
function levelLabel(level: number): string {
  if (level >= 12) return 'critical';
  if (level >= 7) return 'high';
  if (level >= 3) return 'medium';
  return 'low';
}

export default function LogSearch() {
  const [q, setQ] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [view, setView] = useState<'table' | 'raw'>('table');
  const [page, setPage] = useState(1);
  const [size] = useState(50);
  const [sort, setSort] = useState<'desc' | 'asc'>('desc');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState({ severity: '', host: '', rule_id: '', src_ip: '', start: '', end: '' });
  const [showFilters, setShowFilters] = useState(false);

  const params = new URLSearchParams();
  if (submitted) params.set('q', submitted);
  params.set('page', String(page));
  params.set('size', String(size));
  params.set('sort', sort);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.host) params.set('host', filters.host);
  if (filters.rule_id) params.set('rule_id', filters.rule_id);
  if (filters.src_ip) params.set('src_ip', filters.src_ip);
  if (filters.start) params.set('start', filters.start);
  if (filters.end) params.set('end', filters.end);

  const results = useQuery({
    queryKey: ['log-search', submitted, page, size, sort, filters],
    queryFn: () => get<SearchResult>(`/api/logs/search?${params.toString()}`),
    refetchInterval: submitted ? false : 10000,
  });

  const toggle = useCallback((id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const totalPages = results.data ? Math.ceil(results.data.total / size) : 0;

  return (
    <>
      <PageHead title="Log Search" sub={`Search raw logs from ${results.data?.source === 'wazuh' ? 'Wazuh indexer' : 'platform alert database'}. Toggle between organized and raw views.`} />

      <form className="row" onSubmit={e => { e.preventDefault(); setSubmitted(q); setPage(1); }} style={{ gap: 8, marginBottom: 12, alignItems: 'stretch' }}>
        <SearchBox value={q} onChange={v => setQ(v)} placeholder="Search logs… (Lucene syntax supported)" label="Search logs" />
        <button className="btn" type="button" onClick={() => setShowFilters(!showFilters)} title="Filters" style={{ minHeight: 42 }}>
          <Filter size={14} /> Filters
        </button>
        <button className="btn" type="button" onClick={() => results.refetch()} title="Refresh" style={{ minHeight: 42 }}><RefreshCw size={14} /></button>
      </form>

      {showFilters && (
        <div className="card" style={{ padding: 12, marginBottom: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>Severity</label>
              <select value={filters.severity} onChange={e => { setFilters({ ...filters, severity: e.target.value }); setPage(1); }}>
                <option value="">All</option>
                <option value="info">Info</option><option value="low">Low</option>
                <option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>Host</label>
              <input placeholder="hostname" value={filters.host} onChange={e => setFilters({ ...filters, host: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>Rule ID</label>
              <input placeholder="e.g. 5710" value={filters.rule_id} onChange={e => setFilters({ ...filters, rule_id: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>Source IP</label>
              <input placeholder="10.0.0.1" value={filters.src_ip} onChange={e => setFilters({ ...filters, src_ip: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>From</label>
              <input type="datetime-local" value={filters.start} onChange={e => setFilters({ ...filters, start: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>To</label>
              <input type="datetime-local" value={filters.end} onChange={e => setFilters({ ...filters, end: e.target.value })} />
            </div>
          </div>
          <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
            <button className="btn small" onClick={() => { setFilters({ severity: '', host: '', rule_id: '', src_ip: '', start: '', end: '' }); setPage(1); }}>Clear filters</button>
          </div>
        </div>
      )}

      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          {results.data && <span style={{ fontSize: 13, color: 'var(--muted)' }}>{results.data.total.toLocaleString()} log{results.data.total !== 1 ? 's' : ''} found · source: <strong>{results.data.source}</strong></span>}
        </div>
        <div className="row" style={{ gap: 4 }}>
          <button className={`btn small ${view === 'table' ? 'primary' : ''}`} onClick={() => setView('table')} title="Organized view"><List size={14} /></button>
          <button className={`btn small ${view === 'raw' ? 'primary' : ''}`} onClick={() => setView('raw')} title="Raw JSON view"><Code2 size={14} /></button>
          <button className={`btn small`} onClick={() => { setSort(sort === 'desc' ? 'asc' : 'desc'); setPage(1); }} title={`Sort ${sort === 'desc' ? 'oldest first' : 'newest first'}`}>
            <Clock size={14} /> {sort === 'desc' ? 'Newest' : 'Oldest'}
          </button>
        </div>
      </div>

      {results.isLoading ? <Loading /> : results.error ? <ErrorBox error={results.error} /> : results.data!.logs.length === 0 ? (
        <Empty>{submitted ? `No logs matching "${submitted}"` : 'No logs found. Try adjusting your filters or check your Wazuh indexer connection.'}</Empty>
      ) : view === 'table' ? (
        <LogTable logs={results.data!.logs} expanded={expanded} onToggle={toggle} />
      ) : (
        <RawView logs={results.data!.logs} expanded={expanded} onToggle={toggle} />
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

function LogTable({ logs, expanded, onToggle }: { logs: LogEntry[]; expanded: Set<string>; onToggle: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 28 }} />
            <th>Time</th>
            <th>Level</th>
            <th>Rule</th>
            <th>Agent</th>
            <th>Source IP</th>
            <th>User</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {logs.map(log => (
            <Fragment key={log.id}>
              <tr onClick={() => onToggle(log.id)} style={{ cursor: 'pointer' }} className={expanded.has(log.id) ? 'selected' : ''}>
                <td>{expanded.has(log.id) ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                <td style={{ whiteSpace: 'nowrap', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                  {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                </td>
                <td>
                  <span className="badge" style={{ background: levelColor(log.rule_level), color: '#fff', fontSize: 10 }}>
                    {log.rule_level} · {levelLabel(log.rule_level)}
                  </span>
                </td>
                <td><span className="mono" style={{ fontSize: 12 }}>{log.rule_id || '—'}</span></td>
                <td style={{ fontSize: 12 }}>{log.agent_name || '—'}</td>
                <td><span className="mono" style={{ fontSize: 12 }}>{log.src_ip || '—'}</span></td>
                <td style={{ fontSize: 12 }}>{log.username || '—'}</td>
                <td style={{ fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.rule_description}</td>
              </tr>
              {expanded.has(log.id) && (
                <tr>
                  <td colSpan={8} style={{ padding: 0 }}>
                    <LogDetail log={log} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LogDetail({ log }: { log: LogEntry }) {
  const [showRaw, setShowRaw] = useState(false);
  const mitre = log.mitre || {};
  const mitreIds = mitre.id || mitre.technique || [];

  return (
    <div style={{ padding: '12px 16px', background: 'var(--soft)', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8, marginBottom: 12 }}>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Timestamp</span><div style={{ fontSize: 13 }}>{log.timestamp ? new Date(log.timestamp).toISOString() : '—'}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Rule ID</span><div style={{ fontSize: 13 }}>{log.rule_id || '—'}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Level</span><div style={{ fontSize: 13, color: levelColor(log.rule_level) }}>{log.rule_level} ({levelLabel(log.rule_level)})</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Agent</span><div style={{ fontSize: 13 }}>{log.agent_name}{log.agent_id ? ` (${log.agent_id})` : ''}{log.agent_ip ? ` · ${log.agent_ip}` : ''}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Source</span><div className="mono" style={{ fontSize: 12 }}>{log.src_ip || '—'}{log.src_port ? `:${log.src_port}` : ''}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Destination</span><div className="mono" style={{ fontSize: 12 }}>{log.dst_ip || '—'}{log.dst_port ? `:${log.dst_port}` : ''}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>User</span><div style={{ fontSize: 13 }}>{log.username || '—'}</div></div>
        <div><span style={{ fontSize: 11, color: 'var(--muted)' }}>Location</span><div style={{ fontSize: 13 }}>{log.location || '—'}</div></div>
      </div>

      {log.rule_groups?.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>Groups: </span>
          {log.rule_groups.map(g => <span key={g} className="badge" style={{ marginRight: 4 }}>{g}</span>)}
        </div>
      )}

      {Array.isArray(mitreIds) && mitreIds.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>MITRE ATT&CK: </span>
          {mitreIds.map((id: string) => <span key={id} className="badge" style={{ marginRight: 4, background: 'var(--accent)', color: '#fff' }}>{id}</span>)}
        </div>
      )}

      <div style={{ marginBottom: 8 }}>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>Description</span>
        <div style={{ fontSize: 13 }}>{log.rule_description}</div>
      </div>

      {log.full_log && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>Full Log</span>
          <pre className="log-raw">{log.full_log}</pre>
        </div>
      )}

      <button className="btn small" onClick={() => setShowRaw(!showRaw)} style={{ marginTop: 4 }}>
        <Terminal size={12} /> {showRaw ? 'Hide' : 'Show'} raw JSON
      </button>
      {showRaw && (
        <pre className="log-raw" style={{ marginTop: 8 }}>{JSON.stringify(log.raw, null, 2)}</pre>
      )}
    </div>
  );
}

function RawView({ logs, expanded, onToggle }: { logs: LogEntry[]; expanded: Set<string>; onToggle: (id: string) => void }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 1, fontFamily: 'var(--mono)', fontSize: 12 }}>
      {logs.map(log => (
        <div key={log.id} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4 }}>
          <div
            onClick={() => onToggle(log.id)}
            style={{ padding: '8px 12px', cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'flex-start', lineHeight: 1.5 }}
          >
            <span style={{ color: 'var(--muted)', whiteSpace: 'nowrap', flexShrink: 0 }}>
              {log.timestamp ? new Date(log.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '—'}
            </span>
            <span style={{ color: levelColor(log.rule_level), flexShrink: 0, minWidth: 20, textAlign: 'center' }}>{log.rule_level}</span>
            <span style={{ color: 'var(--accent)', flexShrink: 0 }}>{log.agent_name || '—'}</span>
            <span style={{ color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: expanded.has(log.id) ? 'pre-wrap' : 'nowrap' }}>
              {log.rule_id ? `[${log.rule_id}] ` : ''}{log.rule_description}
              {log.src_ip ? ` src=${log.src_ip}` : ''}{log.username ? ` user=${log.username}` : ''}
            </span>
          </div>
          {expanded.has(log.id) && (
            <pre className="log-raw" style={{ margin: '0 12px 12px', maxHeight: 400, overflow: 'auto' }}>
              {JSON.stringify(log.raw, null, 2)}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}
