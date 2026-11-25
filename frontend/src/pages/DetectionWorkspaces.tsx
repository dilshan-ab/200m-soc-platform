import { useQuery } from '@tanstack/react-query';
import { ArrowRight } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Empty, ErrorBox, Loading, PageHead, Sev } from '../components/ui';
import { get } from '../lib/api';
import { SEVERITIES, ago } from '../lib/format';
import { REFRESH_MS } from '../lib/refresh';

type Correlation = { client_id: string | null; host: string; sources: number; alerts: number; last_seen: string };
type VulnerabilitySummary = { by_severity: Record<string, Record<string, number>>; overdue: number };
const number = new Intl.NumberFormat();

export function Xdr() {
  const [days, setDays] = useState(7);
  const q = useQuery({
    queryKey: ['alert-correlations', days],
    queryFn: () => get<{ since: string; items: Correlation[] }>('/api/alerts/correlations', { days }),
    refetchInterval: REFRESH_MS,
  });
  return (
    <>
      <PageHead title="XDR" eyebrow="CROSS-SOURCE DETECTION" sub="Find hosts with alerts from two or more sources within the same client and time window.">
        <select className="select" aria-label="Correlation window" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option>
        </select>
      </PageHead>
      {q.error ? <ErrorBox error={q.error} /> : !q.data ? <Loading /> : q.data.items.length === 0 ? (
        <Empty>No hosts have alerts from multiple sources in this window.</Empty>
      ) : (
        <section className="panel">
          <div className="panel-title"><div><h2>Correlated hosts</h2><p>Up to 50 hosts, ranked by alert volume</p></div></div>
          <div className="table-scroll"><table>
            <thead><tr><th>Host</th><th>Sources</th><th>Alerts</th><th>Last seen</th></tr></thead>
            <tbody>{q.data.items.map((item) => {
              const params = new URLSearchParams({ host: item.host, since: q.data.since });
              if (item.client_id) params.set('client_id', item.client_id);
              else params.set('unassigned_client', 'true');
              return (
                <tr key={JSON.stringify([item.client_id, item.host])}>
                  <td><Link className="record-link" to={`/app/siem?${params}`}>{item.host} <ArrowRight size={13} aria-hidden="true" /></Link></td>
                  <td>{number.format(item.sources)}</td><td>{number.format(item.alerts)}</td><td>{ago(item.last_seen)}</td>
                </tr>
              );
            })}</tbody>
          </table></div>
        </section>
      )}
    </>
  );
}

export function RiskAnalytics() {
  const q = useQuery({
    queryKey: ['vuln-summary'],
    queryFn: () => get<VulnerabilitySummary>('/api/vulnerabilities/summary'),
    refetchInterval: REFRESH_MS,
  });
  const summary = q.data;
  const rows = SEVERITIES.map((severity) => ({
    severity,
    open: summary?.by_severity[severity]?.open ?? 0,
    inProgress: summary?.by_severity[severity]?.in_progress ?? 0,
    accepted: summary?.by_severity[severity]?.accepted_risk ?? 0,
  }));
  const active = rows.reduce((count, row) => count + row.open + row.inProgress, 0);
  const critical = rows[0].open + rows[0].inProgress;
  return (
    <>
      <PageHead title="Risk Analytics" eyebrow="POSTURE" sub="Track vulnerability exposure, remediation backlog, and accepted risk within your scope.">
        <Link className="btn" to="/app/vulnerabilities">Open findings <ArrowRight size={14} /></Link>
      </PageHead>
      {q.error ? <ErrorBox error={q.error} /> : !summary ? <Loading /> : <>
        <div className="metrics">
          <div className="metric"><span>Active findings</span><strong>{number.format(active)}</strong><small>Open or in progress</small></div>
          <div className="metric"><span>Critical findings</span><strong>{number.format(critical)}</strong><small>Open or in progress</small></div>
          <div className="metric"><span>Overdue findings</span><strong>{number.format(summary.overdue)}</strong><small>Past remediation deadline</small></div>
        </div>
        <section className="panel">
          <div className="panel-title"><h2>Findings by severity</h2></div>
          <div className="table-scroll"><table>
            <thead><tr><th>Severity</th><th>Open</th><th>In progress</th><th>Accepted risk</th></tr></thead>
            <tbody>{rows.map((row) => (
              <tr key={row.severity}>
                <td><Sev v={row.severity} /></td>
                <td><Link className="record-link" to={`/app/vulnerabilities?severity=${row.severity}&status=open`}>{number.format(row.open)}</Link></td>
                <td><Link className="record-link" to={`/app/vulnerabilities?severity=${row.severity}&status=in_progress`}>{number.format(row.inProgress)}</Link></td>
                <td><Link className="record-link" to={`/app/vulnerabilities?severity=${row.severity}&status=accepted_risk`}>{number.format(row.accepted)}</Link></td>
              </tr>
            ))}</tbody>
          </table></div>
        </section>
      </>}
    </>
  );
}
