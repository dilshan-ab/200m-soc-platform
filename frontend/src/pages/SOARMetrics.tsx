import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Summary } from '../components/manage';
import { ErrorBox, Loading, PageHead } from '../components/ui';
import { get } from '../lib/api';
import { minutes, titleCase } from '../lib/format';
import { REFRESH_MS } from '../lib/refresh';

type SOARData = {
  since: string; days: number;
  alerts: { total: number; mtta_minutes: number | null; mttr_minutes: number | null; sla_breached: number; sla_compliance_pct: number; by_severity: Record<string, number> };
  playbooks: { total: number; published: number; runs: number; by_status: Record<string, number>; avg_duration_minutes: number | null; success_rate_pct: number | null; top: { name: string; runs: number }[] };
  automation: { rules_total: number; rules_enabled: number; evaluations: number; matched: number; match_rate_pct: number | null; failures: number; coverage: { auto_resolved: number; manual_resolved: number; auto_pct: number | null } };
  response_actions: { total: number; by_status: Record<string, number>; by_type: Record<string, number>; avg_approval_minutes: number | null; avg_execution_minutes: number | null };
};

const num = new Intl.NumberFormat();
const pct = (v: number | null | undefined) => v != null ? `${v}%` : '—';

export default function SOARMetrics() {
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ['soar-metrics', days], queryFn: () => get<SOARData>('/api/soar/metrics', { days }), refetchInterval: REFRESH_MS });
  const d = q.data;
  return (
    <>
      <PageHead title="SOAR metrics" sub="Playbook effectiveness, automation coverage, response action analytics and SLA compliance." eyebrow="INSIGHTS">
        <select aria-label="Reporting period" value={days} onChange={(e) => setDays(Number(e.target.value))} className="select">
          {[7, 30, 90].map((n) => <option key={n} value={n}>Last {n} days</option>)}
        </select>
      </PageHead>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : d && (
        <>
          {/* KPI strip */}
          <Summary items={[
            { label: 'MTTA', value: minutes(d.alerts.mtta_minutes) },
            { label: 'MTTR', value: minutes(d.alerts.mttr_minutes) },
            { label: 'SLA compliance', value: pct(d.alerts.sla_compliance_pct), tone: d.alerts.sla_compliance_pct >= 95 ? 'ok' : d.alerts.sla_compliance_pct >= 80 ? 'warn' : 'bad' },
            { label: 'Automation coverage', value: pct(d.automation.coverage.auto_pct), tone: (d.automation.coverage.auto_pct ?? 0) >= 50 ? 'ok' : 'warn' },
            { label: 'Playbook success', value: pct(d.playbooks.success_rate_pct), tone: (d.playbooks.success_rate_pct ?? 0) >= 90 ? 'ok' : (d.playbooks.success_rate_pct ?? 0) >= 70 ? 'warn' : 'bad' },
          ]} />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 'var(--gap, 16px)', marginTop: 16 }}>
            {/* Playbooks panel */}
            <section className="panel">
              <h3>Playbooks</h3>
              <dl className="stat-grid">
                <div><dt>Total</dt><dd>{d.playbooks.total}</dd></div>
                <div><dt>Published</dt><dd>{d.playbooks.published}</dd></div>
                <div><dt>Runs</dt><dd>{num.format(d.playbooks.runs)}</dd></div>
                <div><dt>Avg duration</dt><dd>{minutes(d.playbooks.avg_duration_minutes)}</dd></div>
                <div><dt>Completed</dt><dd>{num.format(d.playbooks.by_status['completed'] ?? 0)}</dd></div>
                <div><dt>Failed</dt><dd>{num.format(d.playbooks.by_status['failed'] ?? 0)}</dd></div>
              </dl>
              {d.playbooks.top.length > 0 && (<>
                <h4 style={{ marginTop: 12 }}>Top playbooks</h4>
                <div className="table-wrap"><table>
                  <thead><tr><th>Playbook</th><th style={{ textAlign: 'right' }}>Runs</th></tr></thead>
                  <tbody>{d.playbooks.top.map((p) => <tr key={p.name}><td>{p.name}</td><td style={{ textAlign: 'right' }}>{num.format(p.runs)}</td></tr>)}</tbody>
                </table></div>
              </>)}
            </section>

            {/* Automation panel */}
            <section className="panel">
              <h3>Automation rules</h3>
              <dl className="stat-grid">
                <div><dt>Total rules</dt><dd>{d.automation.rules_total}</dd></div>
                <div><dt>Enabled</dt><dd>{d.automation.rules_enabled}</dd></div>
                <div><dt>Evaluations</dt><dd>{num.format(d.automation.evaluations)}</dd></div>
                <div><dt>Matched</dt><dd>{num.format(d.automation.matched)}</dd></div>
                <div><dt>Match rate</dt><dd>{pct(d.automation.match_rate_pct)}</dd></div>
                <div><dt>Failures</dt><dd>{num.format(d.automation.failures)}</dd></div>
              </dl>
              <h4 style={{ marginTop: 12 }}>Coverage</h4>
              <div style={{ display: 'flex', borderRadius: 6, overflow: 'hidden', height: 26, marginTop: 4, border: '1px solid var(--border)' }}>
                {(d.automation.coverage.auto_resolved + d.automation.coverage.manual_resolved) > 0 ? (<>
                  <div style={{ flex: d.automation.coverage.auto_resolved, background: 'color-mix(in srgb, var(--ok) 22%, var(--surface))', color: 'var(--ok)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 600 }}>
                    {d.automation.coverage.auto_resolved > 0 && `Auto ${pct(d.automation.coverage.auto_pct)}`}
                  </div>
                  <div style={{ flex: d.automation.coverage.manual_resolved, background: 'color-mix(in srgb, var(--accent) 22%, var(--surface))', color: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 600 }}>
                    {d.automation.coverage.manual_resolved > 0 && 'Manual'}
                  </div>
                </>) : <div style={{ flex: 1, background: 'var(--soft)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, color: 'var(--muted)' }}>No resolved alerts</div>}
              </div>
              <p style={{ color: 'var(--muted)', fontSize: 12, marginTop: 4 }}>Auto: {num.format(d.automation.coverage.auto_resolved)} · Manual: {num.format(d.automation.coverage.manual_resolved)}</p>
            </section>

            {/* Response actions panel */}
            <section className="panel">
              <h3>Response actions</h3>
              <dl className="stat-grid">
                <div><dt>Total requests</dt><dd>{num.format(d.response_actions.total)}</dd></div>
                <div><dt>Avg approval time</dt><dd>{minutes(d.response_actions.avg_approval_minutes)}</dd></div>
                <div><dt>Avg execution time</dt><dd>{minutes(d.response_actions.avg_execution_minutes)}</dd></div>
                <div><dt>Completed</dt><dd>{num.format(d.response_actions.by_status['completed'] ?? 0)}</dd></div>
                <div><dt>Pending</dt><dd>{num.format(d.response_actions.by_status['pending_approval'] ?? 0)}</dd></div>
                <div><dt>Failed</dt><dd>{num.format(d.response_actions.by_status['failed'] ?? 0)}</dd></div>
              </dl>
              {Object.keys(d.response_actions.by_type).length > 0 && (<>
                <h4 style={{ marginTop: 12 }}>By action type</h4>
                <div className="table-wrap"><table>
                  <thead><tr><th>Action</th><th style={{ textAlign: 'right' }}>Count</th></tr></thead>
                  <tbody>{Object.entries(d.response_actions.by_type).map(([k, v]) => <tr key={k}><td>{titleCase(k)}</td><td style={{ textAlign: 'right' }}>{num.format(v)}</td></tr>)}</tbody>
                </table></div>
              </>)}
            </section>

            {/* Alert overview panel */}
            <section className="panel">
              <h3>Alert overview</h3>
              <dl className="stat-grid">
                <div><dt>Total alerts</dt><dd>{num.format(d.alerts.total)}</dd></div>
                <div><dt>SLA breaches</dt><dd style={{ color: d.alerts.sla_breached > 0 ? 'var(--bad)' : undefined }}>{num.format(d.alerts.sla_breached)}</dd></div>
                <div><dt>SLA compliance</dt><dd>{pct(d.alerts.sla_compliance_pct)}</dd></div>
              </dl>
              {Object.keys(d.alerts.by_severity).length > 0 && (<>
                <h4 style={{ marginTop: 12 }}>By severity</h4>
                <div className="table-wrap"><table>
                  <thead><tr><th>Severity</th><th style={{ textAlign: 'right' }}>Count</th></tr></thead>
                  <tbody>{['critical', 'high', 'medium', 'low', 'info'].filter((s) => d.alerts.by_severity[s]).map((s) => (
                    <tr key={s}><td><span className={`badge sev-${s}`}>{s}</span></td><td style={{ textAlign: 'right' }}>{num.format(d.alerts.by_severity[s])}</td></tr>
                  ))}</tbody>
                </table></div>
              </>)}
            </section>
          </div>

          <p style={{ color: 'var(--muted)', marginTop: 16, fontSize: 12 }}>
            MTTA = time from first seen to acknowledgement. MTTR = time from first seen to resolution.
            Automation coverage = resolved alerts without an assignee (auto) vs with an assignee (manual).
          </p>
        </>
      )}
    </>
  );
}
