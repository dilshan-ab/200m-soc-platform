import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Summary } from '../components/manage';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';
import { get } from '../lib/api';
import { minutes, titleCase } from '../lib/format';
import { REFRESH_MS } from '../lib/refresh';

type AnalystRow = {
  id: string; name: string; email: string | null; role: string | null; active: boolean;
  alerts_assigned: number; alerts_acknowledged: number; alerts_resolved: number; alerts_breached: number;
  critical_high_handled: number; mtta_minutes: number | null; mttr_minutes: number | null;
  cases_owned: number; cases_closed: number; case_mttr_minutes: number | null;
};
type Performance = {
  since: string; days: number; analysts: AnalystRow[];
  team: { analysts_active: number; alerts_resolved: number; cases_closed: number; mtta_minutes: number | null; mttr_minutes: number | null; case_mttr_minutes: number | null };
};

const number = new Intl.NumberFormat();

export default function AnalystPerformance() {
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ['analyst-performance', days], queryFn: () => get<Performance>('/api/analysts/performance', { days }), refetchInterval: REFRESH_MS });
  const data = q.data;
  return (
    <>
      <PageHead title="Analyst performance" sub="MTTA, MTTR, SLA adherence and case volume per analyst." eyebrow="INSIGHTS">
        <select aria-label="Reporting period" value={days} onChange={(e) => setDays(Number(e.target.value))} className="select">
          {[7, 30, 90].map((n) => <option key={n} value={n}>Last {n} days</option>)}
        </select>
      </PageHead>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : data && (
        <>
          <Summary items={[
            { label: 'Active analysts', value: number.format(data.team.analysts_active) },
            { label: 'Alerts resolved', value: number.format(data.team.alerts_resolved) },
            { label: 'Cases closed', value: number.format(data.team.cases_closed) },
            { label: 'Team MTTA', value: minutes(data.team.mtta_minutes) },
            { label: 'Team MTTR', value: minutes(data.team.mttr_minutes) },
          ]} />
          {data.analysts.length === 0 ? <Empty>No assigned alerts or owned cases in this time range yet. Assign alerts and cases to analysts to start tracking performance.</Empty> : (
            <div className="table-wrap"><table>
              <thead><tr>
                <th>Analyst</th><th>Role</th><th>Assigned</th><th>Acked</th><th>Resolved</th><th>Crit/High</th>
                <th>MTTA</th><th>MTTR</th><th>SLA breaches</th><th>Cases owned</th><th>Cases closed</th><th>Case MTTR</th>
              </tr></thead>
              <tbody>{data.analysts.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}{!a.active && <small style={{ display: 'block', color: 'var(--muted)' }}>Inactive account</small>}</td>
                  <td>{a.role ? titleCase(a.role) : '—'}</td>
                  <td>{number.format(a.alerts_assigned)}</td>
                  <td>{number.format(a.alerts_acknowledged)}</td>
                  <td>{number.format(a.alerts_resolved)}</td>
                  <td>{number.format(a.critical_high_handled)}</td>
                  <td>{minutes(a.mtta_minutes)}</td>
                  <td>{minutes(a.mttr_minutes)}</td>
                  <td>{a.alerts_breached > 0 ? <span style={{ color: 'var(--danger, #c0392b)' }}>{a.alerts_breached}</span> : 0}</td>
                  <td>{number.format(a.cases_owned)}</td>
                  <td>{number.format(a.cases_closed)}</td>
                  <td>{minutes(a.case_mttr_minutes)}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
          <p style={{ color: 'var(--muted)', marginTop: 8 }}>
            MTTA = time from first seen to acknowledgement. MTTR = time from first seen to resolution. Case MTTR = time from case creation to closure.
            Only alerts with an assignee and cases with an owner are counted.
          </p>
        </>
      )}
    </>
  );
}
