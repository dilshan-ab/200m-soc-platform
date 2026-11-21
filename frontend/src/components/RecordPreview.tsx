import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Drawer, ErrorBox, Loading, Sev, Status } from './ui';
import { get } from '../lib/api';
import { when } from '../lib/format';

export type PreviewRecord = { kind: 'alert' | 'case' | 'asset'; id: string };
export function RecordPreview({ record, onClose }: { record: PreviewRecord; onClose: () => void }) {
  const area = record.kind === 'case' ? 'cases' : `${record.kind}s`;
  const q = useQuery({ queryKey: [record.kind, record.id], queryFn: () => get(`/api/${area}/${encodeURIComponent(record.id)}`) });
  const value = q.data;
  return <Drawer title={value?.title || value?.name || `${record.kind} preview`} onClose={onClose}>
    {q.isPending ? <Loading /> : q.error ? <ErrorBox error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} /> : <>
      <div className="row"><Sev v={value.severity || value.criticality} /><Status v={value.status || value.agent_status} /></div>
      {value.description && <p className="record-description">{value.description}</p>}
      <dl className="kv">{[
        ['Host', value.host || value.hostname], ['Source', value.source], ['Source IP', value.src_ip],
        ['Case', value.number], ['Category', value.category], ['Created', value.time || value.created_at ? when(value.time || value.created_at) : ''],
        ['Owner', value.owner], ['Department', value.department], ['Operating system', value.os],
      ].filter(([, v]) => v !== undefined && v !== null && v !== '').map(([label, v]) => <div className="preview-field" key={String(label)}><dt>{label}</dt><dd>{String(v)}</dd></div>)}</dl>
      <Link className="button primary" to={`/app/${area}?open=${encodeURIComponent(record.id)}`}>Open full {record.kind}</Link>
    </>}
  </Drawer>;
}
