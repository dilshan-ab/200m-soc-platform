import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

const MAP: Record<string, string[]> = {
  'alert.created': ['alerts', 'dashboard', 'alert-stats', 'triage-queue', 'mitre-matrix'], 'alert.updated': ['alerts', 'dashboard', 'alert', 'triage-queue', 'mitre-matrix'], 'case.created': ['cases'], 'case.updated': ['cases', 'case'],
  'action.updated': ['requests', 'approvals', 'request'], 'approval.pending': ['approvals'], 'server.down': ['servers', 'dashboard'],
  'warroom.message': ['warroom', 'warrooms'], 'warroom.created': ['warrooms'],
};

/** Server-sent events carry identifiers only; the UI refetches through the authorised API. */
export function useLive(enabled: boolean): boolean {
  const qc = useQueryClient();
  const [on, setOn] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource('/api/stream');
    es.onopen = () => setOn(true);
    es.onerror = () => setOn(false);
    es.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as { type: string };
        (MAP[ev.type] ?? []).forEach((k) => void qc.invalidateQueries({ queryKey: [k] }));
      } catch { /* ignore malformed */ }
    };
    return () => es.close();
  }, [enabled, qc]);
  return on;
}
