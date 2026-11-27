import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

const MAP: Record<string, string[]> = {
  'alert.created': ['alerts', 'dashboard', 'threat-map', 'alert-stats', 'triage-queue', 'mitre-matrix', 'notif-alerts'], 'alert.updated': ['alerts', 'dashboard', 'threat-map', 'alert', 'alert-stats', 'triage-queue', 'mitre-matrix', 'notif-alerts'], 'case.created': ['cases', 'dashboard'], 'case.updated': ['cases', 'case', 'dashboard'],
  'action.updated': ['requests', 'approvals', 'request'], 'approval.pending': ['approvals'], 'server.down': ['servers', 'dashboard'],
  'alert.deleted': ['alerts', 'alert', 'alert-stats', 'dashboard', 'triage-queue', 'mitre-matrix', 'threat-map', 'overview-recent-alerts', 'cases', 'case', 'incidents', 'incident', 'assets', 'asset', 'notif-alerts'],
  'warroom.deleted': ['warrooms'],
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
        window.dispatchEvent(new CustomEvent('soc:live', { detail: ev })); // e.g. pop-ups for new alerts
      } catch { /* ignore malformed */ }
    };
    return () => es.close();
  }, [enabled, qc]);
  return on;
}
