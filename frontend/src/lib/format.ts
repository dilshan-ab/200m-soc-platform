export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export function ago(iso?: string | null): string {
  if (!iso) return '—';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '—');
export function until(iso?: string | null): string {
  if (!iso) return '—';
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  if (s < 0) return `overdue ${ago(iso).replace(' ago', '')}`;
  if (s < 3600) return `${Math.ceil(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}
export const titleCase = (s: string) => s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
export const firstName = (name?: string | null) => (name || '').trim().split(/\s+/)[0] || '';
export function minutes(v: number | null | undefined): string {
  if (v == null) return '—';
  if (v < 60) return `${Math.round(v)}m`;
  if (v < 1440) return `${Math.floor(v / 60)}h ${Math.round(v % 60)}m`;
  return `${Math.floor(v / 1440)}d ${Math.round((v % 1440) / 60)}h`;
}
