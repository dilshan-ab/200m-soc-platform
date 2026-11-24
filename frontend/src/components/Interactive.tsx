import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Bell, CheckCircle2, Clock, X } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Modal, Sev } from './ui';
import { REFRESH_MS } from '../lib/refresh';

/* ── LiveTimer ─────────────────────────────────────────────────────── */
function fmt(ms: number): string {
  const abs = Math.abs(ms);
  const m = Math.floor(abs / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

export function LiveTimer({ deadline, done }: { deadline: string | null | undefined; done?: boolean }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (done || !deadline) return;
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, [done, deadline]);

  if (!deadline) return <span className="muted">—</span>;
  if (done) return <span className="live-timer done"><CheckCircle2 size={13} /> Done</span>;
  const diff = new Date(deadline).getTime() - now;
  const overdue = diff < 0;
  return (
    <span className={`live-timer${overdue ? ' overdue' : ''}`}>
      <Clock size={13} /> {overdue ? '−' : ''}{fmt(diff)}
    </span>
  );
}

/* ── Skeleton ──────────────────────────────────────────────────────── */
export function Skeleton({ lines = 5, width = 'full' }: { lines?: number; width?: 'full' | 'medium' | 'short' }) {
  const w = width === 'short' ? '40%' : width === 'medium' ? '70%' : '100%';
  return (
    <div className="skeleton-wrap" role="status" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton" style={{ width: i === lines - 1 ? '60%' : w }} />
      ))}
    </div>
  );
}

/* ── Pulse ─────────────────────────────────────────────────────────── */
export function Pulse({ active, color }: { active: boolean; color?: string }) {
  if (!active) return null;
  return <span className="pulse" style={color ? { background: color } : undefined} />;
}

/* ── NotificationPanel ─────────────────────────────────────────────── */
export function NotificationPanel({ onClose }: { onClose: () => void }) {
  const { can } = useAuth();
  const alerts = useQuery({
    queryKey: ['notif-alerts'],
    queryFn: () => get<{ items: any[] }>('/api/alerts', { severity: ['critical'], status: ['new'], limit: 5 }),
    refetchInterval: REFRESH_MS,
  });
  const approvals = useQuery({
    queryKey: ['notif-approvals'],
    enabled: can('response.approve'),
    queryFn: () => get<{ actions: any[]; changes: any[] }>('/api/approvals'),
    refetchInterval: REFRESH_MS,
  });
  const items = alerts.data?.items ?? [];
  const pendingActions = approvals.data?.actions ?? [];
  const pendingChanges = approvals.data?.changes ?? [];
  const total = pendingActions.length + pendingChanges.length;

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (!(e.target as HTMLElement).closest('.notification-panel, .bell')) onClose();
    };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [onClose]);

  return (
    <div className="notification-panel">
      <div className="notif-header">
        <Bell size={16} /> <strong>Notifications</strong>
        <button className="notif-close" onClick={onClose} aria-label="Close"><X size={16} /></button>
      </div>
      {items.length === 0 && total === 0 && (
        <div className="notif-empty">No critical alerts or pending approvals.</div>
      )}
      {items.length > 0 && (
        <div className="notif-section">
          <div className="notif-section-label"><AlertTriangle size={13} /> Critical alerts</div>
          {items.map((a) => (
            <Link key={a.id} className="notif-item" to={`/app/alerts?open=${a.id}`} onClick={onClose}>
              <Sev v={a.severity} />
              <span className="notif-title">{a.title}</span>
              <span className="notif-meta">{a.source}</span>
            </Link>
          ))}
          <Link className="notif-viewall" to="/app/alerts?severity=critical&status=new" onClick={onClose}>View all critical alerts</Link>
        </div>
      )}
      {total > 0 && (
        <div className="notif-section">
          <div className="notif-section-label"><CheckCircle2 size={13} /> Pending approvals ({total})</div>
          <Link className="notif-viewall" to="/app/approvals" onClick={onClose}>Review approvals</Link>
        </div>
      )}
    </div>
  );
}

/* ── KeyboardHelp ──────────────────────────────────────────────────── */
const SHORTCUTS: { key: string; label: string; scope?: string }[] = [
  { key: 'Ctrl+K', label: 'Open command palette' },
  { key: '?', label: 'Show keyboard shortcuts' },
  { key: 'j / k', label: 'Move down / up in list', scope: 'Tables' },
  { key: 'Arrow ↑ / ↓, Home / End', label: 'Navigate focused rows', scope: 'Tables' },
  { key: 'x', label: 'Toggle selection', scope: 'Alerts' },
  { key: 'Enter / Space', label: 'Open focused item', scope: 'Tables' },
  { key: 'a', label: 'Acknowledge selected', scope: 'Alerts' },
  { key: 'Escape', label: 'Clear selection / close panel' },
];

export function KeyboardHelp({ onClose }: { onClose: () => void }) {
  return <Modal title="Keyboard shortcuts" onClose={onClose}>
    <div className="kbd-help-list">
      {SHORTCUTS.map((shortcut) => (
        <div key={shortcut.key} className="kbd-help-row">
          <kbd>{shortcut.key}</kbd>
          <span>{shortcut.label}</span>
          {shortcut.scope && <span className="kbd-help-scope">{shortcut.scope}</span>}
        </div>
      ))}
    </div>
  </Modal>;
}

/* ── HoverActions ──────────────────────────────────────────────────── */
export function HoverActions({ children }: { children: ReactNode }) {
  return <div className="hover-actions">{children}</div>;
}

/* ── TaskProgress ──────────────────────────────────────────────────── */
export function TaskProgress({ tasks }: { tasks: { status: string }[] }) {
  const done = tasks.filter((t) => t.status === 'done').length;
  const total = tasks.length;
  if (total === 0) return null;
  const pct = Math.round((done / total) * 100);
  return (
    <div className="task-progress">
      <div className="task-progress-bar">
        <div className="task-progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="task-progress-label">{done}/{total} tasks · {pct}%</span>
    </div>
  );
}
