import { useQuery, useQueryClient } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { REFRESH_MS } from '../lib/refresh';
import { Sev } from './ui';

type Popup = { id: string; severity: string; title: string; host: string; source: string };
type AlertRow = { id: string; severity: string; title: string; host?: string; source?: string };

export const MAX_VISIBLE = 4;
/** Only critical and high alerts pop up. */
export const popsUp = (severity: string | undefined) => severity === 'critical' || severity === 'high';
// How long a pop-up stays before it closes itself; critical stays until dismissed.
const LIFETIME: Record<string, number | null> = { critical: null, high: 30_000 };

/** Pop-up messages for new critical and high alerts. Driven by the live event stream; checks every 30 seconds instead when the stream is down. */
export function AlertPopups({ live }: { live: boolean }) {
  const seen = useRef(new Set<string>());
  const list = useRef<Popup[]>([]); // the visible pop-ups; state below only mirrors it for rendering
  const [popups, setPopups] = useState<Popup[]>([]);
  const [overflow, setOverflow] = useState(0);
  const [outcome, setOutcome] = useState<Record<string, string>>({}); // id -> "Acknowledged" / "Investigating" / error text
  const { can } = useAuth();
  const canTriage = can('alerts.triage');
  const navigate = useNavigate();
  const qc = useQueryClient();

  const dismiss = useCallback((id: string) => {
    list.current = list.current.filter((p) => p.id !== id);
    setPopups(list.current);
  }, []);

  const show = useCallback((a: AlertRow) => {
    if (seen.current.has(a.id) || !popsUp(a.severity)) return;
    seen.current.add(a.id);
    if (list.current.length >= MAX_VISIBLE) {
      setOverflow((n) => n + 1);
      return;
    }
    list.current = [...list.current, { id: a.id, severity: a.severity, title: a.title, host: a.host ?? '', source: a.source ?? '' }];
    setPopups(list.current);
    const life = a.severity in LIFETIME ? LIFETIME[a.severity] : 8_000; // null means stay until dismissed (`??` would turn it into 8 s)
    if (life) window.setTimeout(() => dismiss(a.id), life);
  }, [dismiss]);

  const open = useCallback((id: string) => {
    dismiss(id);
    navigate(`/app/alerts?open=${id}`);
  }, [dismiss, navigate]);

  const act = useCallback(async (id: string, status: 'acknowledged' | 'investigating') => {
    setOutcome((o) => ({ ...o, [id]: '…' }));
    try {
      await post('/api/alerts/bulk', { ids: [id], status });
      setOutcome((o) => ({ ...o, [id]: status === 'acknowledged' ? 'Acknowledged' : 'Investigating' }));
      ['alerts', 'alert', 'alert-stats', 'notif-alerts', 'dashboard', 'triage-queue'].forEach((k) => void qc.invalidateQueries({ queryKey: [k] }));
      window.setTimeout(() => dismiss(id), 2500);
    } catch (e) {
      setOutcome((o) => ({ ...o, [id]: e instanceof Error ? e.message : 'Could not update the alert' }));
    }
  }, [dismiss, qc]);

  // Live stream: the event carries the id and severity; the details come through the authorised API.
  useEffect(() => {
    const onLive = (e: Event) => {
      const ev = (e as CustomEvent<{ type: string; id?: string; severity?: string }>).detail;
      if (ev?.type !== 'alert.created' || !ev.id || seen.current.has(ev.id) || !popsUp(ev.severity)) return;
      get<AlertRow>(`/api/alerts/${ev.id}`).then(show).catch(() => { /* deleted or out of scope */ });
    };
    window.addEventListener('soc:live', onLive);
    return () => window.removeEventListener('soc:live', onLive);
  }, [show]);

  // Fallback while the stream is down: anything newer than what was there when checking started.
  const baseline = useRef<Set<string> | null>(null);
  const recent = useQuery({
    queryKey: ['alert-popups-recent'],
    queryFn: () => get<{ items: AlertRow[] }>('/api/alerts', { severity: ['critical', 'high'], sort: '-time', limit: 20 }),
    enabled: !live,
    refetchInterval: live ? false : REFRESH_MS,
  });
  useEffect(() => {
    const items = recent.data?.items;
    if (!items || live) return;
    if (baseline.current === null) {
      baseline.current = new Set(items.map((a) => a.id));
      items.forEach((a) => seen.current.add(a.id));
      return;
    }
    items.filter((a) => !baseline.current!.has(a.id)).reverse().forEach(show);
  }, [recent.data, live, show]);

  if (popups.length === 0 && overflow === 0) return null;
  return (
    <div className="alert-popups" aria-label="New alerts">
      {popups.map((p) => {
        const result = outcome[p.id];
        const done = result === 'Acknowledged' || result === 'Investigating';
        return (
          <div key={p.id} className={`alert-popup sev-${p.severity} clickable`} role={p.severity === 'critical' || p.severity === 'high' ? 'alert' : 'status'}
            tabIndex={0} aria-label={`${p.severity} alert: ${p.title}. Press Enter to open.`}
            onClick={() => open(p.id)} onKeyDown={(e) => { if (e.key === 'Enter' && e.target === e.currentTarget) open(p.id); }}>
            <div className="alert-popup-head">
              <Sev v={p.severity} /><span className="alert-popup-kind">New alert</span>
              <button type="button" className="alert-popup-close" aria-label="Dismiss" onClick={(e) => { e.stopPropagation(); dismiss(p.id); }}><X size={14} /></button>
            </div>
            <div className="alert-popup-title">{p.title}</div>
            {(p.host || p.source) && <div className="alert-popup-meta">{[p.host, p.source].filter(Boolean).join(' · ')}</div>}
            <div className="alert-popup-actions" onClick={(e) => e.stopPropagation()}>
              {done ? <span className="alert-popup-done">{result}</span> : <>
                {canTriage && <button type="button" disabled={result === '…'} onClick={() => void act(p.id, 'acknowledged')}>Acknowledge</button>}
                {canTriage && <button type="button" disabled={result === '…'} onClick={() => void act(p.id, 'investigating')}>Investigate</button>}
                <Link className="alert-popup-open" to={`/app/alerts?open=${p.id}`} onClick={() => dismiss(p.id)}>Open alert</Link>
              </>}
            </div>
            {result && !done && result !== '…' && <div className="alert-popup-error" role="status">{result}</div>}
          </div>
        );
      })}
      {overflow > 0 && (
        <div className="alert-popup more" role="status">
          <span>+{overflow} more critical or high alert{overflow === 1 ? '' : 's'}</span>
          <Link className="alert-popup-open" to="/app/alerts?status=new" onClick={() => setOverflow(0)}>View alerts</Link>
          <button type="button" className="alert-popup-close" aria-label="Dismiss" onClick={() => setOverflow(0)}><X size={14} /></button>
        </div>
      )}
    </div>
  );
}
