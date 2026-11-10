import type { ReactNode } from 'react';

/** Quick-view chips: one click applies a saved filter. */
export function Chips({ items }: { items: { label: string; active: boolean; onClick: () => void; count?: number }[] }) {
  return (
    <div className="chips" role="group" aria-label="Quick views">
      {items.map((c) => (
        <button key={c.label} type="button" className={`chip${c.active ? ' on' : ''}`} aria-pressed={c.active} onClick={c.onClick}>
          {c.label}{c.count != null && <span>{c.count}</span>}
        </button>
      ))}
    </div>
  );
}

/** At-a-glance summary strip; tiles can be clicked to filter. */
export function Summary({ items }: { items: { label: string; value: ReactNode; tone?: 'ok' | 'warn' | 'bad'; onClick?: () => void; active?: boolean }[] }) {
  return (
    <div className="summary">
      {items.map((s) => (
        <button key={s.label} type="button" className={`sum ${s.tone ?? ''}${s.active ? ' on' : ''}`} onClick={s.onClick} disabled={!s.onClick}>
          <b>{s.value}</b><span>{s.label}</span>
        </button>
      ))}
    </div>
  );
}

export function Shortcuts({ items }: { items: [string, string][] }) {
  return <div className="shortcuts">{items.map(([k, d]) => <span key={k}><kbd>{k}</kbd> {d}</span>)}</div>;
}
