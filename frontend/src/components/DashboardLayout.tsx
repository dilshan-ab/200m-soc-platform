import { Children, createContext, isValidElement, useContext, useState, type ReactNode } from 'react';
import { useAuth } from '../lib/auth';
import { useToast } from './ui';

type Preference = { order: string[]; wide: string[] };
type Layout = Record<string, Preference>;
const Context = createContext<{ editing: boolean; layout: Layout; save: (group: string, value: Preference) => void }>({ editing: false, layout: {}, save: () => {} });
function load(key: string): Layout {
  try {
    const value = JSON.parse(localStorage.getItem(key) ?? '{}');
    if (!value || Array.isArray(value) || typeof value !== 'object') return {};
    return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, Preference] => {
      const v = entry[1] as Preference;
      return !!v && Array.isArray(v.order) && Array.isArray(v.wide) && [...v.order, ...v.wide].every((id) => typeof id === 'string');
    }));
  } catch { return {}; }
}
export function DashboardLayout({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  return <LayoutSettings key={me?.id} storageKey={`200m:dashboard-layout:v1:${me?.id}`} >{children}</LayoutSettings>;
}
function LayoutSettings({ storageKey, children }: { storageKey: string; children: ReactNode }) {
  const [editing, setEditing] = useState(false);
  const [layout, setLayout] = useState<Layout>(() => load(storageKey));
  const [error, setError] = useState('');
  const toast = useToast();
  function persist(next: Layout) {
    setLayout(next);
    try { localStorage.setItem(storageKey, JSON.stringify(next)); setError(''); }
    catch { setError('Layout changed for this visit. Browser storage is unavailable.'); }
  }
  return <Context.Provider value={{ editing, layout, save: (group, value) => persist({ ...layout, [group]: value }) }}>
    <div className="dashboard-layout-controls"><span>{editing ? 'Move widgets or choose their width. Changes save automatically on this browser.' : 'Your overview'}</span>
      <button className="btn small" aria-pressed={editing} onClick={() => setEditing(!editing)}>{editing ? 'Done customizing' : 'Customize dashboard'}</button>
      {editing && <button className="btn small" onClick={() => { const previous = layout; persist({}); toast('Dashboard layout reset', false, { label: 'Undo', run: () => persist(previous) }); }}>Reset layout</button>}
    </div>
    {error && <p role="status" className="notice">{error}</p>}{children}
  </Context.Provider>;
}
export function WidgetGrid({ group, children }: { group: string; children: ReactNode }) {
  const { editing, layout, save } = useContext(Context);
  const widgets = Children.toArray(children).filter(isValidElement);
  const ids = widgets.map((w) => String(w.key));
  const pref = layout[group] ?? { order: [], wide: [] };
  const order = [...new Set(pref.order.filter((id) => ids.includes(id))), ...ids.filter((id) => !pref.order.includes(id))];
  return <div className={`widget-grid widget-grid-${group}`}>
    {order.map((id, index) => {
      const widget = widgets.find((w) => String(w.key) === id)!;
      const title = String((widget.props as { 'data-widget-title'?: string })['data-widget-title'] ?? id.replace('.$', ''));
      const move = (direction: number) => { const next = [...order]; [next[index], next[index + direction]] = [next[index + direction], next[index]]; save(group, { ...pref, order: next }); };
      return <div className={`dashboard-widget${pref.wide.includes(id) ? ' widget-wide' : ''}`} key={id} data-widget={title}>
        {editing && <div className="widget-tools" role="group" aria-label={`Customize ${title}`}><strong>{title}</strong>
          <button className="btn small" aria-label={`Move ${title} earlier`} disabled={index === 0} onClick={() => move(-1)}>←</button>
          <button className="btn small" aria-label={`Move ${title} later`} disabled={index === order.length - 1} onClick={() => move(1)}>→</button>
          <label>Width <select aria-label={`${title} width`} value={pref.wide.includes(id) ? 'wide' : 'standard'} onChange={(e) => save(group, { ...pref, order, wide: e.target.value === 'wide' ? [...pref.wide.filter((v) => v !== id), id] : pref.wide.filter((v) => v !== id) })}><option value="standard">Standard</option><option value="wide">Full row</option></select></label>
        </div>}{widget}
      </div>;
    })}
  </div>;
}
