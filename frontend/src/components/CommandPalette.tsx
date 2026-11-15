import * as Dialog from '@radix-ui/react-dialog';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, Bell, Command, Layers, LayoutGrid, LoaderCircle, Search, Server, X } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { get } from '../lib/api';

export type PaletteItem = { label: string; hint: string; run: () => void; kind?: 'page' | 'action' };
type RecordArea = 'alerts' | 'cases' | 'assets';
type Scope = 'all' | 'pages' | RecordArea | 'actions';
type SearchResults = {
  alerts: { id: string; title: string; severity: string }[];
  cases: { id: string; title: string; number: number }[];
  assets: { id: string; name: string }[];
};
const icons = { pages: LayoutGrid, actions: Command, alerts: Bell, cases: Layers, assets: Server };
const scopeLabels = { all: 'All', pages: 'Pages', alerts: 'Alerts', cases: 'Cases', assets: 'Assets', actions: 'Actions' };

export function CommandPalette({ items, onClose, onSearch, onNavigate, recordTypes = [] }: {
  items: PaletteItem[];
  onClose: () => void;
  onSearch?: (q: string) => void;
  onNavigate?: (path: string) => void;
  recordTypes?: RecordArea[];
}) {
  const [q, setQ] = useState('');
  const [scope, setScope] = useState<Scope>('all');
  const [i, setI] = useState(0);
  const [debounced, setDebounced] = useState('');
  const ref = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const listId = useId();
  const term = q.trim();
  useEffect(() => { ref.current?.focus(); }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(term), 200);
    return () => window.clearTimeout(timer);
  }, [term]);
  const results = useQuery({
    queryKey: ['workspace-search', debounced],
    queryFn: () => get<SearchResults>('/api/search', { q: debounced }),
    enabled: !!onNavigate && recordTypes.length > 0 && debounced.length >= 2,
  });
  const matchingQuery = term === debounced;
  const searching = !!onNavigate && recordTypes.length > 0 && term.length >= 2;
  const pending = searching && (!matchingQuery || results.isFetching);
  const list = useMemo(() => {
    const query = term.toLowerCase();
    const choices = items.filter((item) => !query || `${item.label} ${item.hint}`.toLowerCase().includes(query)).map((item) => ({
      ...item, key: `command-${item.label}`, area: item.kind === 'action' ? 'actions' as const : 'pages' as const,
    }));
    const records = matchingQuery && searching ? results.data : undefined;
    const matches = [
      ...choices,
      ...(recordTypes.includes('alerts') ? (records?.alerts ?? []).map((alert) => ({ key: `alert-${alert.id}`, label: alert.title, hint: `${alert.severity} alert`, area: 'alerts' as const, run: () => onNavigate?.(`/app/alerts?open=${encodeURIComponent(alert.id)}`) })) : []),
      ...(recordTypes.includes('cases') ? (records?.cases ?? []).map((item) => ({ key: `case-${item.id}`, label: item.title, hint: `Case #${item.number}`, area: 'cases' as const, run: () => onNavigate?.(`/app/cases?open=${encodeURIComponent(item.id)}`) })) : []),
      ...(recordTypes.includes('assets') ? (records?.assets ?? []).map((asset) => ({ key: `asset-${asset.id}`, label: asset.name, hint: 'Asset inventory', area: 'assets' as const, run: () => onNavigate?.(`/app/assets?open=${encodeURIComponent(asset.id)}`) })) : []),
    ];
    if (onSearch && term.length >= 2) matches.push({ key: 'search-alerts', label: `Search all alerts for “${term}”`, hint: 'Open alert search', area: 'alerts', run: () => onSearch(term) });
    return matches.filter((item) => scope === 'all' || item.area === scope);
  }, [items, term, results.data, matchingQuery, searching, recordTypes, scope, onSearch, onNavigate]);
  useEffect(() => setI(0), [q, scope]);
  const selected = Math.min(i, Math.max(0, list.length - 1));
  useEffect(() => { listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' }); }, [selected, q, scope]);
  const go = (item?: typeof list[number]) => { if (!item) return; onClose(); item.run(); };
  const scopes: Scope[] = ['all', 'pages', ...recordTypes, 'actions'];

  return <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="palette-backdrop" />
      <Dialog.Content className="palette" aria-describedby={undefined}>
        <Dialog.Title className="sr-only">Search workspace</Dialog.Title>
        <div className="palette-search-row">
          <Search size={21} aria-hidden="true" />
          <input ref={ref} value={q} onChange={(event) => setQ(event.target.value)} placeholder={recordTypes.length ? `Search pages, ${recordTypes.join(', ')}…` : 'Search pages and actions…'} aria-label="Command"
            role="combobox" aria-expanded="true" aria-autocomplete="list" aria-controls={listId}
            aria-activedescendant={list.length ? `${listId}-${selected}` : undefined} autoComplete="off" maxLength={200}
            onKeyDown={(event) => {
              if (event.nativeEvent.isComposing) return;
              if (event.key === 'ArrowDown') { event.preventDefault(); setI((value) => list.length ? (value + 1) % list.length : 0); }
              else if (event.key === 'ArrowUp') { event.preventDefault(); setI((value) => list.length ? (value - 1 + list.length) % list.length : 0); }
              else if (event.key === 'Enter') { event.preventDefault(); go(list[selected]); }
            }} />
          {q && <button type="button" className="palette-icon-button" aria-label="Clear workspace search" onClick={() => { setQ(''); ref.current?.focus(); }}><X size={17} /></button>}
          <Dialog.Close className="palette-icon-button" aria-label="Close workspace search"><kbd>Esc</kbd></Dialog.Close>
        </div>
        <div className="palette-scopes" role="group" aria-label="Search in">
          {scopes.map((area) => <button type="button" key={area} aria-pressed={scope === area} onClick={() => setScope(area)}>{scopeLabels[area]}</button>)}
        </div>
        <div className="palette-result-status" role="status">
          {pending ? <><LoaderCircle size={14} className="palette-spinner" aria-hidden="true" />Searching workspace…</> : term ? `${list.length} results` : 'Quick navigation and actions'}
        </div>
        {searching && matchingQuery && results.error && <div className="palette-search-error" role="alert">Workspace results could not load. <button type="button" onClick={() => void results.refetch()}>Retry</button></div>}
        <ul ref={listRef} id={listId} role="listbox" aria-label="Workspace results" aria-busy={pending}>
          {!list.length && <li className="palette-empty">{pending ? 'Looking for matches…' : 'No matches. Try another name or search category.'}</li>}
          {list.map((item, n) => {
            const Icon = icons[item.area];
            return <li key={item.key} id={`${listId}-${n}`} role="option" aria-selected={n === selected} className={n === selected ? 'on' : ''} onMouseEnter={() => setI(n)} onClick={() => go(item)}>
              <span className="palette-result-icon"><Icon size={17} aria-hidden="true" /></span>
              <span className="palette-result-copy"><span>{item.label}</span><small>{item.hint}</small></span>
              <ArrowUpRight className="palette-result-arrow" size={16} aria-hidden="true" />
            </li>;
          })}
        </ul>
        <div className="palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>Esc</kbd> close</span></div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
