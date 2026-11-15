import * as Dialog from '@radix-ui/react-dialog';
import { useEffect, useId, useMemo, useRef, useState } from 'react';


export type PaletteItem = { label: string; hint: string; run: () => void };

/** Ctrl/⌘+K launcher: jump to any page, run quick actions, or search alerts. */
export function CommandPalette({ items, onClose, onSearch }: { items: PaletteItem[]; onClose: () => void; onSearch?: (q: string) => void }) {
  const [q, setQ] = useState('');
  const [i, setI] = useState(0);
  const ref = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const listId = useId();
  useEffect(() => { ref.current?.focus(); }, []);
  const list = useMemo(() => {
    const t = q.trim().toLowerCase();
    const hits = items.filter((x) => !t || x.label.toLowerCase().includes(t) || x.hint.toLowerCase().includes(t));
    return onSearch && t.length >= 2 ? [...hits, { label: `Search alerts for “${q.trim()}”`, hint: 'Search', run: () => onSearch(q.trim()) }] : hits;
  }, [q, items, onSearch]);
  useEffect(() => setI(0), [q]);
  useEffect(() => { listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' }); }, [i]);
  const selected = Math.min(i, Math.max(0, list.length - 1));
  const go = (x?: PaletteItem) => { if (!x) return; onClose(); x.run(); };
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="palette-backdrop" />
        <Dialog.Content className="palette" aria-describedby={undefined}>
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
        <input ref={ref} value={q} onChange={(e) => setQ(e.target.value)} placeholder={onSearch ? 'Jump to a page or search alerts…' : 'Jump to a page or action…'} aria-label="Command"
          role="combobox" aria-expanded="true" aria-autocomplete="list" aria-controls={listId}
          aria-activedescendant={list.length ? `${listId}-${selected}` : undefined} autoComplete="off" maxLength={200}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setI((n) => Math.max(0, Math.min(n + 1, list.length - 1))); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setI((n) => Math.max(n - 1, 0)); }
            else if (e.key === 'Enter' && !e.nativeEvent.isComposing) { e.preventDefault(); go(list[selected]); }
          }} />
        <ul ref={listRef} id={listId} role="listbox" aria-label="Pages and actions">
          {list.length === 0 && <li className="palette-empty">No matches</li>}
          {list.map((x, n) => (
            <li key={x.label} id={`${listId}-${n}`} role="option" aria-selected={n === selected} className={n === selected ? 'on' : ''} onMouseEnter={() => setI(n)} onClick={() => go(x)}>
              <span>{x.label}</span><small>{x.hint}</small>
            </li>
          ))}
        </ul>
        <div className="palette-foot"><span>↑↓ move</span><span>↵ open</span><span>esc close</span></div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
