import * as Dialog from '@radix-ui/react-dialog';
import { useEffect, useMemo, useRef, useState } from 'react';


export type PaletteItem = { label: string; hint: string; run: () => void };

/** Ctrl/⌘+K launcher: jump to any page, run quick actions, or search alerts. */
export function CommandPalette({ items, onClose, onSearch }: { items: PaletteItem[]; onClose: () => void; onSearch?: (q: string) => void }) {
  const [q, setQ] = useState('');
  const [i, setI] = useState(0);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { ref.current?.focus(); }, []);
  const list = useMemo(() => {
    const t = q.trim().toLowerCase();
    const hits = items.filter((x) => !t || x.label.toLowerCase().includes(t) || x.hint.toLowerCase().includes(t));
    return onSearch && t.length >= 2 ? [...hits, { label: `Search alerts for “${q.trim()}”`, hint: 'Search', run: () => onSearch(q.trim()) }] : hits;
  }, [q, items, onSearch]);
  useEffect(() => setI(0), [q]);
  const go = (x?: PaletteItem) => { if (!x) return; onClose(); x.run(); };
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="palette-backdrop" />
        <Dialog.Content className="palette" aria-describedby={undefined}>
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
        <input ref={ref} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to a page or search alerts…" aria-label="Command"
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setI((n) => Math.max(0, Math.min(n + 1, list.length - 1))); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setI((n) => Math.max(n - 1, 0)); }
            else if (e.key === 'Enter') { e.preventDefault(); go(list[i]); }
          }} />
        <ul role="listbox">
          {list.length === 0 && <li className="palette-empty">No matches</li>}
          {list.map((x, n) => (
            <li key={x.label} role="option" aria-selected={n === i} className={n === i ? 'on' : ''} onMouseEnter={() => setI(n)} onClick={() => go(x)}>
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
