import * as Dialog from '@radix-ui/react-dialog';
import { Search } from 'lucide-react';
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { titleCase } from '../lib/format';

export const Sev = ({ v }: { v: string }) => <span className={`badge sev-${v}`}>{v}</span>;
export const Status = ({ v }: { v: string }) => <span className={`badge st-${v}`}>{titleCase(v)}</span>;

export function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="modal" aria-describedby={undefined} style={wide ? { width: 'min(760px, 94vw)' } : undefined}>
          <Dialog.Title>{title}</Dialog.Title>
          <Dialog.Close className="close" aria-label="Close">×</Dialog.Close>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Drawer({ title, children, onClose }: { title: ReactNode; children: ReactNode; onClose: () => void }) {
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer" aria-describedby={undefined}>
          <span className="eyebrow">DETAILS</span>
          <Dialog.Close className="close" aria-label="Close details">×</Dialog.Close>
          <Dialog.Title>{title}</Dialog.Title>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Field({ label, hint, children, id }: { label: string; hint?: string; children: ReactNode; id?: string }) {
  return <div className="field"><label htmlFor={id}>{label}</label>{children}{hint && <span className="hint">{hint}</span>}</div>;
}

export function PageHead({ title, sub, children, eyebrow }: { title: string; sub?: string; children?: ReactNode; eyebrow?: string }) {
  return <div className="heading"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{sub && <p className="subtitle">{sub}</p>}</div><div className="actions">{children}</div></div>;
}

export function Pager({ page, limit, total, set }: { page: number; limit: number; total: number; set: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pager"><span>{total} total</span><button className="btn small" disabled={page <= 1} onClick={() => set(page - 1)}>Prev</button><span>{page} / {pages}</span><button className="btn small" disabled={page >= pages} onClick={() => set(page + 1)}>Next</button></div>
  );
}

/** A search icon that expands into a text input on click/focus, and collapses again when empty and blurred. */
export function SearchBox({ value, onChange, placeholder = 'Search…', label = 'Search' }: { value: string; onChange: (v: string) => void; placeholder?: string; label?: string }) {
  const [open, setOpen] = useState(!!value);
  const ref = useRef<HTMLInputElement>(null);
  function expand() {
    setOpen(true);
    requestAnimationFrame(() => ref.current?.focus());
  }
  function collapseIfEmpty() {
    if (!value) setOpen(false);
  }
  return (
    <div className={`search-box${open ? ' open' : ''}`}>
      <button type="button" className="search-box-icon" aria-label={label} aria-expanded={open} onClick={expand}><Search size={16} aria-hidden="true" /></button>
      <input
        ref={ref} type="search" value={value} placeholder={placeholder} aria-label={label}
        tabIndex={open ? 0 : -1}
        onFocus={expand}
        onChange={(e) => onChange(e.target.value)}
        onBlur={collapseIfEmpty}
        onKeyDown={(e) => { if (e.key === 'Escape') { onChange(''); ref.current?.blur(); } }}
      />
    </div>
  );
}

export const Empty = ({ children = 'Nothing here yet.' }: { children?: ReactNode }) => <div className="empty">{children}</div>;
export const Loading = () => <div className="empty" role="status">Loading…</div>;
export const ErrorBox = ({ error }: { error: unknown }) => <div className="error" role="alert">{error instanceof Error ? error.message : 'Something went wrong'}</div>;

type ToastFn = (msg: string, err?: boolean) => void;
const ToastCtx = createContext<ToastFn>(() => {});
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<{ id: number; msg: string; err: boolean }[]>([]);
  const push = useCallback<ToastFn>((msg, err = false) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, msg, err }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 4500);
  }, []);
  return <ToastCtx.Provider value={push}>{children}<div className="toast-wrap" aria-live="polite">{items.map((i) => <div key={i.id} className={`toast${i.err ? ' err' : ''}`}>{i.msg}</div>)}</div></ToastCtx.Provider>;
}
