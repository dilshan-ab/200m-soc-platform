import * as Dialog from '@radix-ui/react-dialog';
import { Eye, EyeOff, Search, X } from 'lucide-react';
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { titleCase } from '../lib/format';

export const Sev = ({ v }: { v: string }) => <span className={`badge sev-${v}`}>{v}</span>;
export const Status = ({ v }: { v: string }) => <span className={`badge st-${v}`}>{titleCase(v)}</span>;

export function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  const returnFocus = useRef(document.activeElement as HTMLElement | null);
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="modal" onCloseAutoFocus={(event) => { if (returnFocus.current?.isConnected) { event.preventDefault(); returnFocus.current.focus({ preventScroll: true }); } }} aria-describedby={undefined} style={wide ? { width: 'min(760px, 94vw)' } : undefined}>
          <Dialog.Title>{title}</Dialog.Title>
          <Dialog.Close className="close" aria-label="Close">×</Dialog.Close>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Drawer({ title, children, onClose }: { title: ReactNode; children: ReactNode; onClose: () => void }) {
  const returnFocus = useRef(document.activeElement as HTMLElement | null);
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer" onCloseAutoFocus={(event) => { if (returnFocus.current?.isConnected) { event.preventDefault(); returnFocus.current.focus({ preventScroll: true }); } }} aria-describedby={undefined}>
          <span className="eyebrow">DETAILS</span>
          <Dialog.Close className="close" aria-label="Close details">×</Dialog.Close>
          <Dialog.Title>{title}</Dialog.Title>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Password field with an eye button that shows or hides what is typed. */
export function PasswordInput({ id, value, onChange, autoComplete = 'new-password', maxLength, placeholder }: { id: string; value: string; onChange: (v: string) => void; autoComplete?: string; maxLength?: number; placeholder?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div className="password-input">
      <input id={id} type={show ? 'text' : 'password'} autoComplete={autoComplete} maxLength={maxLength} placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
      <button type="button" className="eye" aria-label={show ? 'Hide password' : 'Show password'} aria-pressed={show} title={show ? 'Hide password' : 'Show password'} onClick={() => setShow((v) => !v)}>
        {show ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
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

export function SearchBox({ value, onChange, placeholder = 'Search…', label = 'Search', id }: { value: string; onChange: (v: string) => void; placeholder?: string; label?: string; id?: string }) {
  const ref = useRef<HTMLInputElement>(null);
  function clear() {
    onChange('');
    ref.current?.focus();
  }
  return (
    <div className="search-box">
      <Search size={17} aria-hidden="true" />
      <input
        ref={ref} id={id} type="search" value={value} placeholder={placeholder} aria-label={label} maxLength={200}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && value) {
            e.preventDefault();
            e.stopPropagation();
            clear();
          }
        }}
      />
      {value && <button type="button" className="search-box-clear" aria-label={`Clear ${label.toLowerCase()}`} onClick={clear}><X size={16} aria-hidden="true" /></button>}
    </div>
  );
}

export const Empty = ({ children = 'Nothing here yet.', action, onAction }: { children?: ReactNode; action?: string; onAction?: () => void }) => <div className="empty"><p>{children}</p>{onAction && <button className="btn small" onClick={onAction}>{action ?? 'Clear filters'}</button>}</div>;
export const Loading = () => <div className="loading-state" role="status"><span className="loading-indicator" aria-hidden="true" />Loading…</div>;
export const ErrorBox = ({ error, onRetry, retrying = false }: { error: unknown; onRetry?: () => void; retrying?: boolean }) => <div className="error" role="alert"><span>{error instanceof Error ? error.message : 'Something went wrong'}</span>{onRetry && <button className="btn small" disabled={retrying} onClick={onRetry}>{retrying ? 'Retrying…' : 'Try again'}</button>}</div>;

type ToastAction = { label: string; run: () => void | Promise<void> };
type ToastFn = (msg: string, err?: boolean, action?: ToastAction) => void;
const ToastCtx = createContext<ToastFn>(() => {});
export const useToast = () => useContext(ToastCtx);
function ToastItem({ item, dismiss }: { item: { id: number; msg: string; err: boolean; action?: ToastAction }; dismiss: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState('');
  return <div className={`toast${item.err ? ' err' : ''}`}><span>{failure || item.msg}</span>
    {item.action && <button disabled={busy} onClick={async () => { setBusy(true); try { await item.action!.run(); dismiss(); } catch (e) { setFailure(e instanceof Error ? e.message : 'Could not undo the change'); setBusy(false); } }}>{busy ? 'Working…' : item.action.label}</button>}
    <button aria-label="Dismiss notification" onClick={dismiss}>×</button>
  </div>;
}
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<{ id: number; msg: string; err: boolean; action?: ToastAction }[]>([]);
  const push = useCallback<ToastFn>((msg, err = false, action) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, msg, err, action }]);
    // Undo notifications remain until used or dismissed so keyboard users have time.
    if (!action) setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 6000);
  }, []);
  return <ToastCtx.Provider value={push}>{children}<div className="toast-wrap" aria-live="polite">{items.map((i) => <ToastItem key={i.id} item={i} dismiss={() => setItems((x) => x.filter((v) => v.id !== i.id))} />)}</div></ToastCtx.Provider>;
}
