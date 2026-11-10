import { useQueryClient } from '@tanstack/react-query';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ApiError, get, onStepUp, onUnauth, post, setCsrf, type Me } from './api';
import { Modal } from '../components/ui';

type Ctx = { me: Me | null; loading: boolean; can: (cap: string) => boolean; login: (email: string, password: string, totp: string) => Promise<void>; logout: () => Promise<void>; refresh: () => Promise<void> };
const AuthCtx = createContext<Ctx>(null as unknown as Ctx);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [stepUp, setStepUp] = useState<null | ((ok: boolean) => void)>(null);

  const apply = useCallback((m: Me | null) => { setMe(m); setCsrf(m?.csrf_token ?? null); }, []);
  const refresh = useCallback(async () => {
    try { apply(await get<Me>('/api/auth/me')); } catch { apply(null); } finally { setLoading(false); }
  }, [apply]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    onUnauth(() => { apply(null); qc.clear(); });
    onStepUp(() => new Promise<boolean>((resolve) => setStepUp(() => resolve)));
    return () => { onUnauth(null); onStepUp(null); };
  }, [apply, qc]);

  const login = useCallback(async (email: string, password: string, totp: string) => {
    apply(await post<Me>('/api/auth/login', { email, password, totp }));
  }, [apply]);
  const logout = useCallback(async () => { try { await post('/api/auth/logout'); } finally { apply(null); qc.clear(); } }, [apply, qc]);
  const can = useCallback((cap: string) => !!me?.capabilities.includes(cap), [me]);
  const value = useMemo(() => ({ me, loading, can, login, logout, refresh }), [me, loading, can, login, logout, refresh]);

  return (
    <AuthCtx.Provider value={value}>
      {children}
      {stepUp && <StepUpModal mode={me?.auth_mode ?? 'dev'} done={(ok) => { stepUp(ok); setStepUp(null); if (ok) void refresh(); }} />}
    </AuthCtx.Provider>
  );
}

function StepUpModal({ mode, done }: { mode: 'dev' | 'oidc'; done: (ok: boolean) => void }) {
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { ref.current?.focus(); }, []);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr('');
    try { await post('/api/auth/step-up', { password, totp }); done(true); }
    catch (x) { setErr(x instanceof ApiError ? x.message : 'Verification failed'); setBusy(false); }
  }
  return (
    <Modal title="Confirm it's you" onClose={() => done(false)}>
      <p className="notice">This action needs recent multi-factor verification.</p>
      {mode === 'oidc' ? (
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => { window.location.href = `/api/auth/oidc/step-up?return_to=${encodeURIComponent(window.location.pathname)}`; }}>Verify with identity provider</button>
          <button className="btn" onClick={() => done(false)}>Cancel</button>
        </div>
      ) : (
        <form onSubmit={submit} style={{ marginTop: 14 }}>
          <div className="field"><label htmlFor="su-pw">Password</label><input id="su-pw" ref={ref} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></div>
          <div className="field"><label htmlFor="su-totp">Authenticator code</label><input id="su-totp" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={totp} onChange={(e) => setTotp(e.target.value)} required /></div>
          {err && <div className="error" role="alert">{err}</div>}
          <div className="row" style={{ marginTop: 12 }}><button className="btn primary" disabled={busy}>Verify</button><button type="button" className="btn" onClick={() => done(false)}>Cancel</button></div>
        </form>
      )}
    </Modal>
  );
}
