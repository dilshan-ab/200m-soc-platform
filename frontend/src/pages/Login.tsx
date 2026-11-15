import * as Dialog from '@radix-ui/react-dialog';
import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowRight, Check, Moon, Sun, X } from 'lucide-react';
import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';
import { Loading } from '../components/ui';
import { CircuitLogo } from '../components/CircuitLogo';
import { LoginGlobe } from '../components/LoginGlobe';
import { ApiError, get } from '../lib/api';
import { WorkspaceIntro } from '../WorkspaceIntro';
import { useAuth } from '../lib/auth';

export default function Login() {
  const { me, loading, login } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [entered, setEntered] = useState(false);
  const cfg = useQuery({ queryKey: ['auth-config'], queryFn: () => get<{ auth_mode: 'dev' | 'oidc' }>('/api/auth/config'), retry: 3 });
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === 'dark');
  const [help, setHelp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const requested = new URLSearchParams(location.search).get('next') ?? (location.state as { from?: string } | null)?.from;
  const destination = requested && /^\/app(?:[/?#]|$)/.test(requested) ? requested : '/app';
  const ssoReturn = `/login?${new URLSearchParams({ entry: '1', next: destination })}`;
  if (loading) return <Loading />;
  if (me) {
    const showIntro = entered || busy || new URLSearchParams(location.search).get('entry') === '1';
    if (showIntro && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return <WorkspaceIntro onComplete={() => nav(destination, { replace: true })} />;
    }
    return <Navigate to={destination} replace />;
  }

  const toggle = () => {
    const next = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next; document.documentElement.style.colorScheme = next; setDark(!dark);
    try { localStorage.setItem('200m-theme', next); } catch { /* storage unavailable */ }
  };
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr('');
    try { await login(email, password, totp); setEntered(true); }
    catch (x) { setErr(x instanceof ApiError && x.status === 429 ? 'Too many attempts. Wait a minute and retry.' : 'Sign-in failed. Check your credentials and code.'); setBusy(false); }
  }
  const mode = cfg.data?.auth_mode;
  return (
    <div className="app">
      <main className="login neon-login">
        <section className="login-story">
          <div className="story-content">
            <div className="story-copy">
              <h1>Security<br />operations center</h1>
              <p>Investigate alerts, manage cases, and coordinate response.</p>
            </div>
            <div className="orbit" aria-hidden="true">
              <div className="orbit-ring" /><div className="orbit-ring second" /><LoginGlobe />
              <span className="orbit-chip one"><Activity size={16} />Detection</span>
              <span className="orbit-chip two"><Check size={16} />Response</span>
            </div>
          </div>
        </section>
        <section className="login-form">
          <div className="login-tools">
            <Button variant="ghost" aria-label={dark ? 'Use light theme' : 'Use dark theme'} onClick={toggle}>{dark ? <Sun size={18} /> : <Moon size={18} />}</Button>
          </div>
          <div className="login-card">
            <div className="login-symbol" role="img" aria-label="200M logo"><CircuitLogo className="login-logo" /></div>
            <h2>Sign in</h2>
            <p>Use your organization account to access the SOC.</p>
            {cfg.isError ? <div className="error" role="alert" style={{ marginTop: 24 }}>The service is unreachable. <button className="btn small" disabled={cfg.isFetching} onClick={() => void cfg.refetch()}>Try again</button></div>
              : mode === 'oidc' ? (
                <>
                  <Button asChild className="wide company-sso">
                    <a href={`/api/auth/oidc/login?return_to=${encodeURIComponent(ssoReturn)}`}>
                      Continue with company SSO <ArrowRight size={17} />
                    </a>
                  </Button>
                  <p className="login-note">Sign-in is handled by Keycloak with multi-factor authentication.</p>
                </>
              ) : mode === 'dev' ? (
                <>
                  <form onSubmit={submit}>
                    <label>Email<input id="em" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
                    <label>Password<input id="pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
                    <label>Authenticator code<input id="tp" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={totp} onChange={(e) => setTotp(e.target.value)} required /></label>
                    {err && <div className="error" role="alert" style={{ marginBottom: 14 }}>{err}</div>}
                    <Button className="wide" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'} <ArrowRight size={17} /></Button>
                  </form>
                  <p className="login-note">Local sign-in is for development only. Production uses company SSO.</p>
                </>
              ) : <p style={{ marginTop: 24 }}>Loading…</p>}
          </div>
          <div className="login-bottom"><button onClick={() => setHelp(true)}>Need help?</button></div>
        </section>
        <small className="login-brand-footer">200M · Security Operations Center</small>
      </main>
      <Dialog.Root open={help} onOpenChange={setHelp}>
        <Dialog.Portal>
          <Dialog.Overlay className="overlay" />
          <Dialog.Content className="modal">
            <Dialog.Close className="close" aria-label="Close dialog"><X /></Dialog.Close>
            <Dialog.Title>Getting started</Dialog.Title>
            <Dialog.Description>Use your company account. The first time you sign in you will be asked to set up an authenticator app. If you cannot sign in, your SOC administrator can reset your access.</Dialog.Description>
            <Button onClick={() => setHelp(false)}>Got it</Button>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
