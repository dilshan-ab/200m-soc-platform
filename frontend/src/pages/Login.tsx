import * as Dialog from '@radix-ui/react-dialog';
import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowRight, Check, Eye, EyeOff, Moon, Pause, Play, Sun, X } from 'lucide-react';
import { useRef, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';
import { Loading } from '../components/ui';
import { CircuitLogo } from '../components/CircuitLogo';
import { LoginRecovery } from '../components/LoginRecovery';
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
  const [paused, setPaused] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const helpButton = useRef<HTMLButtonElement>(null);
  const [help, setHelp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const authParams = new URLSearchParams(location.search);
  const authError = authParams.get('auth_error');
  const requested = authParams.get('next') ?? (location.state as { from?: string } | null)?.from;
  const destination = requested && /^\/app(?:[/?#]|$)/.test(requested) ? requested : '/app';
  const ssoReturn = `/login?${new URLSearchParams({ entry: '1', next: destination })}`;
  if (loading) return <Loading />;
  if (me && !authError) {
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
      <main className={`login neon-login${paused ? ' motion-paused' : ''}`}>
        <div className="login-signals" aria-hidden="true">
          <svg viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice" fill="none">
            <g className="login-signal-grid">
              <path d="M0 150H175L260 235H430M0 600H130L235 495H390M1200 190H1040L950 280H830M1200 660H1090L980 550H850M100 0V65L355 320V480M1110 0V90L1000 200M200 800V690L370 520M1120 800V735L930 545" />
            </g>
            <g className="login-signal-flow">
              <path d="M0 150H175L260 235H430" />
              <path d="M0 600H130L235 495H390" />
              <path d="M1200 190H1040L950 280H830" />
              <path d="M1200 660H1090L980 550H850" />
              <path d="M100 0V65L355 320V480" />
              <path d="M1120 800V735L930 545" />
            </g>
            <g className="login-signal-nodes">
              <circle cx="175" cy="150" r="4" /><circle cx="235" cy="495" r="4" />
              <circle cx="1040" cy="190" r="4" /><circle cx="980" cy="550" r="4" />
              <circle cx="355" cy="320" r="4" /><circle cx="930" cy="545" r="4" />
            </g>
          </svg>
        </div>
        <section className="login-story">
          <a className="brand" href="/" aria-label="200M home"><CircuitLogo className="login-logo" /></a>
          <div className="story-content">
            <div className="story-copy">
              <h1>Security<br />operations center</h1>
              <p>Investigate alerts, manage cases, and coordinate response.</p>
            </div>
            <div className="orbit" aria-hidden="true">
              <div className="login-radar"><span /><span /></div>
              <div className="orbit-ring" /><div className="orbit-ring second" /><LoginGlobe paused={paused} />
              <span className="orbit-chip one"><Activity size={16} />Detection</span>
              <span className="orbit-chip two"><Check size={16} />Response</span>
            </div>
          </div>
        </section>
        <section className="login-form">
          <div className="login-tools">
            <Button variant="ghost" className="login-motion-toggle" aria-label={paused ? 'Resume animation' : 'Pause animation'} aria-pressed={paused} title={paused ? 'Resume animation' : 'Pause animation'} onClick={() => setPaused((value) => !value)}>{paused ? <Play size={15} /> : <Pause size={15} />}<span>{paused ? 'Resume animation' : 'Pause animation'}</span></Button>
            <Button variant="ghost" aria-label={dark ? 'Use light theme' : 'Use dark theme'} onClick={toggle}>{dark ? <Sun size={18} /> : <Moon size={18} />}</Button>
          </div>
          <div className="login-card">
            <div className="login-symbol" role="img" aria-label="200M logo"><CircuitLogo className="login-logo" /></div>
            <h2>{authError === 'mfa_required' && me ? 'Verify your account' : 'Sign in'}</h2>
            <p>Use your organization account to access the SOC.</p>
            {authError && <LoginRecovery code={authError} reference={authParams.get('ref')} />}
            {cfg.isError ? <div className="error" role="alert" style={{ marginTop: 24 }}>The service is unreachable. <button className="btn small" disabled={cfg.isFetching} onClick={() => void cfg.refetch()}>Try again</button></div>
              : mode === 'oidc' ? (
                <>
                  <Button asChild className="wide company-sso">
                    <a href={authError === 'mfa_required' && me ? `/api/auth/oidc/step-up?return_to=${encodeURIComponent(destination)}` : `/api/auth/oidc/login?return_to=${encodeURIComponent(ssoReturn)}`}>
                      {authError === 'mfa_required' && me ? 'Verify with company SSO' : authError ? 'Try company SSO again' : 'Continue with company SSO'} <ArrowRight size={17} />
                    </a>
                  </Button>
                  {me && authError && <a className="button outline wide" href={destination}>Return to workspace</a>}
                  <p className="login-note">Sign-in is handled by Keycloak with multi-factor authentication.</p>
                </>
              ) : mode === 'dev' ? (
                <>
                  <form onSubmit={submit}>
                    <label>Email<input id="em" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
                    <div className="login-password-field"><label htmlFor="pw">Password</label><div className="login-password-control"><input id="pw" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /><button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword} onClick={() => setShowPassword((value) => !value)}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></div>
                    <label>Authenticator code<input id="tp" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={totp} onChange={(e) => setTotp(e.target.value)} required /></label>
                    {err && <div className="error" role="alert" style={{ marginBottom: 14 }}>{err}</div>}
                    <Button className="wide" type="submit" disabled={busy} aria-busy={busy}>{busy ? 'Signing in…' : 'Sign in'} <ArrowRight size={17} /></Button>
                  </form>
                  <p className="login-note">Local sign-in is for development only. Production uses company SSO.</p>
                </>
              ) : <p role="status" style={{ marginTop: 24 }}>Loading sign-in options…</p>}
          </div>
          <div className="login-bottom"><button ref={helpButton} onClick={() => setHelp(true)}>Need help?</button></div>
        </section>
        <small className="login-brand-footer">200M · Security Operations Center</small>
      </main>
      <Dialog.Root open={help} onOpenChange={setHelp}>
        <Dialog.Portal>
          <Dialog.Overlay className="overlay" />
          <Dialog.Content className="modal" onCloseAutoFocus={(event) => { event.preventDefault(); helpButton.current?.focus(); }}>
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
