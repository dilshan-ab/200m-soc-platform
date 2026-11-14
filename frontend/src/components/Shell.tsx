import * as Dialog from '@radix-ui/react-dialog';
import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, Bell, BookMarked, Bot, Check, ChevronRight, Crosshair, FileCode2, FileText, Flame, GitMerge, Globe, HeartPulse, MessagesSquare, Network, Radar, Layers, LayoutDashboard, LogOut, Menu, Moon, Play, Plug, Repeat2, Search, Server, Settings, Share2, Shield, Sun, Target, Workflow, X, Zap, BookOpen, CheckCircle2, Cpu, Gauge, type LucideIcon } from 'lucide-react'; // Building2 removed with the Clients & MSSP nav entry below — re-add it when un-commenting
import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';
import { firstName } from '../lib/format';
import { useLive } from '../lib/live';
import { Button } from './Button';
import { CommandPalette } from './CommandPalette';
import { CircuitLogo } from './CircuitLogo';

type Item = { to: string; label: string; icon: LucideIcon; cap?: string };
const SECURITY_TOOLS: Item[] = [
  { to: '/app/siem', label: 'SIEM', icon: Server, cap: 'alerts.read' },
  { to: '/app/edr', label: 'EDR', icon: Cpu, cap: 'assets.read' },
  { to: '/app/xdr', label: 'XDR', icon: Network, cap: 'alerts.read' },
  { to: '/app/soar', label: 'SOAR', icon: Zap, cap: 'automation.read' },
];
const NAV: { group: string; items: Item[] }[] = [
  { group: 'OPERATIONS', items: [
    { to: '/app', label: 'Home', icon: LayoutDashboard },
    { to: '/app/intel', label: 'Threat Intelligence', icon: Globe, cap: 'intel.read' },
    { to: '/app/threat-intel-sharing', label: 'Intel Sharing (STIX/TAXII)', icon: Share2, cap: 'threat_intel.read' },
    { to: '/app/enrichment', label: 'Enrichment', icon: Search, cap: 'intel.read' },
    { to: '/app/ueba', label: 'Behavior Analytics', icon: Activity, cap: 'ueba.read' },
    { to: '/app/copilot', label: 'AI Copilot', icon: Bot, cap: 'copilot.read' },
    { to: '/app/alerts', label: 'Alerts', icon: Bell, cap: 'alerts.read' },
    { to: '/app/triage', label: 'Triage Queue', icon: Flame, cap: 'alerts.triage' },
    { to: '/app/correlation', label: 'Correlation', icon: GitMerge, cap: 'incidents.read' },
    { to: '/app/cases', label: 'Cases', icon: Layers, cap: 'cases.read' },
    { to: '/app/response', label: 'Incident Response', icon: Workflow, cap: 'response.read' },
    { to: '/app/approvals', label: 'Approvals', icon: CheckCircle2, cap: 'response.approve' },
    { to: '/app/playbooks', label: 'Playbooks', icon: Play, cap: 'playbooks.read' },
    { to: '/app/notebooks', label: 'Investigation Notebooks', icon: BookMarked, cap: 'notebooks.read' },
    { to: '/app/warroom', label: 'War Room', icon: MessagesSquare, cap: 'warroom.read' },
    { to: '/app/handoff', label: 'Shift Handoff', icon: Repeat2, cap: 'handoff.read' },
  ] },
  { group: 'SECURITY POSTURE', items: [
    { to: '/app/servers', label: 'Servers', icon: Cpu, cap: 'servers.read' },
    { to: '/app/assets', label: 'Assets', icon: Server, cap: 'assets.read' },
    { to: '/app/vulnerabilities', label: 'Vulnerability Management', icon: AlertTriangle, cap: 'vulns.read' },
    { to: '/app/risk', label: 'Risk Analytics', icon: Activity, cap: 'vulns.read' },
    { to: '/app/hunting', label: 'Threat Hunting', icon: Radar, cap: 'hunts.read' },
    { to: '/app/compliance', label: 'Compliance', icon: Shield, cap: 'compliance.read' },
    { to: '/app/threat-map', label: 'Threat map', icon: Globe, cap: 'alerts.read' },
    { to: '/app/mitre', label: 'ATT&CK mapping', icon: Crosshair, cap: 'alerts.read' },
    { to: '/app/sigma', label: 'Detection rules', icon: FileCode2, cap: 'detections.read' },
    { to: '/app/simulation', label: 'Attack Simulation', icon: Target, cap: 'simulation.read' },
  ] },
  { group: 'INSIGHTS', items: [
    { to: '/app/analysts', label: 'Analyst Performance', icon: Gauge, cap: 'metrics.read' },
    { to: '/app/runbooks', label: 'Runbooks', icon: BookOpen, cap: 'runbooks.read' },
    { to: '/app/reports', label: 'Reports', icon: FileText, cap: 'reports.read' },
  ] },
  { group: 'WORKSPACE', items: [
    { to: '/app/integrations', label: 'Integrations', icon: Plug, cap: 'integrations.read' },
    { to: '/app/integration-health', label: 'Integration Health', icon: HeartPulse, cap: 'integrations.read' },
    // Hidden until this moves to the personal repo — uncomment (and re-add `Building2` to the lucide-react import above) to restore.
    // { to: '/app/clients', label: 'Clients & MSSP', icon: Building2, cap: 'clients.read' },
    { to: '/app/admin', label: 'Settings', icon: Settings, cap: 'admin.settings' },
  ] },
];
const NAV_ITEMS = [...NAV.flatMap((group) => group.items), ...SECURITY_TOOLS];
const TITLES = Object.fromEntries(NAV_ITEMS.map((item) => [item.to, item.label]));
const isToolRoute = (path: string) => SECURITY_TOOLS.some((item) => item.to === path.replace(/\/$/, ''));
const initials = (n: string) => n.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join('');
const ROLE_LABEL: Record<string, string> = { superadmin: 'Super admin', admin: 'Administrator', l2: 'L2 / Incident response', l1: 'L1 analyst', viewer: 'Viewer' };

export function Shell() {
  const { me, can, logout } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const live = useLive(true);
  const [toolsOpen, setToolsOpen] = useState(() => isToolRoute(loc.pathname));
  const visibleTools = SECURITY_TOOLS.filter((item) => !item.cap || can(item.cap));
  const [mobile, setMobile] = useState(false);
  const [account, setAccount] = useState(false);
  const [palette, setPalette] = useState(false);
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === 'dark');
  const authConfig = useQuery({ queryKey: ['auth-config'], queryFn: () => get<{ auth_mode: string; account_url: string | null }>('/api/auth/config') });
  const approvals = useQuery({ queryKey: ['approvals'], queryFn: () => get('/api/approvals'), enabled: can('response.approve'), refetchInterval: 15000 });
  const pending = (approvals.data?.actions?.length ?? 0) + (approvals.data?.changes?.length ?? 0);
  const alertStats = useQuery({ queryKey: ['alert-stats'], queryFn: () => get('/api/alerts/stats'), enabled: can('alerts.read'), refetchInterval: 15000 });
  const newAlerts = Object.values((alertStats.data ?? {}) as Record<string, Record<string, number>>).reduce((n, st) => n + (st.new ?? 0), 0);

  useEffect(() => {
    setMobile(false);
    if (isToolRoute(loc.pathname)) setToolsOpen(true);
    window.scrollTo(0, 0);
  }, [loc.pathname]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (!e.repeat && !account && (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); } };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [account]);
  const toggleTheme = () => {
    const next = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next; document.documentElement.style.colorScheme = next; setDark(!dark);
    try { localStorage.setItem('200m-theme', next); } catch { /* storage unavailable */ }
  };
  const title = TITLES[loc.pathname.replace(/\/$/, '')] ?? 'Overview';
  const name = me?.name || me?.email || '';
  const signOut = async () => {
    await logout();
    nav('/');
  };

  return (
    <>
      <a className="skip-workspace" href="#workspace-main">Skip to content</a>
      <aside className={'sidebar ' + (mobile ? 'open' : '')}>
        <Link to="/app" className="brand" aria-label="200M home"><CircuitLogo className="workspace-brand-logo" strokeWidth={7} /><span>SOC</span></Link>
        <div className="workspace"><span className="workspace-avatar"><Shield size={16} aria-hidden="true" /></span><div>Security operations<small>200M workspace</small></div></div>
        <nav id="workspace-navigation" aria-label="Main">
          {NAV.map((g) => {
            const items = g.items.filter((i) => !i.cap || can(i.cap));
            return items.length ? (
              <div key={g.group}>
                <div className="nav-label">{g.group}</div>
                {items.map((i) => (
                  <NavLink key={i.to} to={i.to} end={i.to === '/app'} className={({ isActive }) => (isActive ? 'active' : '')}>
                    <i.icon size={17} />{i.label}
                    {i.to === '/app/alerts' && newAlerts > 0 && <span className="nav-count">{newAlerts}</span>}
                    {i.to === '/app/approvals' && pending > 0 && <span className="nav-count hot">{pending}</span>}
                  </NavLink>
                ))}
                {g.group === 'OPERATIONS' && visibleTools.length > 0 && (
                  <div className="sidebar-tools">
                    <button type="button" className="sidebar-tools-toggle" aria-expanded={toolsOpen}
                      aria-controls="sidebar-security-tools" onClick={() => setToolsOpen((open) => !open)}>
                      <Shield size={17} aria-hidden="true" /><span>Security Tools</span>
                      <ChevronRight size={15} aria-hidden="true" />
                    </button>
                    <div id="sidebar-security-tools" className="sidebar-tools-links" hidden={!toolsOpen}>
                      {visibleTools.map((item) => (
                        <NavLink key={item.to} to={item.to}><item.icon size={17} aria-hidden="true" />{item.label}</NavLink>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : null;
          })}
        </nav>
        {can('alerts.read') && <div className={`soc-sidebar-health ${live ? 'online' : 'offline'}`}>
          <Activity size={15} aria-hidden="true" /><span>{live ? 'SOC stream online' : 'SOC stream offline'}</span>
        </div>}
        <button className="user" onClick={() => setAccount(true)}>
          <span className="avatar">{initials(name)}</span><span>{firstName(me?.name) || me?.email}<small>{ROLE_LABEL[me?.role ?? ''] ?? me?.role}</small></span><ChevronRight size={16} />
        </button>
      </aside>
      {mobile && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMobile(false)} />}
      <div className="main-shell">
        <header>
          <div className="crumb">
            <Button variant="ghost" className="mobile-menu" aria-label="Open navigation" aria-expanded={mobile} aria-controls="workspace-navigation" onClick={() => setMobile(true)}><Menu size={20} /></Button>
            <span>Workspace</span><ChevronRight size={14} /><strong>{title}</strong>
          </div>
          <div className="header-actions">
            <Button variant="ghost" aria-label="Search workspace (Ctrl+K)" onClick={() => setPalette(true)}><Search size={18} aria-hidden="true" /></Button>
            <span className={'demo-pill' + (live ? '' : ' off')}><Activity size={11} style={{ verticalAlign: -1, marginRight: 5 }} />{live ? 'Live' : 'Offline'}</span>
            <Button variant="ghost" aria-label={dark ? 'Use light theme' : 'Use dark theme'} onClick={toggleTheme}>{dark ? <Sun size={18} /> : <Moon size={18} />}</Button>
            {can('response.approve') && <Button variant="ghost" aria-label={`Approvals${pending ? ` (${pending} pending)` : ''}`} onClick={() => nav('/app/approvals')} className="bell"><Bell size={18} />{pending > 0 && <i />}</Button>}
            <button type="button" className="avatar workspace-account" aria-label="Open account menu" onClick={() => setAccount(true)}>{initials(name)}</button>
          </div>
        </header>
        <main id="workspace-main" tabIndex={-1} className="content" key={loc.pathname}><Outlet context={{ dark, live }} /></main>
      </div>
      {palette && (
        <CommandPalette
          onClose={() => setPalette(false)}
          onSearch={can('alerts.read') ? (t) => nav(`/app/alerts?q=${encodeURIComponent(t)}`) : undefined}
          items={[
            ...NAV_ITEMS.filter((i) => !i.cap || can(i.cap)).map((i) => ({ label: i.label, hint: 'Go to page', run: () => nav(i.to) })),
            { label: dark ? 'Switch to light theme' : 'Switch to dark theme', hint: 'Action', run: toggleTheme },
            { label: 'Sign out', hint: 'Action', run: () => void signOut() },
          ]}
        />
      )}
      <Dialog.Root open={account} onOpenChange={setAccount}>
        <Dialog.Portal>
          <Dialog.Overlay className="overlay" />
          <Dialog.Content className="modal">
            <Dialog.Close className="close" aria-label="Close"><X /></Dialog.Close>
            <Dialog.Title>Your workspace</Dialog.Title>
            <Dialog.Description>{me?.name} · {me?.email}</Dialog.Description>
            <dl className="kv">
              <dt>Role</dt><dd>{ROLE_LABEL[me?.role ?? ''] ?? me?.role}</dd>
              <dt>Sign-in</dt><dd>{me?.auth_mode === 'oidc' ? 'Company SSO (Keycloak, MFA)' : 'Local development account'}</dd>
              <dt>Client scope</dt><dd>{me?.all_clients ? 'All clients' : `${me?.client_ids?.length ?? 0} client(s)`}</dd>
              <dt>Recent verification</dt><dd>{me?.step_up_until && new Date(me.step_up_until) > new Date() ? <><Check size={13} style={{ verticalAlign: -2 }} /> active</> : 'not active'}</dd>
            </dl>
            <p className="muted">Access is monitored and audited · Asia/Colombo</p>
            {authConfig.data?.account_url && (
              <a className="button outline wide" href={authConfig.data.account_url} target="_blank" rel="noreferrer" style={{ marginBottom: 10 }}>
                <Settings size={16} /> Edit name, email or password
              </a>
            )}
            <Button className="wide" onClick={() => void signOut()}><LogOut size={16} />Sign out</Button>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}

