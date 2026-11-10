import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { Brand, CircuitWord, Intro } from '../components/Logo';
import { useAuth } from '../lib/auth';

const FEATURES = [
  ['One queue for every alert', 'Wazuh, Suricata, Zeek, Osquery and Fail2ban events arrive through one normalised, de-duplicated stream.'],
  ['Cases that stay in sync', 'Triage to closure with templates, tasks, SLAs and TheHive as the system of record.'],
  ['Response with guardrails', 'Every action is approved, scoped, audited and reversible, with a kill switch.'],
  ['Every tool, linked once', 'Add Wazuh, TheHive, Cortex, MISP, Velociraptor, OpenVAS and more from one screen.'],
];

export default function Landing() {
  const { me } = useAuth();
  const [intro, setIntro] = useState(() => { try { return sessionStorage.getItem('intro-seen') !== '1'; } catch { return true; } });
  const done = () => { setIntro(false); try { sessionStorage.setItem('intro-seen', '1'); } catch { /* ignore */ } };
  if (me && !intro) return <Navigate to="/app" replace />;
  return (
    <div className="pub">
      {intro && <Intro onDone={done} />}
      <header className="pub-nav"><Brand /><Link className="btn primary" to={me ? '/app' : '/login'}>{me ? 'Open workspace' : 'Sign in'}</Link></header>
      <section className="pub-hero">
        <div className="pub-logo"><CircuitWord animated={!intro} /></div>
        <h1>Security Operations Center</h1>
        <p>A single workspace for the 200M SOC: monitor alerts, run cases, approve response actions and keep every integrated tool under control.</p>
        <Link className="btn primary lg" to="/login">Sign in to the SOC</Link>
        <div className="pub-features">{FEATURES.map(([t, d]) => <div className="pub-feature" key={t}><h3>{t}</h3><p>{d}</p></div>)}</div>
      </section>
      <footer className="pub-foot">200M · Security Operations Center · Access is monitored and audited</footer>
    </div>
  );
}
