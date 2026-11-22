import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Shell } from './components/Shell';
import { Loading } from './components/ui';
import { useAuth } from './lib/auth';
import Login from './pages/Login';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Cases = lazy(() => import('./pages/Cases'));
const Response = lazy(() => import('./pages/Response'));
const Approvals = lazy(() => import('./pages/Approvals'));
const Servers = lazy(() => import('./pages/Servers'));
const Assets = lazy(() => import('./pages/Assets'));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'));
const Compliance = lazy(() => import('./pages/Compliance'));
const Intel = lazy(() => import('./pages/Intel'));
const Runbooks = lazy(() => import('./pages/Runbooks'));
const Reports = lazy(() => import('./pages/Reports'));
const Integrations = lazy(() => import('./pages/Integrations'));
const Automation = lazy(() => import('./pages/Automation'));
const ThreatMap = lazy(() => import('./pages/ThreatMap'));
const MitreAttack = lazy(() => import('./pages/MitreAttack'));
const AnalystPerformance = lazy(() => import('./pages/AnalystPerformance'));
const SOARMetrics = lazy(() => import('./pages/SOARMetrics'));
const ThreatHunting = lazy(() => import('./pages/ThreatHunting'));
const SigmaRules = lazy(() => import('./pages/SigmaRules'));
const Playbooks = lazy(() => import('./pages/Playbooks'));
const Correlation = lazy(() => import('./pages/Correlation'));
const Enrichment = lazy(() => import('./pages/Enrichment'));
const UEBAPage = lazy(() => import('./pages/UEBA'));
const CopilotPage = lazy(() => import('./pages/Copilot'));
const SimulationPage = lazy(() => import('./pages/Simulation'));
const TriageQueue = lazy(() => import('./pages/TriageQueue'));
const Notebooks = lazy(() => import('./pages/Notebooks'));
const IntegrationHealth = lazy(() => import('./pages/IntegrationHealth'));
const ThreatIntelSharing = lazy(() => import('./pages/ThreatIntelSharing'));
const ShiftHandoff = lazy(() => import('./pages/ShiftHandoff'));
const WarRoom = lazy(() => import('./pages/WarRoom'));
const Clients = lazy(() => import('./pages/Clients'));
const LogSearch = lazy(() => import('./pages/LogSearch'));
const Xdr = lazy(() => import('./pages/DetectionWorkspaces').then(({ Xdr }) => ({ default: Xdr })));
const RiskAnalytics = lazy(() => import('./pages/DetectionWorkspaces').then(({ RiskAnalytics }) => ({ default: RiskAnalytics })));
const Admin = lazy(() => import('./pages/Admin'));

function Guard({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <Loading />;
  if (!me) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  return <>{children}</>;
}

function Need({ cap, children }: { cap: string; children: ReactNode }) {
  const { can } = useAuth();
  return can(cap) ? <>{children}</> : <div className="error" role="alert">You do not have permission to view this page.</div>;
}

export default function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
        <Route path="/app" element={<Guard><Shell /></Guard>}>
          <Route index element={<Dashboard />} />
          <Route path="alerts" element={<Need cap="alerts.read"><Alerts /></Need>} />
          <Route path="siem" element={<Need cap="alerts.read"><Alerts workspace="siem" /></Need>} />
          <Route path="hunting" element={<Need cap="hunts.read"><ThreatHunting /></Need>} />
          <Route path="edr" element={<Need cap="assets.read"><Assets endpoint /></Need>} />
          <Route path="xdr" element={<Need cap="alerts.read"><Xdr /></Need>} />
          <Route path="soar" element={<Need cap="automation.read"><Automation soar /></Need>} />
          <Route path="risk" element={<Need cap="vulns.read"><RiskAnalytics /></Need>} />
          <Route path="cases" element={<Need cap="cases.read"><Cases /></Need>} />
          <Route path="response" element={<Need cap="response.read"><Response /></Need>} />
          <Route path="approvals" element={<Need cap="response.approve"><Approvals /></Need>} />
          <Route path="servers" element={<Need cap="servers.read"><Servers /></Need>} />
          <Route path="assets" element={<Need cap="assets.read"><Assets /></Need>} />
          <Route path="vulnerabilities" element={<Need cap="vulns.read"><Vulnerabilities /></Need>} />
          <Route path="compliance" element={<Need cap="compliance.read"><Compliance /></Need>} />
          <Route path="intel" element={<Need cap="intel.read"><Intel /></Need>} />
          <Route path="runbooks" element={<Need cap="runbooks.read"><Runbooks /></Need>} />
          <Route path="reports" element={<Need cap="reports.read"><Reports /></Need>} />
          <Route path="analysts" element={<Need cap="metrics.read"><AnalystPerformance /></Need>} />
          <Route path="soar-metrics" element={<Need cap="metrics.read"><SOARMetrics /></Need>} />
          <Route path="integrations" element={<Need cap="integrations.read"><Integrations /></Need>} />
          <Route path="automation" element={<Need cap="automation.read"><Automation /></Need>} />
          <Route path="threat-map" element={<Need cap="alerts.read"><ThreatMap /></Need>} />
          <Route path="mitre" element={<Need cap="alerts.read"><MitreAttack /></Need>} />
          <Route path="sigma" element={<Need cap="detections.read"><SigmaRules /></Need>} />
          <Route path="playbooks" element={<Need cap="playbooks.read"><Playbooks /></Need>} />
          <Route path="correlation" element={<Need cap="incidents.read"><Correlation /></Need>} />
          <Route path="enrichment" element={<Need cap="intel.read"><Enrichment /></Need>} />
          <Route path="ueba" element={<Need cap="ueba.read"><UEBAPage /></Need>} />
          <Route path="copilot" element={<Need cap="copilot.read"><CopilotPage /></Need>} />
          <Route path="simulation" element={<Need cap="simulation.read"><SimulationPage /></Need>} />
          <Route path="triage" element={<Need cap="alerts.triage"><TriageQueue /></Need>} />
          <Route path="notebooks" element={<Need cap="notebooks.read"><Notebooks /></Need>} />
          <Route path="integration-health" element={<Need cap="integrations.read"><IntegrationHealth /></Need>} />
          <Route path="threat-intel-sharing" element={<Need cap="threat_intel.read"><ThreatIntelSharing /></Need>} />
          <Route path="handoff" element={<Need cap="handoff.read"><ShiftHandoff /></Need>} />
          <Route path="warroom" element={<Need cap="warroom.read"><WarRoom /></Need>} />
          <Route path="clients" element={<Need cap="clients.read"><Clients /></Need>} />
          <Route path="logs" element={<Need cap="logs.read"><LogSearch /></Need>} />
          <Route path="admin" element={<Need cap="admin.settings"><Admin /></Need>} />
          <Route path="*" element={<Navigate to="/app" replace />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}
