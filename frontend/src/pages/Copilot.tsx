import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, Brain, FileText, Lightbulb, MessageSquare, Shield, Zap } from 'lucide-react';
import { useState } from 'react';
import { Empty, ErrorBox, Loading, PageHead, Sev } from '../components/ui';
import { get, post } from '../lib/api';

type CopilotStatus = { enabled: boolean; provider: string; model: string };

export default function Copilot() {
  const status = useQuery({ queryKey: ['copilot-status'], queryFn: () => get<CopilotStatus>('/api/copilot/status') });
  const [tab, setTab] = useState<'analyze' | 'triage' | 'explain' | 'suggest' | 'summarize'>('analyze');

  if (status.isLoading) return <Loading />;
  if (status.error) return <ErrorBox error={status.error} />;

  const s = status.data!;
  if (!s.enabled) return (
    <>
      <PageHead title="AI Copilot" sub="AI-powered alert analysis, triage, and response suggestions." />
      <Empty>AI Copilot is not configured. Set SOC_LLM_PROVIDER and SOC_LLM_API_KEY environment variables.</Empty>
    </>
  );

  return (
    <>
      <PageHead title="AI Copilot" sub="AI-powered alert analysis, triage, and response suggestions." />
      <div className="kpi-row" style={{ marginBottom: 16 }}>
        <div className="kpi"><Bot size={18} style={{ color: 'var(--accent)' }} /><div><strong>{s.provider}</strong><small>LLM Provider</small></div></div>
        <div className="kpi"><Brain size={18} /><div><strong style={{ fontSize: 12 }}>{s.model}</strong><small>Model</small></div></div>
      </div>
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={tab === 'analyze' ? 'active' : ''} onClick={() => setTab('analyze')}>Deep Analysis</button>
        <button className={tab === 'triage' ? 'active' : ''} onClick={() => setTab('triage')}>Quick Triage</button>
        <button className={tab === 'explain' ? 'active' : ''} onClick={() => setTab('explain')}>Explain</button>
        <button className={tab === 'suggest' ? 'active' : ''} onClick={() => setTab('suggest')}>Response Actions</button>
        <button className={tab === 'summarize' ? 'active' : ''} onClick={() => setTab('summarize')}>Case Summary</button>
      </div>
      {tab === 'analyze' && <AnalyzePanel />}
      {tab === 'triage' && <TriagePanel />}
      {tab === 'explain' && <ExplainPanel />}
      {tab === 'suggest' && <SuggestPanel />}
      {tab === 'summarize' && <SummarizePanel />}
    </>
  );
}

function AlertIdForm({ label, icon: Icon, onSubmit, isPending }: { label: string; icon: typeof Brain; onSubmit: (id: string) => void; isPending: boolean }) {
  const [alertId, setAlertId] = useState('');
  return (
    <form className="row" style={{ gap: 8, marginBottom: 16 }} onSubmit={(e) => { e.preventDefault(); if (alertId.trim()) onSubmit(alertId.trim()); }}>
      <input type="text" placeholder="Alert ID" value={alertId} onChange={(e) => setAlertId(e.target.value)} style={{ flex: 1, maxWidth: 400 }} />
      <button className="btn primary" type="submit" disabled={isPending || !alertId.trim()}>
        <Icon size={16} /> {isPending ? 'Processing…' : label}
      </button>
    </form>
  );
}

function AnalyzePanel() {
  const analyze = useMutation({ mutationFn: (alertId: string) => post<{ analysis: string; model: string; generated_at: string }>('/api/copilot/analyze', { alert_id: alertId }) });
  return (
    <>
      <div className="card" style={{ padding: 16, marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
        <h4 style={{ margin: 0, marginBottom: 4 }}><Brain size={16} style={{ verticalAlign: -3 }} /> Deep Analysis</h4>
        <small style={{ color: 'var(--muted)' }}>Comprehensive AI analysis: threat assessment, MITRE mapping, investigation steps, and recommended actions.</small>
      </div>
      <AlertIdForm label="Analyze" icon={Brain} onSubmit={(id) => analyze.mutate(id)} isPending={analyze.isPending} />
      {analyze.error && <ErrorBox error={analyze.error} />}
      {analyze.data && <ResultCard title="Analysis Result" model={analyze.data.model} time={analyze.data.generated_at} content={analyze.data.analysis} />}
    </>
  );
}

function TriagePanel() {
  const triage = useMutation({ mutationFn: (alertId: string) => post<any>('/api/copilot/triage', { alert_id: alertId }) });
  return (
    <>
      <div className="card" style={{ padding: 16, marginBottom: 16, borderLeft: '3px solid var(--yellow)' }}>
        <h4 style={{ margin: 0, marginBottom: 4 }}><Zap size={16} style={{ verticalAlign: -3 }} /> Quick Triage</h4>
        <small style={{ color: 'var(--muted)' }}>Instant severity assessment, priority ranking, and verdict recommendation.</small>
      </div>
      <AlertIdForm label="Triage" icon={Zap} onSubmit={(id) => triage.mutate(id)} isPending={triage.isPending} />
      {triage.error && <ErrorBox error={triage.error} />}
      {triage.data && <TriageResult data={triage.data} />}
    </>
  );
}

function ExplainPanel() {
  const explain = useMutation({ mutationFn: (alertId: string) => post<{ explanation: string; model: string; generated_at: string }>('/api/copilot/explain', { alert_id: alertId }) });
  return (
    <>
      <div className="card" style={{ padding: 16, marginBottom: 16, borderLeft: '3px solid var(--blue, var(--accent))' }}>
        <h4 style={{ margin: 0, marginBottom: 4 }}><MessageSquare size={16} style={{ verticalAlign: -3 }} /> Plain Language Explanation</h4>
        <small style={{ color: 'var(--muted)' }}>Explain alerts in simple terms for junior analysts and stakeholders.</small>
      </div>
      <AlertIdForm label="Explain" icon={MessageSquare} onSubmit={(id) => explain.mutate(id)} isPending={explain.isPending} />
      {explain.error && <ErrorBox error={explain.error} />}
      {explain.data && <ResultCard title="Explanation" model={explain.data.model} time={explain.data.generated_at} content={explain.data.explanation} />}
    </>
  );
}

function SuggestPanel() {
  const suggest = useMutation({ mutationFn: (alertId: string) => post<any>('/api/copilot/suggest-response', { alert_id: alertId }) });
  return (
    <>
      <div className="card" style={{ padding: 16, marginBottom: 16, borderLeft: '3px solid var(--red)' }}>
        <h4 style={{ margin: 0, marginBottom: 4 }}><Shield size={16} style={{ verticalAlign: -3 }} /> Response Suggestions</h4>
        <small style={{ color: 'var(--muted)' }}>AI-recommended incident response actions with priority and automation assessment.</small>
      </div>
      <AlertIdForm label="Get Suggestions" icon={Shield} onSubmit={(id) => suggest.mutate(id)} isPending={suggest.isPending} />
      {suggest.error && <ErrorBox error={suggest.error} />}
      {suggest.data?.actions && <ActionsResult actions={suggest.data.actions} />}
    </>
  );
}

function SummarizePanel() {
  const [caseId, setCaseId] = useState('');
  const summarize = useMutation({ mutationFn: (id: string) => post<{ summary: string; model: string; generated_at: string }>('/api/copilot/summarize', { case_id: id }) });
  return (
    <>
      <div className="card" style={{ padding: 16, marginBottom: 16, borderLeft: '3px solid var(--green, var(--accent))' }}>
        <h4 style={{ margin: 0, marginBottom: 4 }}><FileText size={16} style={{ verticalAlign: -3 }} /> Case Summary</h4>
        <small style={{ color: 'var(--muted)' }}>Generate an executive summary of a case including key findings, impact, and next steps.</small>
      </div>
      <form className="row" style={{ gap: 8, marginBottom: 16 }} onSubmit={(e) => { e.preventDefault(); if (caseId.trim()) summarize.mutate(caseId.trim()); }}>
        <input type="text" placeholder="Case ID" value={caseId} onChange={(e) => setCaseId(e.target.value)} style={{ flex: 1, maxWidth: 400 }} />
        <button className="btn primary" type="submit" disabled={summarize.isPending || !caseId.trim()}>
          <FileText size={16} /> {summarize.isPending ? 'Summarizing…' : 'Summarize'}
        </button>
      </form>
      {summarize.error && <ErrorBox error={summarize.error} />}
      {summarize.data && <ResultCard title="Case Summary" model={summarize.data.model} time={summarize.data.generated_at} content={summarize.data.summary} />}
    </>
  );
}

function ResultCard({ title, model, time, content }: { title: string; model: string; time: string; content: string }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h4 style={{ margin: 0 }}><Lightbulb size={16} style={{ verticalAlign: -3, color: 'var(--accent)' }} /> {title}</h4>
        <small style={{ color: 'var(--muted)' }}>{model} · {new Date(time).toLocaleString()}</small>
      </div>
      <div className="markdown-body" style={{ whiteSpace: 'pre-wrap', lineHeight: 1.65, fontSize: 14 }}>{content}</div>
    </div>
  );
}

function TriageResult({ data }: { data: any }) {
  const VERDICT_COLORS: Record<string, string> = { true_positive: 'var(--red)', false_positive: 'var(--green)', needs_investigation: 'var(--yellow)' };
  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="row" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        {data.severity_suggestion && <Sev v={data.severity_suggestion} />}
        {data.verdict && <span className="badge" style={{ background: VERDICT_COLORS[data.verdict] ?? 'var(--muted)', color: '#fff' }}>{data.verdict.replace(/_/g, ' ')}</span>}
        {data.confidence != null && <span className="badge">confidence: {(data.confidence * 100).toFixed(0)}%</span>}
        {data.priority && <span className="badge">P{data.priority}</span>}
        {data.recommended_status && <span className="badge">{data.recommended_status}</span>}
      </div>
      {data.summary && <p style={{ margin: '8px 0' }}>{data.summary}</p>}
      {data.reasoning && <p style={{ color: 'var(--muted)', fontSize: 13, margin: 0 }}>{data.reasoning}</p>}
      <small style={{ color: 'var(--muted)' }}>{data.generated_at && new Date(data.generated_at).toLocaleString()}</small>
    </div>
  );
}

function ActionsResult({ actions }: { actions: any[] }) {
  const PRIORITY_COLORS: Record<string, string> = { immediate: 'var(--red)', urgent: 'var(--yellow)', standard: 'var(--blue, var(--accent))' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {actions.map((a, i) => (
        <div key={i} className="card" style={{ padding: 12, borderLeft: `3px solid ${PRIORITY_COLORS[a.priority] ?? 'var(--border)'}` }}>
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>{a.action?.replace(/_/g, ' ')}</strong>
            <div className="row" style={{ gap: 6 }}>
              <span className="badge" style={{ background: PRIORITY_COLORS[a.priority] ?? 'var(--muted)', color: '#fff' }}>{a.priority}</span>
              {a.automated && <span className="badge" style={{ background: 'var(--green)', color: '#fff' }}>automatable</span>}
            </div>
          </div>
          {a.target && <div style={{ fontSize: 13 }} className="mono">{a.target}</div>}
          {a.reason && <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}>{a.reason}</div>}
        </div>
      ))}
    </div>
  );
}
