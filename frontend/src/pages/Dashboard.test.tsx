import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useLive } from '../lib/live';
import Dashboard from './Dashboard';

vi.mock('../lib/api', () => ({ get: vi.fn() }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));
vi.mock('../Trend', () => ({
  default: ({ onInspect }: { onInspect: (point: { since: string; until: string }) => void }) =>
    <button onClick={() => onInspect({ since: '2026-11-27T10:00:00Z', until: '2026-11-27T10:59:59Z' })}>Inspect bucket</button>,
}));

class TestEventSource {
  static current: TestEventSource;
  onmessage?: (event: { data: string }) => void;

  constructor() { TestEventSource.current = this; }
  close() {}
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', () => ({ matches: true, addEventListener: () => {}, removeEventListener: () => {} }));
  vi.stubGlobal('EventSource', TestEventSource);
});
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); });

function DashboardOutlet() {
  const live = useLive(true);
  return <Outlet context={{ dark: true, live }} />;
}

function renderDashboard(caps: string[]) {
  vi.mocked(useAuth).mockReturnValue({
    me: { id: 'analyst', role: 'l2', name: 'Analyst' },
    can: (cap: string) => caps.includes(cap),
  } as ReturnType<typeof useAuth>);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>
    <MemoryRouter initialEntries={['/app']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route element={<DashboardOutlet />}>
          <Route path="/app" element={<Dashboard />} />
          <Route path="/app/alerts" element={<AlertListLocation />} />
        </Route>
      </Routes>
    </MemoryRouter>
  </QueryClientProvider>);
}

function AlertListLocation() {
  const { search } = useLocation();
  return <div>{search}</div>;
}

const activeCases = { items: [{ id: 'a', number: '1', title: 'Scoped investigation', severity: 'high', status: 'open', updated_at: '2026-11-27' }] };

it('renders and refreshes active cases when alert summary fails', async () => {
  vi.mocked(get).mockImplementation(async (path) => {
    if (path === '/api/cases') return activeCases;
    throw new Error('Alert summary unavailable');
  });
  renderDashboard(['alerts.read', 'cases.read']);
  await screen.findByText('Alert summary unavailable');
  await screen.findByRole('link', { name: /Scoped investigation/ });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  expect(vi.mocked(get).mock.calls.filter(([path]) => path === '/api/cases')).toHaveLength(2);
});

it('loads cases for analysts who only have case read permission', async () => {
  vi.mocked(get).mockResolvedValue(activeCases);
  renderDashboard(['cases.read']);
  await screen.findByRole('link', { name: /Scoped investigation/ });
  expect(get).not.toHaveBeenCalledWith('/api/dashboard', expect.anything());
});

it('opens an all-severity alert list from a total-alert bucket', async () => {
  vi.mocked(get).mockImplementation(async (path) => {
    if (path === '/api/dashboard') return {
      series: [], metrics: { alerts_by_status: {}, open_cases: 0, mtta_minutes: null, sla_breached: 0, assets_total: 0, agents_active: 0, agent_coverage_pct: 0 },
    };
    if (path === '/api/dashboard-links') return [];
    throw new Error('Map unavailable');
  });
  renderDashboard(['alerts.read']);
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect bucket' }));
  await screen.findByText(/show_all=1/);
});

it('refreshes the active case list immediately after a case is created', async () => {
  vi.mocked(get).mockResolvedValueOnce({ items: [] }).mockResolvedValue(activeCases);
  renderDashboard(['cases.read']);
  await screen.findByText('No active cases.');
  act(() => TestEventSource.current.onmessage?.({ data: JSON.stringify({ type: 'case.created' }) }));
  await screen.findByRole('link', { name: /Scoped investigation/ });
});
