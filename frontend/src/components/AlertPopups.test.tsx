import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { AlertPopups, MAX_VISIBLE } from './AlertPopups';
import { Pulse } from './Interactive';

vi.mock('../lib/api', () => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));

function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search}</output>; }

const ALERTS: Record<string, { id: string; severity: string; title: string; host: string; source: string }> = {};
function alert(id: string, severity: string, title = `Alert ${id}`) {
  ALERTS[id] = { id, severity, title, host: 'ws-01', source: 'wazuh' };
}
function live(id: string) {
  act(() => { window.dispatchEvent(new CustomEvent('soc:live', { detail: { type: 'alert.created', id, severity: ALERTS[id].severity } })); });
}
function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter><AlertPopups live /><Where /></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  localStorage.clear();
  vi.mocked(get).mockClear();
  vi.mocked(post).mockReset();
  vi.mocked(useAuth).mockReturnValue({ can: () => true } as unknown as ReturnType<typeof useAuth>);
  vi.mocked(get).mockImplementation((path: string) => {
    const id = path.split('/').pop()!;
    return ALERTS[id] ? Promise.resolve(ALERTS[id]) : Promise.reject(new Error('not found'));
  });
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

it('shows a pop-up for a new alert from the live stream, with a link to open it', async () => {
  alert('a1', 'critical', 'Ransomware detected');
  mount();
  live('a1');
  expect(await screen.findByText('Ransomware detected')).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toContain('ws-01');
  expect(screen.getByRole('link', { name: 'Open alert' }).getAttribute('href')).toBe('/app/alerts?open=a1');
});

it('shows each alert once and can be dismissed', async () => {
  alert('a2', 'high', 'Brute force');
  mount();
  live('a2');
  live('a2');
  await screen.findByText('Brute force');
  expect(screen.getAllByText('Brute force')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
  await waitFor(() => expect(screen.queryByText('Brute force')).toBeNull());
});

it('pops up only critical and high alerts, never medium, low or info', async () => {
  alert('m1', 'medium', 'Medium one');
  alert('l1', 'low', 'Low one');
  alert('i1', 'info', 'Info one');
  alert('h1', 'high', 'High one');
  mount();
  live('m1');
  live('l1');
  live('i1');
  live('h1');
  await screen.findByText('High one');
  for (const t of ['Medium one', 'Low one', 'Info one']) expect(screen.queryByText(t)).toBeNull();
  expect(vi.mocked(get)).toHaveBeenCalledTimes(1); // the others are not even fetched
});

it('ignores pop-up settings saved by an earlier version', async () => {
  localStorage.setItem('200m-alert-popups', JSON.stringify({ critical: false, high: false }));
  alert('h5', 'high', 'High still pops');
  mount();
  live('h5');
  expect(await screen.findByText('High still pops')).toBeTruthy();
});

it('groups a burst beyond the visible limit into one summary', async () => {
  for (let i = 0; i < MAX_VISIBLE + 3; i++) alert(`b${i}`, 'high');
  mount();
  for (let i = 0; i < MAX_VISIBLE + 3; i++) live(`b${i}`);
  expect(await screen.findByText('+3 more critical or high alerts')).toBeTruthy();
  expect(screen.getAllByRole('alert')).toHaveLength(MAX_VISIBLE);
});

it('closes high pop-ups by itself but keeps critical ones until dismissed', async () => {
  alert('h4', 'high', 'Short lived');
  alert('c2', 'critical', 'Stays put');
  vi.useFakeTimers({ shouldAdvanceTime: true });
  mount();
  live('h4');
  live('c2');
  await screen.findByText('Short lived');
  await screen.findByText('Stays put');
  act(() => { vi.advanceTimersByTime(60_000); });
  expect(screen.queryByText('Short lived')).toBeNull();
  expect(screen.getByText('Stays put')).toBeTruthy();
});

it('the bell dot blinks only when told to', () => {
  const { rerender } = render(<Pulse active blink />);
  expect(screen.getByTestId('pulse').className).toBe('pulse blink');
  rerender(<Pulse active blink={false} />);
  expect(screen.getByTestId('pulse').className).toBe('pulse steady');
  rerender(<Pulse active={false} />);
  expect(screen.queryByTestId('pulse')).toBeNull();
});


it('acknowledges an alert straight from the pop-up', async () => {
  alert('k1', 'critical', 'Act on me');
  vi.mocked(post).mockResolvedValue({ updated: 1, skipped: [] });
  mount();
  live('k1');
  await screen.findByText('Act on me');
  fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
  expect(await screen.findByText('Acknowledged')).toBeTruthy();
  expect(vi.mocked(post)).toHaveBeenCalledWith('/api/alerts/bulk', { ids: ['k1'], status: 'acknowledged' });
  expect(screen.getByTestId('where').textContent).toBe('/');  // acting does not navigate away
});

it('can start an investigation, and shows the error if the update fails', async () => {
  alert('k2', 'high', 'Investigate me');
  vi.mocked(post).mockRejectedValueOnce(new Error('alert changed; reload'));
  mount();
  live('k2');
  await screen.findByText('Investigate me');
  fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
  expect(await screen.findByText('alert changed; reload')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Investigate' })).toBeTruthy();  // can try again
});

it('clicking the pop-up opens the alert', async () => {
  alert('k3', 'critical', 'Click anywhere');
  mount();
  live('k3');
  fireEvent.click(await screen.findByText('Click anywhere'));
  expect(screen.getByTestId('where').textContent).toBe('/app/alerts?open=k3');
  expect(screen.queryByText('Click anywhere')).toBeNull();
});

it('hides the triage buttons from users who cannot triage', async () => {
  vi.mocked(useAuth).mockReturnValue({ can: () => false } as unknown as ReturnType<typeof useAuth>);
  alert('k4', 'high', 'Read only');
  mount();
  live('k4');
  await screen.findByText('Read only');
  expect(screen.queryByRole('button', { name: 'Acknowledge' })).toBeNull();
  expect(screen.getByRole('link', { name: 'Open alert' })).toBeTruthy();
});
