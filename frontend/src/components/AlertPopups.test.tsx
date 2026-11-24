import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { get } from '../lib/api';
import { DEFAULT_POPUP_PREFS, resetPopupPrefsCache, setPopupPrefs } from '../lib/popupPrefs';
import { AlertPopups, MAX_VISIBLE } from './AlertPopups';
import { Pulse } from './Interactive';

vi.mock('../lib/api', () => ({ get: vi.fn() }));

const ALERTS: Record<string, { id: string; severity: string; title: string; host: string; source: string }> = {};
function alert(id: string, severity: string, title = `Alert ${id}`) {
  ALERTS[id] = { id, severity, title, host: 'ws-01', source: 'wazuh' };
}
function live(id: string) {
  act(() => { window.dispatchEvent(new CustomEvent('soc:live', { detail: { type: 'alert.created', id, severity: ALERTS[id].severity } })); });
}
function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter><AlertPopups live /></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  localStorage.clear();
  resetPopupPrefsCache();
  setPopupPrefs(DEFAULT_POPUP_PREFS);
  vi.mocked(get).mockClear();
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

it('respects the per-severity switches', async () => {
  alert('m1', 'medium', 'Medium one');
  alert('l1', 'info', 'Info one');
  alert('c1', 'critical', 'Critical one');
  setPopupPrefs({ critical: true, high: true, medium: false, low: false });
  mount();
  live('m1');
  live('l1');
  live('c1');
  await screen.findByText('Critical one');
  expect(screen.queryByText('Medium one')).toBeNull();
  expect(screen.queryByText('Info one')).toBeNull();
  expect(vi.mocked(get)).toHaveBeenCalledTimes(1); // switched-off severities are not even fetched
});

it('groups a burst beyond the visible limit into one summary', async () => {
  for (let i = 0; i < MAX_VISIBLE + 3; i++) alert(`b${i}`, 'high');
  mount();
  for (let i = 0; i < MAX_VISIBLE + 3; i++) live(`b${i}`);
  expect(await screen.findByText('+3 more new alerts')).toBeTruthy();
  expect(screen.getAllByRole('alert')).toHaveLength(MAX_VISIBLE);
});

it('closes medium pop-ups by itself but keeps critical ones until dismissed', async () => {
  alert('m2', 'medium', 'Short lived');
  alert('c2', 'critical', 'Stays put');
  vi.useFakeTimers({ shouldAdvanceTime: true });
  mount();
  live('m2');
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
