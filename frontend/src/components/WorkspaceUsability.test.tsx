import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DashboardLayout, WidgetGrid } from './DashboardLayout';
import { SavedViews } from './SavedViews';
import { RecordPreview } from './RecordPreview';
import { ToastProvider } from './ui';
import { tableKeyboard } from '../lib/tableKeyboard';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';

vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));
vi.mock('../lib/api', () => ({ get: vi.fn() }));
afterEach(cleanup);
beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
  vi.mocked(useAuth).mockReturnValue({ me: { id: 'analyst-1' } } as unknown as ReturnType<typeof useAuth>);
});
const layout = () => <ToastProvider><DashboardLayout><WidgetGrid group="charts"><section key="one" data-widget-title="First">First widget</section><section key="two" data-widget-title="Second">Second widget</section></WidgetGrid></DashboardLayout></ToastProvider>;

it('persists widget order and width for each signed-in user', () => {
  const { container, unmount } = render(layout());
  fireEvent.click(screen.getByRole('button', { name: 'Customize dashboard' }));
  fireEvent.click(screen.getByRole('button', { name: 'Move Second earlier' }));
  fireEvent.change(screen.getByLabelText('Second width'), { target: { value: 'wide' } });
  expect(container.querySelector('.dashboard-widget')?.getAttribute('data-widget')).toBe('Second');
  expect(container.querySelector('.dashboard-widget')?.classList.contains('widget-wide')).toBe(true);
  unmount();
  const next = render(layout());
  expect(next.container.querySelector('.dashboard-widget')?.getAttribute('data-widget')).toBe('Second');
  next.unmount();
  vi.mocked(useAuth).mockReturnValue({ me: { id: 'analyst-2' } } as unknown as ReturnType<typeof useAuth>);
  const other = render(layout());
  expect(other.container.querySelector('.dashboard-widget')?.getAttribute('data-widget')).toBe('First');
});

it('can undo layout reset and ignores malformed browser preferences', async () => {
  localStorage.setItem('200m:dashboard-layout:v1:analyst-1', 'null');
  const { container } = render(layout());
  fireEvent.click(screen.getByRole('button', { name: 'Customize dashboard' }));
  fireEvent.click(screen.getByRole('button', { name: 'Move Second earlier' }));
  fireEvent.click(screen.getByRole('button', { name: 'Reset layout' }));
  expect(container.querySelector('.dashboard-widget')?.getAttribute('data-widget')).toBe('First');
  fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Undo' })).toBeNull());
  expect(container.querySelector('.dashboard-widget')?.getAttribute('data-widget')).toBe('Second');
});

function Location() { return <output data-testid="location">{useLocation().search}</output>; }
it('saves asset filters without record IDs and restores a removed view without losing newer ones', async () => {
  render(<MemoryRouter initialEntries={['/app/assets?kind=server&agent_status=active&open=private-record']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><ToastProvider><SavedViews area="assets" onApply={() => {}} /><Location /></ToastProvider></MemoryRouter>);
  fireEvent.click(screen.getByRole('button', { name: 'Save current view' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'View name' }), { target: { value: 'Servers' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  const key = '200m:saved-views:analyst-1:assets';
  expect(JSON.parse(localStorage.getItem(key)!)[0].query).toBe('kind=server&agent_status=active');
  fireEvent.click(screen.getByRole('button', { name: 'Servers' }));
  expect(screen.getByTestId('location').textContent).not.toContain('open=');
  fireEvent.click(screen.getByRole('button', { name: 'Remove view Servers' }));
  localStorage.setItem(key, JSON.stringify([{ name: 'Newer view', query: 'q=new' }]));
  fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
  await screen.findByRole('button', { name: 'Servers' });
  expect(JSON.parse(localStorage.getItem(key)!)).toHaveLength(2);
});

it('keeps focus navigation inside a table and leaves nested controls alone', () => {
  const scroll = vi.fn();
  HTMLElement.prototype.scrollIntoView = scroll;
  render(<main onKeyDown={tableKeyboard}><table><tbody><tr tabIndex={0}><td>First</td><td><button>Nested</button></td></tr><tr tabIndex={0}><td>Second</td></tr></tbody></table></main>);
  const rows = screen.getAllByRole('row');
  rows[0].focus(); fireEvent.keyDown(rows[0], { key: 'ArrowDown' });
  expect(document.activeElement).toBe(rows[1]);
  fireEvent.keyDown(rows[1], { key: 'Home' });
  expect(document.activeElement).toBe(rows[0]);
  const nested = screen.getByRole('button', { name: 'Nested' }); nested.focus();
  fireEvent.keyDown(nested, { key: 'ArrowDown' });
  expect(document.activeElement).toBe(nested);
  expect(scroll).toHaveBeenCalled();
});

it('previews a record in place and retries an API failure', async () => {
  vi.mocked(get).mockRejectedValueOnce(new Error('Temporary connection failure')).mockResolvedValue({ title: 'Suspicious script', severity: 'high', status: 'new', host: 'ws-1' });
  render(<MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><RecordPreview record={{ kind: 'alert', id: 'alert-1' }} onClose={() => {}} /></QueryClientProvider></MemoryRouter>);
  await screen.findByText('Temporary connection failure');
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  const link = await screen.findByRole('link', { name: 'Open full alert' });
  expect(link.getAttribute('href')).toBe('/app/alerts?open=alert-1');
  await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
});
