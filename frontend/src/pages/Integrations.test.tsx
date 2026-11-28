import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';
import { ToastProvider } from '../components/ui';
import Integrations from './Integrations';

vi.mock('../lib/api', () => ({ get: vi.fn() }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));

afterEach(() => { cleanup(); vi.clearAllMocks(); });

function renderIntegrations(canWrite: boolean) {
  vi.mocked(useAuth).mockReturnValue({ can: (cap: string) => canWrite && cap === 'integrations.write' } as ReturnType<typeof useAuth>);
  vi.mocked(get).mockImplementation(async (path) => {
    if (path === '/api/integrations/tools') return [
      { id: 'hive', type: 'thehive', label: 'TheHive', name: 'Existing case bridge', status: 'disabled' },
      { id: 'wazuh', type: 'wazuh_indexer', label: 'Wazuh indexer', name: 'Existing indexer', status: 'enabled' },
    ];
    if (path === '/api/integrations/catalogue') return [
      { type: 'wazuh_indexer', label: 'Wazuh indexer' }, { type: 'thehive', label: 'TheHive' },
      { type: 'shuffle', label: 'Shuffle' }, { type: 'keycloak', label: 'Keycloak' }, { type: 'custom', label: 'Custom' },
    ].map((connector) => ({ ...connector, fields: [] }));
    return [];
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={queryClient}><ToastProvider><Integrations /></ToastProvider></QueryClientProvider>);
}

it('omits built-in workflow alternatives from Add integrations and retains existing connections', async () => {
  renderIntegrations(true);
  await screen.findByText('Existing case bridge');
  fireEvent.click(screen.getByRole('tab', { name: 'Add integrations' }));
  const catalog = within(screen.getByRole('tabpanel', { name: 'Add integrations' }));
  const configured = await catalog.findByRole('button', { name: 'Wazuh indexer Configured' });
  expect(configured.classList.contains('tool-pick-configured')).toBe(true);
  expect(catalog.getByRole('button', { name: 'Custom' }).classList.contains('tool-pick-configured')).toBe(false);
  for (const name of ['TheHive', 'Shuffle', 'Keycloak']) {
    expect(catalog.queryByRole('button', { name })).toBeNull();
  }
  fireEvent.change(catalog.getByRole('searchbox', { name: 'Find a tool' }), { target: { value: 'TheHive' } });
  expect(catalog.getByText('Use Cases to manage investigations.')).toBeTruthy();
  expect(catalog.queryByRole('button', { name: /as a custom tool/ })).toBeNull();
  fireEvent.click(screen.getByRole('tab', { name: 'Connected' }));
  expect(screen.getByText('Existing case bridge')).toBeTruthy();
});

it('keeps connected integrations visible to read-only users', async () => {
  renderIntegrations(false);
  await screen.findByText('Existing case bridge');
  expect(screen.queryByRole('tab', { name: 'Add integrations' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Add tool' })).toBeNull();
  expect(get).not.toHaveBeenCalledWith('/api/integrations/catalogue');
});

it('opens the add integrations tab from the Add tool shortcut', async () => {
  renderIntegrations(true);
  fireEvent.click(screen.getByRole('button', { name: 'Add tool' }));
  const tab = screen.getByRole('tab', { name: 'Add integrations', selected: true });
  expect(document.activeElement).toBe(tab);
  await within(screen.getByRole('tabpanel', { name: 'Add integrations' })).findByRole('button', { name: /Wazuh indexer/ });
});
