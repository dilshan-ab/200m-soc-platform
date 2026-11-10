import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import MitreAttack from './MitreAttack';
import { get } from '../lib/api';

vi.mock('../lib/api', () => ({ get: vi.fn() }));

it('filters techniques and opens the selected alert', async () => {
  const command = { id: 'T1059', name: 'Command and Scripting Interpreter', count: 1, max_severity: 'high', rule_count: 2 };
  const phishing = { id: 'T1566', name: 'Phishing', count: 0, max_severity: 'none', rule_count: 0 };
  vi.mocked(get).mockImplementation(async (url) => url === '/api/mitre/matrix' ? {
    tactics: ['Execution', 'Initial Access'],
    matrix: { Execution: [command], 'Initial Access': [command, phishing] },
    total_techniques: 2, covered: 1, coverage_pct: 50, total_alerts_mapped: 1,
    rules_covered: 1, rules_coverage_pct: 50, total_rules_mapped: 2,
  } : {
    items: [{ id: 'alert-1', title: 'Suspicious script', severity: 'high', status: 'new', host: 'host-1', time: null }],
    page: 1, limit: 20, total: 1,
  });

  render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <QueryClientProvider client={new QueryClient()}><MitreAttack /></QueryClientProvider>
    </MemoryRouter>,
  );
  const results = await screen.findByRole('region', { name: 'Technique explorer' });
  expect(within(results).getAllByRole('button', { name: /T1059/ })).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: /Initial Access/ }));
  fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '7' } });
  await screen.findByRole('searchbox');
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'T1059' } });
  fireEvent.change(screen.getByLabelText('Highest severity'), { target: { value: 'critical' } });
  expect(screen.getByText('No techniques match these filters.')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Highest severity'), { target: { value: 'high' } });
  expect(screen.queryByRole('button', { name: /Phishing/ })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /T1059/ }));

  const drawer = screen.getByRole('dialog', { name: command.name });
  const link = await within(drawer).findByRole('link', { name: /Suspicious script/ });
  expect(link.getAttribute('href')).toBe('/app/alerts?open=alert-1');
  expect(get).toHaveBeenCalledWith('/api/mitre/technique/T1059/alerts', { days: 7, page: 1 });
  fireEvent.click(within(drawer).getByRole('button', { name: 'Close details' }));
  expect(screen.getByRole('searchbox')).toHaveProperty('value', 'T1059');
});
