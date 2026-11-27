import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Response from './Response';
import Simulation from './Simulation';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';

vi.mock('../lib/api', () => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); vi.mocked(get).mockResolvedValue([]); });

function as(caps: string[]) {
  vi.mocked(useAuth).mockReturnValue({ me: { id: 'u', role: 'l2' }, can: (c: string) => caps.includes(c) } as unknown as ReturnType<typeof useAuth>);
}
function show(element: React.ReactNode) {
  return render(<MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{element}</QueryClientProvider></MemoryRouter>);
}

it('hides the Run Simulation tab from roles that cannot start simulations', () => {
  as(['simulation.read']);
  show(<Simulation />);
  expect(screen.getByRole('tab', { name: 'Platforms' })).toBeTruthy();
  expect(screen.queryByRole('tab', { name: 'Run Simulation' })).toBeNull();
  cleanup();
  as(['simulation.read', 'simulation.write']);
  show(<Simulation />);
  expect(screen.getByRole('tab', { name: 'Run Simulation' })).toBeTruthy();
});

it('links to Approvals only for roles that can approve', async () => {
  as(['response.read', 'response.request']);
  show(<Response />);
  expect(await screen.findByText(/approved by L2 analysts or above/)).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'Approvals' })).toBeNull();
});
