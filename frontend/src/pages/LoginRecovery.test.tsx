import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Login from './Login';
import { get } from '../lib/api';
import { useAuth } from '../lib/auth';

vi.mock('../lib/api', () => ({ get: vi.fn(), ApiError: class extends Error {} }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));
vi.mock('../components/LoginGlobe', () => ({ LoginGlobe: () => <div /> }));
afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(get).mockResolvedValue({ auth_mode: 'oidc' });
  vi.mocked(useAuth).mockReturnValue({ me: null, loading: false } as unknown as ReturnType<typeof useAuth>);
});
function show(url: string) {
  render(<MemoryRouter initialEntries={[url]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><QueryClientProvider client={new QueryClient()}><Login /></QueryClientProvider></MemoryRouter>);
}
it('shows an expired attempt with a fresh SSO retry preserving the destination', async () => {
  show('/login?auth_error=expired_state&ref=trace-123&next=%2Fapp%2Falerts');
  expect(screen.getByText(/Your sign-in attempt expired/)).toBeTruthy();
  expect(screen.getByText('trace-123')).toBeTruthy();
  const retry = await screen.findByRole('link', { name: 'Try company SSO again' });
  const target = new URL(retry.getAttribute('href')!, 'https://soc.example').searchParams.get('return_to')!;
  expect(new URL(target, 'https://soc.example').searchParams.get('next')).toBe('/app/alerts');
});
it('shows MFA recovery to an existing session instead of silently sending it back to Home', async () => {
  vi.mocked(useAuth).mockReturnValue({ me: { role: 'superadmin' }, loading: false } as unknown as ReturnType<typeof useAuth>);
  show('/login?auth_error=mfa_required&next=%2Fapp%2Fadmin');
  const retry = await screen.findByRole('link', { name: 'Verify with company SSO' });
  expect(retry.getAttribute('href')).toBe('/api/auth/oidc/step-up?return_to=%2Fapp%2Fadmin');
  expect(screen.getByRole('link', { name: 'Return to workspace' }).getAttribute('href')).toBe('/app/admin');
});
it('does not echo arbitrary error strings or accept an external return destination', async () => {
  show('/login?auth_error=secret-provider-description&ref=%3Cscript%3E&next=https%3A%2F%2Fevil.example');
  expect(screen.queryByText('secret-provider-description')).toBeNull();
  expect(screen.queryByText(/Reference:/)).toBeNull();
  const retry = await screen.findByRole('link', { name: 'Try company SSO again' });
  expect(retry.getAttribute('href')).not.toContain('evil');
});
