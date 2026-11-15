import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { get } from './api';
import { AuthProvider, useAuth } from './auth';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function SignInConfig() {
  const { loading } = useAuth();
  const config = useQuery({ queryKey: ['auth-config'], queryFn: () => get<{ auth_mode: string }>('/api/auth/config') });
  return <><span>{loading ? 'Checking session' : 'Signed out'}</span><span>{config.data?.auth_mode ?? 'Loading config'}</span></>;
}

it('keeps the pending sign-in configuration when the initial session check returns 401', async () => {
  let resolveConfig!: (response: Response) => void;
  const config = new Promise<Response>((resolve) => { resolveConfig = resolve; });
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (url === '/api/auth/config') return config;
    return new Response(JSON.stringify({ detail: 'not authenticated' }), { status: 401, headers: { 'content-type': 'application/json' } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const clear = vi.spyOn(client, 'clear');
  render(<StrictMode><QueryClientProvider client={client}><AuthProvider><SignInConfig /></AuthProvider></QueryClientProvider></StrictMode>);
  await waitFor(() => expect(screen.getByText('Signed out')).toBeTruthy());
  await act(async () => { resolveConfig(new Response(JSON.stringify({ auth_mode: 'dev' }), { headers: { 'content-type': 'application/json' } })); });
  await waitFor(() => expect(screen.getByText('dev')).toBeTruthy());
  expect(clear).not.toHaveBeenCalled();
  client.clear();
});
