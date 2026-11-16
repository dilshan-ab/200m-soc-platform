import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Admin from './Admin';
import Approvals from './Approvals';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';

vi.mock('../lib/api', () => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock('../lib/auth', () => ({ useAuth: vi.fn() }));
afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

function role(role: 'admin' | 'superadmin') {
  vi.mocked(useAuth).mockReturnValue({ me: { id: 'me', role, auth_mode: 'oidc' }, can: () => true } as unknown as ReturnType<typeof useAuth>);
}
function show(element: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{element}</QueryClientProvider>);
}
function ownInbox() {
  vi.mocked(get).mockResolvedValue({ actions: [], changes: [{ id: 'existing', kind: 'tool.enable', requester_id: 'me', requester: 'Owner', reason: 'Enable connector', payload: {}, created_at: new Date().toISOString() }] });
}

it('ordinary admins see their own pending change as waiting for another approver', async () => {
  role('admin'); ownInbox(); show(<Approvals />);
  const waiting = await screen.findByRole('button', { name: 'Awaiting another approver' });
  expect(waiting.hasAttribute('disabled')).toBe(true);
  expect(screen.queryByRole('button', { name: 'Review' })).toBeNull();
});

it('the super admin can review and apply their existing pending request', async () => {
  role('superadmin'); ownInbox(); vi.mocked(post).mockResolvedValue({ status: 'applied' }); show(<Approvals />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review' }));
  fireEvent.change(screen.getByLabelText('Your decision reason (recorded in the audit log)'), { target: { value: 'Owner decision' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply now' }));
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/approvals/changes/existing/decision', { decision: 'approve', reason: 'Owner decision' }));
  expect(screen.getByText(/Your super-admin changes apply directly/)).toBeTruthy();
});

function adminApi() {
  vi.mocked(get).mockImplementation(async (path) => path === '/api/auth/config' ? { auth_mode: 'oidc', user_provisioning: true } : []);
}

it('the super admin can create an admin with the required Keycloak temporary password', async () => {
  role('superadmin'); adminApi(); vi.mocked(post).mockResolvedValue({ id: 'new-admin' }); show(<Admin />);
  fireEvent.click(await screen.findByRole('button', { name: 'Add user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@t.local' } });
  fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'admin' } });
  fireEvent.change(screen.getByLabelText(/Temporary password/), { target: { value: 'Str0ng-Passw0rd!x' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/admin/users', expect.objectContaining({ email: 'new@t.local', role: 'admin', password: 'Str0ng-Passw0rd!x' })));
});

it('ordinary administrators are not offered owner-only account creation', async () => {
  role('admin'); adminApi(); show(<Admin />);
  await screen.findByText('No users match these filters.');
  expect(screen.queryByRole('button', { name: 'Add user' })).toBeNull();
});
