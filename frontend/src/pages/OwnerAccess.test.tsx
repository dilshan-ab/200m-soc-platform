import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import Admin from './Admin';
import Approvals from './Approvals';
import { get, patch, post } from '../lib/api';
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

it('ordinary administrators can create users', async () => {
  role('admin'); adminApi(); show(<Admin />);
  await screen.findByText('No users match these filters.');
  expect(await screen.findByRole('button', { name: 'Add user' })).toBeTruthy();
});


function usersApi(identity = 'linked') {
  vi.mocked(get).mockImplementation(async (path) => path === '/api/auth/config' ? { auth_mode: 'oidc', user_provisioning: true } : path === '/api/admin/users' ? [{ id: 'target', email: 'person@t.local', name: 'Person', role: 'l1', active: true, all_clients: true, client_ids: [], identity_status: identity }] : []);
}

it('owner resets a Keycloak password after confirmation', async () => {
  role('superadmin'); usersApi(); vi.mocked(post).mockResolvedValue({ ok: true }); show(<Admin />);
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }));
  const submit = screen.getAllByRole('button', { name: 'Reset password' }).at(-1)!;
  expect(submit.hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByLabelText('Temporary password'), { target: { value: 'Str0ng-Passw0rd!x' } });
  fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Str0ng-Passw0rd!x' } });
  fireEvent.click(submit);
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/admin/users/target/password', { password: 'Str0ng-Passw0rd!x' }));
});

it('owner can explicitly provision a legacy account in Keycloak', async () => {
  role('superadmin'); usersApi('local'); vi.mocked(post).mockResolvedValue({ identity_status: 'linked' }); show(<Admin />);
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }));
  fireEvent.click(screen.getByLabelText(/Create in Keycloak/));
  fireEvent.change(screen.getByLabelText('Temporary password'), { target: { value: 'Str0ng-Passw0rd!x' } });
  fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Str0ng-Passw0rd!x' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create in Keycloak' }));
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/admin/users/target/provision', { password: 'Str0ng-Passw0rd!x' }));
});

it('ordinary admins can reset another user password', async () => {
  role('admin'); usersApi(); show(<Admin />);
  await screen.findByText('person@t.local');
  expect(await screen.findByRole('button', { name: 'Reset password' })).toBeTruthy();
});


it('admins can edit the email, name and role of another user', async () => {
  role('admin'); usersApi(); vi.mocked(patch).mockResolvedValue({ id: 'target' }); show(<Admin />);
  fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'updated@t.local' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Updated Name' } });
  fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'admin' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/admin/users/target', expect.objectContaining({ email: 'updated@t.local', name: 'Updated Name', role: 'admin' })));
});

it('the protected owner has no management buttons for an ordinary admin', async () => {
  role('admin');
  vi.mocked(get).mockImplementation(async (path) => path === '/api/auth/config' ? { auth_mode: 'oidc', user_provisioning: true } : path === '/api/admin/users' ? [{ id: 'owner', email: 'owner@t.local', name: 'Owner', role: 'superadmin', active: true, all_clients: true, client_ids: [] }] : []);
  show(<Admin />);
  await screen.findByText('owner@t.local');
  for (const name of ['Edit', 'Reset password', 'Disable', 'Sign out everywhere']) expect(screen.queryByRole('button', { name })).toBeNull();
});
