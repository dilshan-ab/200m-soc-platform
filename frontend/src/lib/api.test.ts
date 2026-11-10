import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, setCsrf } from './api';

afterEach(() => { vi.restoreAllMocks(); setCsrf(null); });

function mockFetch(status: number, body: unknown) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
}

describe('api client', () => {
  it('sends the CSRF header on writes only', async () => {
    const f = mockFetch(200, {});
    setCsrf('tok');
    await api('/api/x', { method: 'POST', body: {} });
    await api('/api/x');
    expect((f.mock.calls[0][1]!.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok');
    expect((f.mock.calls[1][1]!.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
  });
  it('serialises array params and skips empty ones', async () => {
    const f = mockFetch(200, {});
    await api('/api/x', { params: { a: ['1', '2'], b: '', c: undefined, d: 3 } });
    expect(f.mock.calls[0][0]).toBe('/api/x?a=1&a=2&d=3');
  });
  it('turns validation errors into readable messages', async () => {
    mockFetch(422, { detail: [{ loc: ['body', 'title'], msg: 'too short' }] });
    await expect(api('/api/x', { method: 'POST', body: {} })).rejects.toThrow('title: too short');
  });
  it('throws ApiError with the status', async () => {
    mockFetch(404, { detail: 'not found' });
    await expect(api('/api/x')).rejects.toBeInstanceOf(ApiError);
  });
});
