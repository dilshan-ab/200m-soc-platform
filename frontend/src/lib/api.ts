export class ApiError extends Error {
  constructor(public status: number, message: string, public code?: string) {
    super(message);
  }
}

let csrf: string | null = null;
let stepUpHandler: (() => Promise<boolean>) | null = null;
let unauthHandler: (() => void) | null = null;

export const setCsrf = (t: string | null) => { csrf = t; };
export const onStepUp = (fn: (() => Promise<boolean>) | null) => { stepUpHandler = fn; };
export const onUnauth = (fn: (() => void) | null) => { unauthHandler = fn; };

type Opts = { method?: string; body?: unknown; params?: Record<string, string | number | boolean | string[] | undefined | null> };

function qs(params?: Opts['params']): string {
  if (!params) return '';
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) v.forEach((x) => u.append(k, x));
    else u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : '';
}

export async function api<T = any>(path: string, opts: Opts = {}, retried = false): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const res = await fetch(`${path}${qs(opts.params)}`, { method, headers, credentials: 'same-origin', body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get('content-type') ?? '';
  const data = ct.includes('json') ? await res.json().catch(() => null) : await res.text();
  if (res.ok) return data as T;
  const d = (data as any)?.detail;
  const code = typeof d === 'object' && d ? d.code : undefined;
  if (res.status === 403 && code === 'step_up_required' && stepUpHandler && !retried) {
    if (await stepUpHandler()) return api<T>(path, opts, true);
  }
  if (res.status === 401 && !path.startsWith('/api/auth/login')) unauthHandler?.();
  let msg = typeof d === 'string' ? d : typeof d === 'object' && d?.detail ? d.detail : Array.isArray(d) ? d.map((x: any) => `${(x.loc ?? []).slice(1).join('.')}: ${x.msg}`).join('; ') : res.statusText;
  if (!msg) msg = `Request failed (${res.status})`;
  throw new ApiError(res.status, msg, code);
}

export const get = <T = any>(path: string, params?: Opts['params']) => api<T>(path, { params });
export const post = <T = any>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body ?? {} });
export const put = <T = any>(path: string, body?: unknown) => api<T>(path, { method: 'PUT', body });
export const patch = <T = any>(path: string, body?: unknown) => api<T>(path, { method: 'PATCH', body });
/** Multipart upload with the CSRF header (the JSON helper can't send FormData). */
export async function upload<T = any>(path: string, form: FormData, params?: Opts['params']): Promise<T> {
  const headers: Record<string, string> = {};
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(`${path}${qs(params)}`, { method: 'POST', headers, credentials: 'same-origin', body: form });
  const data = await res.json().catch(() => null);
  if (res.ok) return data as T;
  if (res.status === 401) unauthHandler?.();
  const d = data?.detail;
  throw new ApiError(res.status, typeof d === 'string' ? d : Array.isArray(d) ? d.map((x: any) => x.msg).join('; ') : res.statusText || `Upload failed (${res.status})`);
}

export const del = <T = any>(path: string) => api<T>(path, { method: 'DELETE' });

export type Page<T> = { items: T[]; total: number; page: number; limit: number };
export type Me = { id: string; email: string; name: string; role: string; capabilities: string[]; all_clients: boolean; client_ids: string[] | null; csrf_token: string | null; step_up_until: string | null; auth_mode: 'dev' | 'oidc'; step_up_required?: boolean };
