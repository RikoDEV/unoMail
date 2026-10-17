
import { t, uiLocale } from './i18n';// HTTP client for the management API and JMAP. Authentication is an HttpOnly session cookie;
// every state-changing request additionally carries the per-session CSRF token.

export interface Account {
  id: number;
  email: string;
  display_name: string;
  role: 'user' | 'domain_admin' | 'super_admin';
  quota_bytes: number;
  used_bytes: number;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = '';
let onUnauthorized: () => void = () => {};

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

async function request(method: string, path: string, body?: BodyInit, contentType?: string): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (contentType) headers['Content-Type'] = contentType;
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(path, { method, headers, body, credentials: 'same-origin' });
  if (response.status === 401 && !path.startsWith('/api/auth/')) onUnauthorized();
  if (!response.ok) {
    let code = 'error';
    let message = t('Request failed ({{status}})', { status: response.status });
    try {
      const data = await response.json();
      code = data?.error?.code ?? code;
      message = data?.error?.message ?? data?.detail ?? message;
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(response.status, code, message);
  }
  return response;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await request(method, path, body === undefined ? undefined : JSON.stringify(body), body === undefined ? undefined : 'application/json');
  return (await response.json()) as T;
}

export const get = <T = unknown>(path: string) => api<T>('GET', path);
export const post = <T = unknown>(path: string, body: unknown = {}) => api<T>('POST', path, body);
export const put = <T = unknown>(path: string, body: unknown = {}) => api<T>('PUT', path, body);
export const patch = <T = unknown>(path: string, body: unknown = {}) => api<T>('PATCH', path, body);
export const del = <T = unknown>(path: string) => api<T>('DELETE', path);

export type MethodCall = [string, Record<string, unknown>, string];
export type MethodResponse = [string, any, string];

/** Sends a batch of JMAP method calls; a method-level error rejects the whole promise. */
export async function jmap(calls: MethodCall[]): Promise<MethodResponse[]> {
  const data = await api<{ methodResponses: MethodResponse[] }>('POST', '/jmap/api', {
    using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'],
    methodCalls: calls,
  });
  const failed = data.methodResponses.find((r) => r[0] === 'error');
  if (failed) throw new ApiError(400, failed[1].type, failed[1].description ?? failed[1].type);
  return data.methodResponses;
}

/** Posts a raw body (file upload) to a management endpoint. */
export async function postRaw<T = unknown>(path: string, body: Blob): Promise<T> {
  const response = await request('POST', path, body, body.type || 'application/octet-stream');
  return (await response.json()) as T;
}

export async function uploadBlob(accountId: string, file: Blob): Promise<{ blobId: string; type: string; size: number }> {
  const response = await request('POST', `/jmap/upload/${accountId}`, file, file.type || 'application/octet-stream');
  return response.json();
}

export function downloadUrl(accountId: string, blobId: string, name: string): string {
  return `/jmap/download/${accountId}/${encodeURIComponent(blobId)}/${encodeURIComponent(name || 'download')}`;
}

/** The message of a failure, or `fallback` when it carries none worth showing. */
export function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(uiLocale());
}
