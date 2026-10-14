import type { Filters } from './filters'
import { rangeToParams } from './filters'
import type { Overview, Me } from './types'

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string, public details?: unknown) {
    super(message)
  }
}

// The CSRF token lives only in memory; it is re-issued by /auth/me after a reload.
let csrf = ''
export const setCsrf = (t: string) => {
  csrf = t
}

let unauthorizedHandler: (() => void) | null = null
export const onUnauthorized = (fn: (() => void) | null) => {
  unauthorizedHandler = fn
}

export async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') {
    if (csrf) headers['X-CSRF-Token'] = csrf
    if (body !== undefined) headers['Content-Type'] = 'application/json'
  }
  let res: Response
  try {
    res = await fetch(path, { method, headers, signal, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) })
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    throw new ApiError(0, 'network', 'network')
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = undefined
    }
  }
  if (!res.ok) {
    const b = (data ?? {}) as { code?: string; message?: string; request_id?: string; details?: unknown }
    if (res.status === 401 && b.code !== 'invalid_credentials') unauthorizedHandler?.()
    throw new ApiError(res.status, b.code ?? 'http_error', b.message ?? res.statusText, b.request_id, b.details)
  }
  return data as T
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, signal),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body ?? {}),
}

export const login = (username: string, password: string) => request<Me | import('./types').MfaChallenge>('POST', '/api/v1/auth/login', { username, password })
export const loginMfa = (mfa_token: string, code: string) => request<Me>('POST', '/api/v1/auth/mfa', { mfa_token, code })
export const logout = () => request<void>('POST', '/api/v1/auth/logout', {})
export const fetchMe = (signal?: AbortSignal) => request<Me>('GET', '/api/v1/auth/me', undefined, signal)

export const fetchScope = (signal?: AbortSignal) =>
  request<{ panels: import('./types').PanelInfo[] }>('GET', '/api/v1/scope', undefined, signal)

export function overviewURL(f: Filters, demoState?: string): string {
  const p = new URLSearchParams(rangeToParams(f))
  if (f.panels.length) p.set('panel_ids', f.panels.join(','))
  if (f.nodes.length) p.set('node_ids', f.nodes.join(','))
  if (demoState) p.set('demo_state', demoState)
  return `/api/v1/overview?${p}`
}

export const fetchOverview = (f: Filters, demoState: string | undefined, signal?: AbortSignal) =>
  request<Overview>('GET', overviewURL(f, demoState), undefined, signal)
