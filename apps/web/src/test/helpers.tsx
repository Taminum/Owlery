import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Overview from '../pages/Overview'
import Panels from '../pages/Panels'
import Settings from '../pages/Settings'
import type { Me, Overview as OverviewData, PanelDTO, PanelInfo, ProbeSummary } from '../lib/types'

// recharts measures its container; jsdom has no layout.
class RO { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal('ResizeObserver', RO)

export const owner: Me = {
  account: { id: 'acc-owner', username: 'owner', is_owner: true }, memberships: [],
  csrf_token: 'csrf-owner', session_expires_at: '2026-10-13T00:00:00Z', custom_ca_available: true,
}
export const member = (role: 'viewer' | 'operator' | 'admin', panelId = 'p-work'): Me => ({
  account: { id: 'acc-m', username: role + '-user', is_owner: false }, memberships: [{ panel_id: panelId, role }],
  csrf_token: 'csrf-member', session_expires_at: '2026-10-13T00:00:00Z', custom_ca_available: false,
})

export const SECRET = 'tok-SECRET-typed-by-the-user'

export const scopePanels: PanelInfo[] = [
  { id: 'p-home', name: 'Home', demo: false, role: 'owner', nodes: [{ id: 'n1', panel_id: 'p-home', name: 'home-a', agent_status: 'none', lag_seconds: 0 }] },
  { id: 'p-work', name: 'Work', demo: false, role: 'owner', nodes: [] },
]

export const panelDTO = (over: Partial<PanelDTO> = {}): PanelDTO => ({
  id: 'p-work', name: 'Work', base_url: 'https://work.example.com', status: 'active', demo: false, use_custom_ca: false,
  sync_options: { nodes: true, users: true, stats: false }, sync_interval_seconds: 300, retention_days: 30, api_version: '3.4.5',
  capabilities: { nodes: true, users: true }, last_probe_at: null, last_probe: null, last_sync_at: '2026-10-12T10:00:00Z', last_sync_status: 'ok',
  next_sync_at: '2026-10-12T10:05:00Z', consecutive_failures: 0, circuit_open_until: null, node_count: 2, user_count: 5,
  token: 'configured', role: 'owner', created_at: '2026-10-01T00:00:00Z', ...over,
})

export const okProbe = (over: Partial<ProbeSummary> = {}): ProbeSummary => ({
  reachable: true, tls_ok: true, authenticated: true, required_ok: true, api_version: '3.4.5', node_count: 2, nodes_preview: ['node-1', 'node-2'],
  capabilities: { nodes: true, users: true, system_stats: true, bandwidth_stats: true, metadata: true },
  checks: [
    { name: 'url', status: 'ok', latency_ms: 0, required: true }, { name: 'connection', status: 'ok', latency_ms: 40, required: true },
    { name: 'auth', status: 'ok', latency_ms: 40, required: true }, { name: 'nodes', status: 'ok', latency_ms: 41, required: true },
    { name: 'users', status: 'ok', latency_ms: 30, required: false }, { name: 'stats', status: 'ok', latency_ms: 30, required: false },
    { name: 'version', status: 'ok', latency_ms: 20, required: false },
  ], ...over,
})

export const emptyOverview = (over: Partial<OverviewData['meta']> = {}): OverviewData => {
  const empty = { ts: [], v: [] }
  return {
    meta: { demo: true, state: 'ok', generated_at: '2026-10-09T12:00:00Z', from: '2026-10-08T12:00:00Z', to: '2026-10-09T12:00:00Z', granularity_seconds: 1800,
      panel_ids: ['p-home'], node_ids: [], coverage: { pct: 100, gaps: [] }, ...over },
    connections: { metric_kind: 'connection_count', source: 'demo_fixture', total: 1200, tcp: 1180, udp: 20, delta_pct: 4, series: empty },
    unique_hosts: { value: 10, series: empty, source: 'demo_fixture' }, unique_ips: { value: 20, series: empty, source: 'demo_fixture' },
    nodes: { reporting: 2, total: 2 },
    traffic: { metric_kind: 'bytes', source: 'demo_fixture', unit: 'bytes', up_bytes: 10, down_bytes: 100, coverage_pct: 100, series: [] },
    freshness: { last_event_at: '2026-10-09T11:59:30Z', lag_seconds: 30, status: 'ok' },
    timeline: [], top_hosts: [], top_ips: [], top_ports: [], services: [], users: [], recent: [],
  }
}

export interface Req { method: string; path: string; url: string; body: Record<string, unknown> | undefined; headers: Record<string, string> }
type Reply = { status: number; body?: unknown } | undefined

/** A scripted backend. Unhandled calls fail the test by returning 599. */
export function mockApi(opts: { me: Me | null; loginAs?: Me; panels?: PanelDTO[]; canCreate?: boolean; handler?: (r: Req) => Reply }) {
  const calls: Req[] = []
  let current: Me | null = opts.me
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const path = url.split('?')[0]
    const method = (init?.method ?? 'GET').toUpperCase()
    const headers = (init?.headers ?? {}) as Record<string, string>
    const req: Req = { method, path, url, headers, body: (init?.body ? JSON.parse(String(init.body)) : undefined) as Req["body"] }
    calls.push(req)
    const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

    const custom = opts.handler?.(req)
    if (custom) return json(custom.status, custom.body)

    if (path === '/api/v1/auth/me') return current ? json(200, current) : json(401, { code: 'unauthenticated', message: 'sign in required', request_id: 'r' })
    if (path === '/api/v1/auth/login') { current = opts.loginAs ?? opts.me; return current ? json(200, current) : json(401, { code: 'invalid_credentials', message: 'x', request_id: 'r' }) }
    if (path === '/api/v1/auth/logout') { current = null; return json(204) }
    if (path === '/api/v1/scope') return json(200, { panels: scopePanels })
    if (path === '/api/v1/panels' && method === 'GET') return json(200, { panels: opts.panels ?? [], can_create: opts.canCreate ?? current?.account.is_owner ?? false, custom_ca_available: current?.custom_ca_available ?? false })
    if (path === '/api/v1/overview') return json(200, emptyOverview())
    return json(599, { code: 'unmocked', message: `${method} ${path}`, request_id: 'r' })
  }))
  return { calls, find: (method: string, path: string) => calls.filter((c) => c.method === method && c.path === path) }
}

export function renderApp(path = '/') {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="panels" element={<Panels />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}
