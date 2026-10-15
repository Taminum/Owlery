import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Security, { SecurityDetail } from '../pages/Security'
import { mockApi, member, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderSec(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="security" element={<Security />} />
            <Route path="security/:id" element={<SecurityDetail />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const vps = (over: object = {}) => ({
  id: 'v1', name: 'Helsinki', origin: 'manual', enabled: true, note: '', created_at: '2026-10-15T10:00:00Z', updated_at: '2026-10-15T10:00:00Z',
  addresses: [{ address: '203.0.113.7', kind: 'ipv4' }], links: [], can_edit: true, ...over,
})

describe('Security page', () => {
  it('lists servers and lets the owner add one', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps' && r.method === 'GET') return { status: 200, body: { items: [vps()], can_create: true } }
      if (r.path === '/api/v1/security/vps' && r.method === 'POST') return { status: 201, body: vps({ id: 'v2', name: 'Oslo' }) }
      if (r.path === '/api/v1/security/vps/v2') return { status: 200, body: vps({ id: 'v2', name: 'Oslo' }) }
    } })
    renderSec('/security')
    expect(await screen.findByText('Helsinki')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Добавить сервер/ }))
    await userEvent.type(screen.getByLabelText('Название'), 'Oslo')
    await userEvent.type(screen.getByLabelText('Адреса'), '198.51.100.9')
    await userEvent.click(screen.getByRole('button', { name: 'Добавить' }))
    expect(await screen.findByRole('heading', { name: 'Oslo' })).toBeInTheDocument()
    const post = api.find('POST', '/api/v1/security/vps')[0]
    expect(post.body).toMatchObject({ name: 'Oslo', addresses: ['198.51.100.9'] })
  })

  it('shows no create button and an honest empty state to a viewer', async () => {
    mockApi({ me: member('viewer'), handler: (r: Req) => (r.path === '/api/v1/security/vps' ? { status: 200, body: { items: [], can_create: false } } : undefined) })
    renderSec('/security')
    expect(await screen.findByText('Серверов пока нет')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Добавить сервер/ })).toBeNull()
  })

  it('never shows a healthy state for a server without an agent, and says what it knows when it has one', async () => {
    const cat = (over: object) => ({ category: 'fail2ban', state: 'agent_required', status: undefined, observed_at: null, received_at: null, clock_skew_ms: 0, data: null, agent: null, ...over })
    let agent: object | null = null
    let f2b: object = cat({})
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent } }
      if (r.path === '/api/v1/security/vps/v1/fail2ban') return { status: 200, body: f2b }
    } })
    const view = renderSec('/security/v1')
    expect(await screen.findByText('Агент не создан. Без него Fail2ban, порты и firewall не видны.')).toBeInTheDocument()
    expect(await screen.findByText('нужен агент')).toBeInTheDocument()
    expect(screen.queryByText('данные получены')).toBeNull()
    view.unmount()

    agent = { id: 'a1', status: 'active', agent_version: '0.1', hostname: 'h1', capabilities: [], last_seen: new Date().toISOString(), online: true }
    f2b = cat({ state: 'ok', status: 'ok', observed_at: '2026-10-15T12:00:00Z', received_at: '2026-10-15T12:00:00Z',
      data: { jails: [{ name: 'sshd', currently_failed: 1, total_failed: 9, currently_banned: 1, total_banned: 4, banned_ips: ['203.0.113.5'] }] } })
    renderSec('/security/v1')
    expect(await screen.findByText('sshd')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.5')).toBeInTheDocument()
    expect(screen.getByText('на связи')).toBeInTheDocument()
    expect(screen.getByText('1 / 4')).toBeInTheDocument()
  })

  it('marks old data as stale and an unreadable source as such, with no invented rows', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent: null } }
      if (r.path === '/api/v1/security/vps/v1/fail2ban') return { status: 200, body: { category: 'fail2ban', state: 'permission_denied', status: 'permission_denied', observed_at: '2026-10-15T12:00:00Z', received_at: '2026-10-15T12:00:00Z', clock_skew_ms: 0, data: {}, agent: null } }
    } })
    renderSec('/security/v1')
    expect(await screen.findByText('нет прав на чтение')).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('shows external results with the vantage warning, and never calls a timeout closed', async () => {
    const port = (over: object) => ({ id: 'e1', host: '203.0.113.7', port: 443, expected: true, source: 'manual', enabled: true, last_checked_at: '2026-10-15T12:00:00Z', last_result: 'reachable', last_error: null, last_ip: '203.0.113.7', last_rtt_ms: 12, changed_at: null, ...over })
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent: null } }
      if (r.path === '/api/v1/security/vps/v1/ports') return { status: 200, body: { category: 'sockets', state: 'agent_required', observed_at: null, received_at: null, clock_skew_ms: 0, data: null, agent: null } }
      if (r.path === '/api/v1/security/vps/v1/public-ports' && r.method === 'GET') return { status: 200, body: { items: [port({}), port({ id: 'e2', port: 8443, expected: false, last_result: 'timeout' }), port({ id: 'e3', port: 22, last_result: null, last_checked_at: null, last_ip: null })], vantage: { id: 'api_server', independent: false }, interval_minutes: 60, coverage: { kind: 'known_endpoints', discovery: 'off' } } }
      if (r.path === '/api/v1/security/vps/v1/checks/ports/run') return { status: 202, body: { requested: 3 } }
    } })
    renderSec('/security/v1')
    await userEvent.click(await screen.findByRole('tab', { name: 'Порты' }))
    expect(await screen.findByText(/Это не независимая точка/)).toBeInTheDocument()
    expect(screen.getByText(/Остальные порты не сканируются/)).toBeInTheDocument()
    expect(screen.getByText('отвечает')).toBeInTheDocument()
    expect(screen.getByText('нет ответа (не значит «закрыт»)')).toBeInTheDocument()
    expect(screen.queryByText(/закрыт$/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Проверить сейчас' }))
    expect(await screen.findByText(/Проверка запрошена/)).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/security/vps/v1/checks/ports/run')).toHaveLength(1)
  })

  it('shows certificates with days left, flags an expired one, and keeps unchecked ones unchecked', async () => {
    const ep = (over: object) => ({ id: 't1', host: 'fi.example.com', port: 443, sni: 'fi.example.com', enabled: true, last_checked_at: '2026-10-15T12:00:00Z', last_state: 'ok', last_ip: '203.0.113.7', last_fingerprint: 'ab', last_not_after: '2026-12-01T00:00:00Z', last_obs: { issuer: "CN=R11,O=Let's Encrypt", days_left: 47 }, ...over })
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent: null } }
      if (r.path === '/api/v1/security/vps/v1/fail2ban') return { status: 200, body: { category: 'fail2ban', state: 'agent_required', observed_at: null, received_at: null, clock_skew_ms: 0, data: null, agent: null } }
      if (r.path === '/api/v1/security/vps/v1/tls') return { status: 200, body: { items: [ep({}), ep({ id: 't2', host: 'old.example.com', last_state: 'expired', last_not_after: '2026-10-10T00:00:00Z', last_obs: { days_left: -5 } }), ep({ id: 't3', host: 'new.example.com', last_state: null, last_checked_at: null, last_not_after: null, last_obs: {} })], vantage: { id: 'api_server', independent: false }, interval_hours: 24 } }
    } })
    renderSec('/security/v1')
    await userEvent.click(await screen.findByRole('tab', { name: 'TLS-сертификаты' }))
    expect(await screen.findByText(/через 47 дн./)).toBeInTheDocument()
    expect(screen.getByText(/истёк 5 дн. назад/)).toBeInTheDocument()
    expect(screen.getByText('истёк')).toBeInTheDocument()
    expect(screen.getByText('ещё не проверялся')).toBeInTheDocument()
    expect(screen.getByText(/Это не независимая точка/)).toBeInTheDocument()
  })

  it('shows the journal of all servers with filters sent to the server, and the fixed parameters', async () => {
    const ev = (over: object) => ({ id: 'e1', vps_id: 'v1', vps_name: 'Helsinki', category: 'fail2ban', type: 'fail2ban.ban', severity: 'info', source: 'state_diff', observed_at: '2026-10-15T12:00:00Z', payload: { jail: 'sshd', ip: '198.51.100.9' }, ...over })
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps') return { status: 200, body: { items: [vps()], can_create: true } }
      if (r.path === '/api/v1/security/settings') return { status: 200, body: { agent_interval_seconds: 30, stale_after_seconds: 120, port_check_minutes: 60, tls_check_hours: 24, tls_warn_days: [30, 14, 7, 3], retention_days: 180, vantage: { id: 'api_server', independent: false }, discovery_scan: 'off' } }
      if (r.path === '/api/v1/security/events') {
        const crit = r.url.includes('severity=critical')
        return { status: 200, body: { items: crit ? [ev({ id: 'e2', category: 'ports', type: 'port.public_reachable', severity: 'critical', payload: { host: '203.0.113.7', port: 9000 } })] : [ev({}), ev({ id: 'e3', category: 'tls', type: 'tls.expired', severity: 'critical', payload: { host: 'a.example', port: 443 } })], more: false } }
      }
    } })
    renderSec('/security')
    await userEvent.click(await screen.findByRole('tab', { name: 'Журнал' }))
    expect(await screen.findByText('Блокировка 198.51.100.9 в sshd')).toBeInTheDocument()
    expect(screen.getByText('Сертификат a.example:443 истёк')).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Helsinki' })[0]).toHaveAttribute('href', '/security/v1')
    expect(screen.getByText(/Данные хранятся|События хранятся 180 дн\./)).toBeInTheDocument()
    expect(screen.getByText(/Поиск неизвестных портов выключен/)).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Важность'), 'critical')
    expect(await screen.findByText('Порт 9000 на 203.0.113.7 стал отвечать снаружи')).toBeInTheDocument()
    expect(screen.queryByText('Блокировка 198.51.100.9 в sshd')).toBeNull()
    expect(api.calls.some((c) => c.url.includes('/api/v1/security/events') && c.url.includes('severity=critical'))).toBe(true)
  })

  it('walks the owner through installing the agent, with the secret in the command and shown once', async () => {
    let agent: object | null = null
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent' && r.method === 'GET') return { status: 200, body: { agent } }
      if (r.path === '/api/v1/security/vps/v1/agent' && r.method === 'POST') { agent = { id: 'a1', status: 'enrolling', agent_version: null, hostname: null, capabilities: [], last_seen: null, online: false }; return { status: 201, body: { agent, token: 'AGENTID.SECRETVALUE', ingest_path: '/ingest/security/v1' } } }
      if (r.path === '/api/v1/security/vps/v1/fail2ban') return { status: 200, body: { category: 'fail2ban', state: 'agent_required', observed_at: null, received_at: null, clock_skew_ms: 0, data: null, agent: null } }
    } })
    renderSec('/security/v1')
    await userEvent.click(await screen.findByRole('button', { name: 'Создать агента' }))
    expect(await screen.findByText(/echo 'AGENTID\.SECRETVALUE'/)).toBeInTheDocument()
    expect(screen.getByText(/useradd --system/)).toBeInTheDocument()
    expect(screen.getByText(/systemctl enable --now remnascope-secagent/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Секрет сохранён' }))
    expect(screen.queryByText(/AGENTID\.SECRETVALUE/)).toBeNull()
    expect(await screen.findByText('ожидает первого подключения')).toBeInTheDocument()
  })
})
