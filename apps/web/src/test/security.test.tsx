import { render, screen, within } from '@testing-library/react'
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
    const view = renderSec('/security/v1?tab=fail2ban')
    expect(await screen.findByText('Агент не создан. Без него Fail2ban, порты и firewall не видны.')).toBeInTheDocument()
    expect(await screen.findByText('нужен агент')).toBeInTheDocument()
    expect(screen.queryByText('данные получены')).toBeNull()
    view.unmount()

    agent = { id: 'a1', status: 'active', agent_version: '0.1', hostname: 'h1', capabilities: [], last_seen: new Date().toISOString(), online: true }
    f2b = cat({ state: 'ok', status: 'ok', observed_at: '2026-10-15T12:00:00Z', received_at: '2026-10-15T12:00:00Z',
      data: { jails: [{ name: 'sshd', currently_failed: 1, total_failed: 9, currently_banned: 1, total_banned: 4, banned_ips: ['203.0.113.5'] }] } })
    renderSec('/security/v1?tab=fail2ban')
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
    renderSec('/security/v1?tab=fail2ban')
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
    renderSec('/security/v1?tab=fail2ban')
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
    renderSec('/security/v1?tab=fail2ban')
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
    renderSec('/security/v1?tab=fail2ban')
    await userEvent.click(await screen.findByRole('button', { name: 'Создать агента' }))
    expect(await screen.findByText(/echo 'AGENTID\.SECRETVALUE'/)).toBeInTheDocument()
    expect(screen.getByText(/useradd --system/)).toBeInTheDocument()
    expect(screen.getByText(/systemctl enable --now remnascope-secagent/)).toBeInTheDocument()
    // The steps are complete: where the files come from, the address of this server in the unit, Fail2ban, the check.
    expect(screen.getByText(/curl -fLO https:\/\/github\.com\/Taminum\/Owlery\/releases\/latest\/download\/remnascope-secagent-linux-\$A/)).toBeInTheDocument()
    expect(screen.getByText((c) => c.includes(`wss://${window.location.host}`))).toBeInTheDocument()
    expect(screen.getByText(/fail2ban\.service\.d\/remnascope\.conf/)).toBeInTheDocument()
    expect(screen.getByText(/journalctl -u remnascope-secagent/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Секрет сохранён' }))
    expect(screen.queryByText(/AGENTID\.SECRETVALUE/)).toBeNull()
    expect(await screen.findByText('ожидает первого подключения')).toBeInTheDocument()
  })

  describe('ban and unban', () => {
    const f2b = (manage: object) => ({
      category: 'fail2ban', state: 'ok', status: 'ok', observed_at: '2026-10-15T12:00:00Z', received_at: '2026-10-15T12:00:00Z', clock_skew_ms: 0, agent: null, manage,
      data: { jails: [{ name: 'sshd', currently_failed: 0, total_failed: 3, currently_banned: 1, total_banned: 1, banned_ips: ['93.184.216.9'] }] },
    })
    const cmd = (over: object) => ({ id: 'c1', vps_id: 'v1', action: 'unban', jail: 'sshd', ip: '93.184.216.9', state: 'pending', requested_at: '2026-10-15T12:00:00Z', sent_at: null, deadline: '2026-10-15T12:00:30Z', finished_at: null, result_code: null, verified: false, final: false, ...over })
    const base = (manage: object, extra?: (r: Req) => { status: number; body?: unknown } | undefined) => mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
      if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent: null } }
      if (r.path === '/api/v1/security/vps/v1/fail2ban') return { status: 200, body: f2b(manage) }
      if (r.path === '/api/v1/security/vps/v1/commands') return { status: 200, body: { items: [] } }
      return extra?.(r)
    } })

    it('asks to confirm, sends one command and follows it to the verified end', async () => {
      const api = base({ allowed: true, ready: true }, (r) => {
        if (r.path === '/api/v1/security/vps/v1/fail2ban/unban') return { status: 202, body: { command: cmd({}) } }
        if (r.path === '/api/v1/security/commands/c1') return { status: 200, body: { command: cmd({ state: 'executed', verified: true, final: true }) } }
      })
      renderSec('/security/v1?tab=fail2ban')
      await userEvent.click(await screen.findByRole('button', { name: 'Разблокировать' }))
      expect(screen.getByText(/Адрес 93\.184\.216\.9 будет разблокирован в jail sshd/)).toBeInTheDocument()
      expect(api.find('POST', '/api/v1/security/vps/v1/fail2ban/unban')).toHaveLength(0) // nothing is sent before the confirmation
      const dialog = screen.getByRole('dialog')
      await userEvent.click(within(dialog).getByRole('button', { name: 'Разблокировать' }))
      expect(await screen.findByText('выполнено и проверено', {}, { timeout: 4000 })).toBeInTheDocument()
      const sent = api.find('POST', '/api/v1/security/vps/v1/fail2ban/unban')
      expect(sent).toHaveLength(1)
      expect(sent[0].body).toMatchObject({ jail: 'sshd', ip: '93.184.216.9', acknowledge_risk: false })
      expect(String((sent[0].body as { idempotency_key: string }).idempotency_key).length).toBeGreaterThanOrEqual(8)
    })

    it('shows the risk, needs it confirmed, and then sends the same request acknowledged', async () => {
      let n = 0
      const api = base({ allowed: true, ready: true }, (r) => {
        if (r.path === '/api/v1/security/vps/v1/fail2ban/ban') {
          n++
          return n === 1 ? { status: 409, body: { code: 'risk', message: 'x', request_id: 'r', details: { reasons: ['private_address'] } } } : { status: 202, body: { command: cmd({ action: 'ban', state: 'executed', verified: true, final: true }) } }
        }
      })
      renderSec('/security/v1?tab=fail2ban')
      await userEvent.type(await screen.findByLabelText('IP'), '10.0.0.5')
      await userEvent.click(screen.getByRole('button', { name: 'Заблокировать' }))
      const dialog = await screen.findByRole('dialog')
      await userEvent.click(within(dialog).getByRole('button', { name: 'Заблокировать' }))
      expect(await screen.findByText(/Это не публичный адрес/)).toBeInTheDocument()
      const go = within(dialog).getByRole('button', { name: 'Заблокировать' })
      expect(go).toBeDisabled()
      await userEvent.click(screen.getByLabelText('Понимаю риск, всё равно выполнить'))
      await userEvent.click(go)
      expect(await screen.findByText('выполнено и проверено')).toBeInTheDocument()
      const calls = api.find('POST', '/api/v1/security/vps/v1/fail2ban/ban')
      expect(calls).toHaveLength(2)
      expect(calls[1].body).toMatchObject({ acknowledge_risk: true })
      expect((calls[1].body as { idempotency_key: string }).idempotency_key).toBe((calls[0].body as { idempotency_key: string }).idempotency_key)
    })

    it('says an unanswered command is unknown, not done', async () => {
      base({ allowed: true, ready: true }, (r) => {
        if (r.path === '/api/v1/security/vps/v1/fail2ban/unban') return { status: 202, body: { command: cmd({ state: 'unknown', final: true }) } }
      })
      renderSec('/security/v1?tab=fail2ban')
      await userEvent.click(await screen.findByRole('button', { name: 'Разблокировать' }))
      await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Разблокировать' }))
      expect(await screen.findByText('результат неизвестен')).toBeInTheDocument()
      expect(screen.getByText(/Это не значит ни «выполнено», ни «не выполнено»/)).toBeInTheDocument()
    })

    it('offers no controls to someone who may not manage, and explains why they are off when the agent cannot take a command', async () => {
      base({ allowed: false, ready: false, reason: 'not_owner' })
      const first = renderSec('/security/v1?tab=fail2ban')
      expect(await screen.findByText('sshd')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Разблокировать' })).toBeNull()
      expect(screen.queryByLabelText('IP')).toBeNull()
      first.unmount()

      base({ allowed: true, ready: false, reason: 'agent_offline' })
      renderSec('/security/v1?tab=fail2ban')
      expect(await screen.findByText(/Агент не на связи: команда не отправляется и не ставится в очередь/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Разблокировать' })).toBeDisabled()
    })
  })

  describe('server cards', () => {
    const card = (id: string, name: string, summary: object) => vps({ id, name, summary })
    it('shows how many addresses Fail2ban has blocked, and says when there is no agent or the data is old', async () => {
      mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/security/vps' ? { status: 200, body: { can_create: true, items: [
        card('a', 'Live', { agent: 'online', fail2ban: { state: 'ok', banned: 7, total_banned: 412, jails: 2, observed_at: '2026-10-15T12:00:00Z' } }),
        card('b', 'Old', { agent: 'offline', fail2ban: { state: 'stale', banned: 3, total_banned: 20, jails: 1, observed_at: '2026-10-15T09:00:00Z' } }),
        card('c', 'Bare', { agent: 'none', fail2ban: { state: 'agent_required', banned: 0, total_banned: 0, jails: 0, observed_at: null } }),
        card('d', 'Denied', { agent: 'online', fail2ban: { state: 'permission_denied', banned: 0, total_banned: 0, jails: 0, observed_at: null } }),
      ] } } : undefined) })
      renderSec('/security')
      expect(await screen.findByText('заблокировано сейчас: 7')).toBeInTheDocument()
      expect(screen.getByText(/за всё время: 412/)).toBeInTheDocument()
      expect(screen.getByText(/данные устарели: 3/)).toBeInTheDocument()
      expect(screen.getByText('нужен агент')).toBeInTheDocument()
      expect(screen.getByText('нет прав на чтение')).toBeInTheDocument()
      // No number is invented for a server that cannot be read.
      expect(screen.queryByText('заблокировано сейчас: 0')).toBeNull()
    })
  })
})

describe('Security overview', () => {
  const ov = (over: object) => ({
    health: 'unknown', reasons: [], agent: 'none',
    categories: { fail2ban: { state: 'agent_required', observed_at: null }, sockets: { state: 'agent_required', observed_at: null }, firewall: { state: 'agent_required', observed_at: null } },
    checks: { ports_total: 0, ports_unexpected: 0, ports_down: 0, tls_total: 0, tls_problems: 0, tls_nearest_end: null, last_checked_at: null },
    last_event: null, events_24h: 0, ...over,
  })
  const run = (body: object) => mockApi({ me: owner, handler: (r: Req) => {
    if (r.path === '/api/v1/security/vps/v1') return { status: 200, body: vps() }
    if (r.path === '/api/v1/security/vps/v1/agent') return { status: 200, body: { agent: null } }
    if (r.path === '/api/v1/security/vps/v1/overview') return { status: 200, body }
  } })

  it('says there is nothing to judge by instead of calling a server with no data healthy', async () => {
    run(ov({}))
    renderSec('/security/v1')
    expect((await screen.findAllByText('Данных пока нет')).length).toBeGreaterThan(0)
    expect(screen.queryByText('Всё в порядке')).toBeNull()
  })

  it('lists the reasons for attention', async () => {
    run(ov({ health: 'attention', reasons: [{ code: 'port_unexpected' }, { code: 'tls_problem' }], checks: { ports_total: 2, ports_unexpected: 1, ports_down: 0, tls_total: 1, tls_problems: 1, tls_nearest_end: null, last_checked_at: '2026-10-15T12:00:00Z' } }))
    renderSec('/security/v1')
    expect(await screen.findByText('Порт отвечает снаружи, но не отмечен как ожидаемый.')).toBeInTheDocument()
    expect(screen.getByText('Есть сертификат с проблемой или скорым окончанием срока.')).toBeInTheDocument()
  })
})
