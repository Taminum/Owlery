import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Intel from '../pages/Intel'
import { DnsMapDetail } from '../pages/DnsMap'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderAt(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="intel" element={<Intel />} />
            <Route path="intel/dns/:id" element={<DnsMapDetail />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const run = (over: object = {}) => ({
  id: 'r1', trigger: 'schedule', started_at: '2026-10-15T12:00:00Z', finished_at: '2026-10-15T12:00:20Z', status: 'ok', mismatch: [], error: null,
  coverage: { discovery: 'known_names', names_total: 3, names_checked: 3, names_dropped: 0, types: ['A', 'MX'], resolvers: ['1.1.1.1:53', '8.8.8.8:53'], questions: 14, failures: 1, unconfirmed: 2, dnssec: 'not_checked', authoritative_asked: 2 },
  auth: [{ ns: 'ns1.example.net', addr: '203.0.113.53', answers: { SOA: { outcome: 'answer', aa: true } } }, { ns: 'ns2.example.net', skipped: 'not_public' }], ...over,
})

const map = (over: object = {}) => ({
  id: 'm1', domain: 'example.com', display: 'example.com', enabled: true, interval_hours: 24, extra_names: [], use_ct: false, created_at: '2026-10-14T00:00:00Z',
  last_run_at: '2026-10-15T12:00:00Z', next_run_at: '2026-10-16T12:00:00Z', last_status: 'ok', baseline_done: true, last_run: run(), ...over,
})

const rec = (over: object) => ({
  name: 'example.com', type: 'A', result: 'answer', values: ['93.184.216.34'], ttl: 300, confirmed: true, last_result: 'answer',
  views: [{ server: '1.1.1.1:53', outcome: 'answer', values: ['93.184.216.34'] }, { server: '8.8.8.8:53', outcome: 'answer', values: ['93.184.216.34'] }],
  first_seen: '2026-10-14T00:00:00Z', last_seen: '2026-10-15T12:00:00Z', last_checked: '2026-10-15T12:00:00Z', last_changed: null, no_longer_observed: false, ...over,
})

describe('DNS Map', () => {
  it('lists domains and will not create one until the scope is confirmed', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps' && r.method === 'GET') return { status: 200, body: { items: [map(), map({ id: 'm2', domain: 'bad.org', display: 'bad.org', last_status: 'failed', last_run: run({ status: 'failed' }) })] } }
      if (r.path === '/api/v1/intel/dns/maps' && r.method === 'POST') return { status: 201, body: map({ id: 'm3', domain: 'new.example', display: 'new.example', last_status: null, last_run: null }) }
      if (r.path === '/api/v1/intel/dns/maps/m3') return { status: 200, body: { map: map({ id: 'm3', domain: 'new.example', display: 'new.example', last_status: null, last_run: null }), names: [] } }
    } })
    renderAt('/intel?view=dns')
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('проверка прошла')).toBeInTheDocument()
    expect(screen.getByText('не удалось проверить')).toBeInTheDocument()
    expect(screen.getByText(/Полной зоной это не называется/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Добавить домен/ }))
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Домен'), 'new.example')
    const create = within(dialog).getByRole('button', { name: 'Создать и проверить' })
    expect(create).toBeDisabled()
    await userEvent.click(within(dialog).getByLabelText(/Подтверждаю границы/))
    await userEvent.click(create)
    expect(await screen.findByRole('heading', { name: 'new.example' })).toBeInTheDocument()
    const sent = api.find('POST', '/api/v1/intel/dns/maps')[0].body as Record<string, unknown>
    expect(sent).toMatchObject({ domain: 'new.example', confirm_scope: true, use_ct: false, interval_hours: 24 })
  })

  it('says what a run covered, and never claims a whole zone or a validated DNSSEC', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps/m1') return { status: 200, body: { map: map({ last_run: run({ mismatch: ['MX'] }) }), names: [] } }
      if (r.path === '/api/v1/intel/dns/maps/m1/graph') return { status: 200, body: { nodes: [], edges: [], total_nodes: 0, truncated: false, note: '' } }
    } })
    renderAt('/intel/dns/m1')
    expect(await screen.findByText(/Имён проверено: 3 из 3/)).toBeInTheDocument()
    expect(screen.getByText(/не вся зона/)).toBeInTheDocument()
    expect(screen.getByText(/DNSSEC не проверялся/)).toBeInTheDocument()
    expect(screen.getByText(/Резолверы ответили по-разному или ответил один: 2/)).toBeInTheDocument()
    expect(screen.getByText(/расходятся с резолверами или друг с другом по записям: MX/)).toBeInTheDocument()
  })

  it('draws the observed records as a map, and opens a node', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps/m1') return { status: 200, body: { map: map(), names: [] } }
      if (r.path === '/api/v1/intel/dns/maps/m1/graph') return { status: 200, body: {
        nodes: [{ id: 'name:example.com', kind: 'name', label: 'example.com' }, { id: 'ip:93.184.216.34', kind: 'ip', label: '93.184.216.34' }, { id: 'mx:mail.example.com', kind: 'mail', label: 'mail.example.com' }],
        edges: [{ from: 'name:example.com', to: 'ip:93.184.216.34', type: 'A' }, { from: 'name:example.com', to: 'mx:mail.example.com', type: 'MX', label: 'prio 10', unverified: true }],
        total_nodes: 9, truncated: true, note: '' } }
      if (r.path === '/api/v1/intel/dns/maps/m1/records') return { status: 200, body: { items: [rec({}), rec({ type: 'MX', values: ['10 mail.example.com'] })], more: false } }
    } })
    renderAt('/intel/dns/m1')
    const node = await screen.findByRole('button', { name: 'имя example.com' })
    expect(screen.getByRole('button', { name: 'IP 93.184.216.34' })).toBeInTheDocument()
    expect(screen.getByText('Показано 3 из 9 узлов. Остальные доступны в таблице записей.')).toBeInTheDocument()
    expect(screen.getByText(/DNS ничего не говорит о хостинге/)).toBeInTheDocument()
    await userEvent.click(node)
    expect(await screen.findByText('10 mail.example.com')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'IP 93.184.216.34' }))
    expect(screen.getByRole('link', { name: 'Сведения об IP' })).toHaveAttribute('href', '/intel?target=93.184.216.34')
  })

  it('shows records with who said what, and marks an unconfirmed or vanished one', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps/m1') return { status: 200, body: { map: map(), names: [] } }
      if (r.path === '/api/v1/intel/dns/maps/m1/graph') return { status: 200, body: { nodes: [], edges: [], total_nodes: 0, truncated: false, note: '' } }
      if (r.path === '/api/v1/intel/dns/maps/m1/records') return { status: 200, body: { items: [
        rec({}),
        rec({ name: 'lag.example.com', confirmed: false, values: ['9.9.9.9'], views: [{ server: '1.1.1.1:53', outcome: 'answer', values: ['9.9.9.9'] }, { server: '8.8.8.8:53', outcome: 'answer', values: ['8.8.4.4'] }] }),
        rec({ name: 'old.example.com', result: 'nodata', values: [], no_longer_observed: true }),
        rec({ name: 'down.example.com', result: null, values: [], last_result: 'timeout', confirmed: false }),
      ], more: false } }
    } })
    renderAt('/intel/dns/m1')
    await userEvent.click(await screen.findByRole('tab', { name: 'Записи' }))
    expect(await screen.findByText('lag.example.com')).toBeInTheDocument()
    expect(screen.getAllByText('подтверждено').length).toBeGreaterThan(0)
    expect(screen.getAllByText('не подтверждено', { selector: 'span' })).toHaveLength(2)
    expect(screen.getByText('больше не наблюдается', { selector: 'span' })).toBeInTheDocument()
    // A name that could not be asked is "no answer", never an empty record.
    expect(screen.getByText('нет ответа')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'lag.example.com' }))
    expect(screen.getAllByText(/1\.1\.1\.1:53/).length).toBeGreaterThan(1)
    expect(screen.getByText((_, el) => el?.tagName === 'P' && /8\.8\.8\.8:53.*8\.8\.4\.4/.test(el.textContent ?? ''))).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '93.184.216.34' })).toHaveAttribute('href', '/intel?target=93.184.216.34')
  })

  it('shows history with before and after, and a flapping record as volatile', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps/m1') return { status: 200, body: { map: map(), names: [] } }
      if (r.path === '/api/v1/intel/dns/maps/m1/graph') return { status: 200, body: { nodes: [], edges: [], total_nodes: 0, truncated: false, note: '' } }
      if (r.path === '/api/v1/intel/dns/maps/m1/changes') return { status: 200, body: { more: false, items: [
        { id: 'c1', name: 'example.com', type: 'MX', kind: 'dns.mx_changed', before: ['10 mail.example.com'], after: ['20 mx.other.org'], observed_at: '2026-10-15T12:00:00Z', volatile: false },
        { id: 'c2', name: 'flip.example.com', type: 'A', kind: 'dns.record_added', before: [], after: ['5.5.5.1'], observed_at: '2026-10-15T11:00:00Z', volatile: true },
        { id: 'c3', name: '', type: '*', kind: 'dns.check_failed', before: [], after: [], observed_at: '2026-10-14T11:00:00Z', volatile: false },
      ] } }
    } })
    renderAt('/intel/dns/m1')
    await userEvent.click(await screen.findByRole('tab', { name: 'История' }))
    expect(await screen.findByText('почтовые серверы (MX)', { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText(/20 mx\.other\.org/)).toBeInTheDocument()
    expect(screen.getByText(/часто меняется/)).toBeInTheDocument()
    expect(screen.getByText('проверка не удалась', { selector: 'span' })).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Вид'), 'dns.ns_changed')
    await screen.findByText('почтовые серверы (MX)', { selector: 'span' })
    expect(api.calls.some((c) => c.url.includes('/changes') && c.url.includes('kind=dns.ns_changed'))).toBe(true)
  })

  it('asks for a refresh and shows the authoritative servers, including one that was not asked', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/dns/maps/m1') return { status: 200, body: { map: map(), names: [] } }
      if (r.path === '/api/v1/intel/dns/maps/m1/graph') return { status: 200, body: { nodes: [], edges: [], total_nodes: 0, truncated: false, note: '' } }
      if (r.path === '/api/v1/intel/dns/maps/m1/refresh') return { status: 202, body: { requested: true } }
      if (r.path === '/api/v1/intel/dns/maps/m1/checks') return { status: 200, body: { items: [run()] } }
    } })
    renderAt('/intel/dns/m1')
    await userEvent.click(await screen.findByRole('button', { name: 'Проверить сейчас' }))
    expect(await screen.findByText(/Проверка запрошена/)).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/intel/dns/maps/m1/refresh')).toHaveLength(1)
    await userEvent.click(screen.getByRole('tab', { name: 'Проверки' }))
    expect(await screen.findByText('ns1.example.net')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.53')).toBeInTheDocument()
    expect(screen.getByText(/адрес не публичный, не опрашивался/)).toBeInTheDocument()
  })
})
