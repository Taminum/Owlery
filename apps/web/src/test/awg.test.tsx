import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Awg from '../pages/Awg'
import { SourceMarks, hasAwg } from '../components/SourceMarks'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderAwg() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/awg']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="awg" element={<Awg />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString()
const peer = (over: object) => ({ id: 'p1', label: 'RouterOne', tunnel_ip: '10.8.1.2/32', key_short: 'AAAA11…111=', state: 'active', handshake_at: ago(60), first_seen: ago(9999), gone: false, download_total: 5e9, upload_total: 1e9, download_range: 2e9, upload_range: 1e8, total_download: 113e9, total_upload: 51e9, total_since: ago(200 * 86400), last_seen_at: ago(60), last_seen_source: 'live', ...over })
const inst = (over: object) => ({ id: 'i1', container: 'amnezia-awg2', interface: 'awg0', port: 49587, variant: 'AWG 2.0', mode: 'read_only', last_report: ago(20), report_fresh: true, counters_since: ago(6 * 86400), peers: [peer({}), peer({ id: 'p2', label: 'old', state: 'never', handshake_at: null, download_range: 0, upload_range: 0 })], ...over })

describe('AmneziaWG page', () => {
  it('shows servers, states, directions and the caveats that keep the numbers honest', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [inst({})], period: '24h0m0s' } } : undefined) })
    renderAwg()
    expect(await screen.findByText('amnezia-awg2 · awg0')).toBeInTheDocument()
    expect(screen.getByText(/порт 49587/)).toBeInTheDocument()
    expect(screen.getByText(/набор параметров: AWG 2.0/)).toBeInTheDocument()
    expect(screen.getByText(/только чтение/)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'amnezia-awg2 awg0' })
    expect(within(table).getByText('на связи')).toBeInTheDocument()
    expect(within(table).getByText('не подключалось')).toBeInTheDocument()
    expect(within(table).getByText('RouterOne')).toBeInTheDocument()
    expect(screen.getAllByText(/с точки зрения устройства/).length).toBeGreaterThan(0)
    expect(screen.getByText(/не обязательно значит обрыв/)).toBeInTheDocument()
  })

  it('says "no data" instead of numbers when the collector stopped reporting', async () => {
    const stale = inst({ report_fresh: false, last_report: ago(3600), peers: [peer({ state: 'unknown', label: 'RouterOne' })] })
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [stale], period: '24h0m0s' } } : undefined) })
    renderAwg()
    expect(await screen.findByText(/Сборщик давно не отправлял данные/)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'amnezia-awg2 awg0' })
    expect(within(table).getByText('нет данных')).toBeInTheDocument()
    const cells = within(within(table).getByText('RouterOne').closest('tr') as HTMLElement).getAllByRole('cell')
    expect(cells[4]).toHaveTextContent('—') // the period is not shown as zero when nothing is reported
  })

  it('opens a peer to see its traffic over time, and explains an empty database', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/awg') return { status: 200, body: { instances: [inst({})], period: '24h0m0s' } }
      if (r.path.startsWith('/api/v1/awg/peers/')) return { status: 200, body: { bucket_seconds: 3600, from: ago(86400), to: ago(0), points: [] } }
      return undefined
    } })
    renderAwg()
    await userEvent.click(await screen.findByRole('button', { name: 'RouterOne' }))
    expect(await screen.findByText('За этот период данных нет.')).toBeInTheDocument()
  })

  it('explains what to do when nothing is connected yet', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [], period: '24h0m0s' } } : undefined) })
    renderAwg()
    expect(await screen.findByText(/Нужен агент AmneziaWG/)).toBeInTheDocument()
  })

  it('shows one running total with its start, a last-seen date for a quiet device, and no mention of the old panel', async () => {
    const quiet = peer({ id: 'p9', label: 'tablet', state: 'stale', handshake_at: null, last_seen_at: ago(36 * 86400), last_seen_source: 'panel', total_download: 83e9, total_upload: 2e9, total_since: ago(180 * 86400) })
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [inst({ peers: [peer({}), quiet] })], period: '24h0m0s' } } : undefined) })
    renderAwg()
    expect(await screen.findByText('Всего (скачано · отправлено)')).toBeInTheDocument()
    const row0 = within(screen.getByText('RouterOne').closest('tr') as HTMLElement)
    expect(screen.queryByText('Считаем с')).not.toBeInTheDocument() // not a column: the date is a hint on the total
    expect(row0.getByTitle(/Считаем с \d/)).toBeInTheDocument()
    expect(screen.queryByText(/Раньше/)).not.toBeInTheDocument()
    expect(screen.queryByText(/по данным панели Amnezia/)).not.toBeInTheDocument()
    const row = within(screen.getByText('tablet').closest('tr') as HTMLElement)
    expect(row.getByText('давно не было')).toBeInTheDocument() // seen before: not "never"
    expect(row.getAllByText(/↓ (7|8)\d/).length).toBeGreaterThan(0) // its total, shown directly (not on hover)
    expect(screen.getByText(/Счётчики самого сервера идут с/)).toBeInTheDocument()
    expect(screen.getByText(/считает RemnaScope по счётчикам сервера/)).toBeInTheDocument() // the one honest caveat about the total
  })

  it('lets the owner remove a device that is gone, and only such a device', async () => {
    const calls: Req[] = []
    const gone = peer({ id: 'g1', label: 'old-phone', gone: true, state: 'stale' })
    mockApi({ me: owner, handler: (r: Req) => {
      calls.push(r)
      if (r.path === '/api/v1/awg') return { status: 200, body: { instances: [inst({ peers: [peer({}), gone] })], period: '24h0m0s' } }
      if (r.path === '/api/v1/awg/peers/g1' && r.method === 'DELETE') return { status: 204, body: null }
      return undefined
    } })
    renderAwg()
    await screen.findByText('old-phone')
    expect(screen.getAllByRole('button', { name: /Убрать/ })).toHaveLength(1) // not offered for a device that is still on the server
    await userEvent.click(screen.getByRole('button', { name: 'Убрать: old-phone' }))
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/api/v1/awg/peers/g1')).toBe(true)
  })
})

describe('AmneziaWG device management', () => {
  const managed = () => inst({ mode: 'managed', peers: [peer({}), peer({ id: 'g1', label: 'old', gone: true, state: 'stale' })] })

  it('offers adding, renaming and revoking only for a managed server, and only to the owner', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [managed(), inst({ id: 'i2', container: 'read-only-one', mode: 'read_only' })], period: '24h0m0s' } } : undefined) })
    renderAwg()
    await screen.findByText('amnezia-awg2 · awg0')
    expect(screen.getAllByRole('button', { name: 'Добавить устройство' })).toHaveLength(1) // not for the read-only server
    expect(screen.getAllByRole('button', { name: /^Отозвать: / }).length).toBe(1) // not for the gone device, not on the read-only server
    expect(screen.getAllByRole('button', { name: /^Переименовать: / }).length).toBeGreaterThanOrEqual(2)
  })

  it('shows the new device configuration once, with a warning, and sends only a valid name', async () => {
    const calls: Req[] = []
    mockApi({ me: owner, handler: (r: Req) => {
      calls.push(r)
      if (r.path === '/api/v1/awg') return { status: 200, body: { instances: [managed()], period: '24h0m0s' } }
      if (r.path === '/api/v1/awg/instances/i1/peers' && r.method === 'POST') return { status: 201, body: { name: 'Pixel 8', key_short: 'NEWK11…111=', tunnel_ip: '10.8.1.9', filename: 'Pixel_8.conf', config: '[Interface]\nPrivateKey = CLIENTSECRET\nAddress = 10.8.1.9/32\n' } }
      return undefined
    } })
    renderAwg()
    await userEvent.click(await screen.findByRole('button', { name: 'Добавить устройство' }))
    const field = screen.getByLabelText('Название')
    const create = screen.getByRole('button', { name: 'Добавить' })
    expect(create).toBeDisabled()
    await userEvent.type(field, 'bad;name')
    expect(create).toBeDisabled() // an invalid name is not even sent
    await userEvent.clear(field)
    await userEvent.type(field, 'Pixel 8')
    await userEvent.click(create)
    expect(await screen.findByText(/добавлено/)).toBeInTheDocument()
    expect(screen.getByText(/показывается один раз/)).toBeInTheDocument()
    expect((screen.getByLabelText('Конфигурация устройства') as HTMLTextAreaElement).value).toContain('PrivateKey = CLIENTSECRET')
    expect(calls.filter((c) => c.method === 'POST')[0].body).toEqual({ name: 'Pixel 8' })
    // closing forgets it: nothing of it is left on the page
    await userEvent.click(screen.getByRole('button', { name: 'Готово, сохранил' }))
    expect(screen.queryByText(/CLIENTSECRET/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Конфигурация устройства')).not.toBeInTheDocument()
  })

  it('asks before revoking, and says plainly when the host refuses', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/awg') return { status: 200, body: { instances: [managed()], period: '24h0m0s' } }
      if (r.path === '/api/v1/awg/peers/p1/revoke') return { status: 409, body: { code: 'awg_busy', message: 'x' } }
      return undefined
    } })
    renderAwg()
    await userEvent.click(await screen.findByRole('button', { name: 'Отозвать: RouterOne' }))
    expect(screen.getByText(/перестанет подключаться/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Отозвать' }))
    expect(await screen.findByText(/занят другим изменением/)).toBeInTheDocument()
  })
})

describe('source marks in Sites and Domains', () => {
  it('names where the traffic of a row was seen, in a fixed order, and says nothing for a row without sources', () => {
    const { container, rerender } = render(<SourceMarks sources={['awg', 'node']} />)
    const marks = Array.from(container.querySelectorAll('span > span')).map((x) => x.textContent)
    expect(marks).toEqual(['узлы', 'AmneziaWG'])
    expect(screen.getByTitle(/датчиком на сервере AmneziaWG/)).toBeInTheDocument()
    rerender(<SourceMarks sources={[]} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<SourceMarks />)
    expect(container).toBeEmptyDOMElement()
  })

  it('knows when a list holds AmneziaWG rows, so its caveats can be shown once under the table', () => {
    expect(hasAwg([{ sources: ['node'] }, { sources: ['router', 'awg'] }])).toBe(true)
    expect(hasAwg([{ sources: ['node'] }, {}])).toBe(false)
  })
})
