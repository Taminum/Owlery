import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Intel from '../pages/Intel'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderIntel(url: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[url]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="intel" element={<Intel />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const meta = { fetched_at: '2026-10-14T12:00:00Z', expires_at: '2026-10-14T12:10:00Z', cached: false, vantage: 'server' }
const domain = {
  kind: 'domain', target: 'example.com', display: 'example.com', ...meta, sources: [{ name: 'system-dns', ok: true }, { name: 'rdap', ok: false, error: 'timeout' }],
  data: {
    dns: { a: ['93.184.216.34'], aaaa: [], mx: [{ host: 'mail.example.com', priority: 10 }], ns: ['ns1.example.com'], txt: ['v=spf1 -all'] },
    ips: [{ ip: '93.184.216.34', version: 4, public: true, owner: 'Edgecast', asn: 15133, country: 'US' }],
  },
}

describe('network intelligence', () => {
  it('opens with a prefilled target, says where the data comes from, and keeps the owner of a range apart from the service', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/intel/lookup' ? { status: 200, body: domain } : undefined) })
    renderIntel('/intel?target=example.com')
    expect((await screen.findAllByText('93.184.216.34')).length).toBeGreaterThan(0)
    expect(screen.getByText(/Проверено .* с сервера/)).toBeInTheDocument()
    expect(screen.getByText('system-dns')).toBeInTheDocument()
    expect(screen.getByText(/rdap: Не ответил вовремя/)).toBeInTheDocument() // a failed source is shown, not hidden
    expect(screen.getByText('Владелец диапазона')).toBeInTheDocument()
    expect(screen.getByText(/а не сайт/)).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((x) => x.textContent)).toEqual(['Обзор', 'DNS', 'Поддомены', 'Ping', 'Трассировка', 'Порты', 'TLS', 'HTTP'])
  })

  it('runs active checks only when asked, and shows a refusal for a non-public address as a message', async () => {
    const calls: Req[] = []
    mockApi({ me: owner, handler: (r: Req) => {
      calls.push(r)
      if (r.path === '/api/v1/intel/lookup') return { status: 200, body: { kind: 'ip', target: '8.8.8.8', display: '8.8.8.8', ...meta, sources: [{ name: 'dbip-asn', ok: true }], data: { ip: '8.8.8.8', version: 4, public: true } } }
      if (r.path === '/api/v1/intel/ping') return { status: 200, body: { kind: 'ping', target: '8.8.8.8', display: '8.8.8.8', ...meta, sources: [{ name: 'icmp', ok: false, error: 'not_public' }], data: null } }
      return undefined
    } })
    renderIntel('/intel?target=8.8.8.8')
    await userEvent.click(await screen.findByRole('tab', { name: 'Ping' }))
    expect(calls.some((c) => c.path === '/api/v1/intel/ping')).toBe(false) // nothing is sent until the button is pressed
    await userEvent.click(screen.getByRole('button', { name: 'Запустить' }))
    await waitFor(() => expect(screen.getAllByText(/Адрес не публичный/).length).toBeGreaterThan(0))
  })

  it('shows a clear error for an invalid target', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/intel/lookup' ? { status: 422, body: { code: 'not_public', message: 'внутреннее имя: во внешнем интернете его нет' } } : undefined) })
    renderIntel('/intel?target=router.lan')
    expect(await screen.findByRole('alert')).toHaveTextContent(/внутреннее имя или непубличный адрес/)
  })

  it('shows a route with silent hops and a certificate that is not trusted, each with its caveat', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/intel/lookup') return { status: 200, body: { kind: 'ip', target: '8.8.8.8', display: '8.8.8.8', ...meta, sources: [{ name: 'dbip-asn', ok: true }], data: { ip: '8.8.8.8', version: 4, public: true } } }
      if (r.path === '/api/v1/intel/trace') return { status: 200, body: { kind: 'trace', target: '8.8.8.8', display: '8.8.8.8', ...meta, sources: [{ name: 'icmp-ttl', ok: true }], data: { address: '8.8.8.8', reached: false, hops: [{ ttl: 1, addr: '192.168.1.1', rtt_ms: [1.1, 1.2, 1.3], lost: 0, reached: false }, { ttl: 2, rtt_ms: [], lost: 3, reached: false }] } } }
      if (r.path === '/api/v1/intel/tls') return { status: 200, body: { kind: 'tls', target: '8.8.8.8', display: '8.8.8.8', ...meta, sources: [{ name: 'tls', ok: true }], data: { address: '8.8.8.8', port: 443, version: 'TLS 1.3', cipher: 'TLS_AES_128_GCM_SHA256', verified: false, verify_error: 'untrusted', handshake_ms: 30, chain: [{ subject: 'CN=x', issuer: 'CN=x', not_before: '2026-01-01T00:00:00Z', not_after: '2026-12-31T00:00:00Z', days_left: 79, serial: '01', sig_alg: 'ECDSA-SHA256', key_type: 'ECDSA P-256', ca: false }] } } }
      return undefined
    } })
    renderIntel('/intel?target=8.8.8.8')
    await userEvent.click(await screen.findByRole('tab', { name: 'Трассировка' }))
    await userEvent.click(screen.getByRole('button', { name: 'Запустить' }))
    expect(await screen.findByText('192.168.1.1')).toBeInTheDocument()
    expect(screen.getByText('нет ответа')).toBeInTheDocument()
    expect(screen.getByText(/Это маршрут от сервера Owlery/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'TLS' }))
    await userEvent.click(screen.getByRole('button', { name: 'Запустить' }))
    expect(await screen.findByText(/Сертификат не прошёл проверку: выдан неизвестным центром/)).toBeInTheDocument()
    expect(screen.getByText(/осталось дней: 79/)).toBeInTheDocument()
  })
})
