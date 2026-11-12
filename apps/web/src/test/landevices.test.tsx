import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import LanDevices from '../pages/LanDevices'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderPage() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/lan']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="lan" element={<LanDevices />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const now = new Date().toISOString()
const devices = [
  { mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.88.20', host: 'home-pc', name: 'Компьютер', source: 'Дом', first_seen: now, last_seen: now, confirmed: true, seen: true },
  { mac: '3C:22:FB:11:90:AB', ip: '192.168.88.141', source: 'Дом', first_seen: now, last_seen: now, confirmed: false, seen: true },
  { mac: '00:1B:A9:6E:12:30', ip: '192.168.0.215', name: 'Принтер', source: 'Работа', first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-09T00:00:00Z', confirmed: true, seen: false },
]

describe('Устройства в сети', () => {
  it('lists devices, marks the new one and filters', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/lan-devices' ? { status: 200, body: { devices } } : undefined) })
    renderPage()
    expect(await screen.findByText('Компьютер')).toBeInTheDocument()
    expect(screen.getByText('новое')).toBeInTheDocument()
    expect(screen.getByText('Принтер')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Новые' }))
    expect(screen.queryByText('Компьютер')).toBeNull()
    expect(screen.getByText('192.168.88.141')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Пропавшие' }))
    expect(screen.getByText('Принтер')).toBeInTheDocument()
    expect(screen.queryByText('192.168.88.141')).toBeNull()
  })

  it('names a new device, which confirms it', async () => {
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.method === 'PATCH') { sent = `${r.path} ${JSON.stringify(r.body)}`; return { status: 204, body: null } }
        if (r.path === '/api/v1/lan-devices') return { status: 200, body: { devices } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Это моё, назвать' }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Телефон' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(sent).toContain('"name":"Телефон"'))
    expect(sent).toContain('3C%3A22%3AFB%3A11%3A90%3AAB')
  })
})
