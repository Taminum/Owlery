import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { setCsrf } from '../lib/api'
import { Maintenance, MaintenanceBanner } from '../components/Maintenance'
import { WakeButton, WakeOnLan } from '../components/WakeOnLan'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

describe('Окно обслуживания', () => {
  it('opens a window for the chosen time with a note, and the banner ends it', async () => {
    setCsrf('')
    const api = mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/servers/s1/maintenance' ? { status: 200, body: {} } : undefined) })
    const changed = vi.fn()
    render(<Maintenance serverId="s1" canEdit onChange={changed} />)
    fireEvent.change(screen.getByLabelText('Заметка (например, «обновление Windows»)'), { target: { value: 'обновление' } })
    fireEvent.click(screen.getByRole('button', { name: 'На 4 часа' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/maintenance')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/maintenance')[0].body).toEqual({ hours: 4, note: 'обновление' })
    expect(changed).toHaveBeenCalled()

    render(<MaintenanceBanner until="2026-11-07T14:30:00Z" note="обновление" canEdit serverId="s1" onChange={changed} />)
    expect(screen.getByText('Идёт обслуживание')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Закончить сейчас' }))
    await waitFor(() => expect(api.find('DELETE', '/api/v1/servers/s1/maintenance')).toHaveLength(1))
  })

  it('does not offer a window to one who cannot open it', () => {
    setCsrf('')
    mockApi({ me: owner })
    render(<Maintenance serverId="s1" canEdit={false} onChange={() => {}} />)
    expect(screen.queryByRole('button', { name: 'На 1 час' })).toBeNull()
    expect(screen.getByText(/Открывать окно может владелец/)).toBeInTheDocument()
  })
})

describe('Включение по сети', () => {
  const nics = [{ name: 'Ethernet', mac: 'aa:bb:cc:dd:ee:01', ips: ['192.168.1.5'] }, { name: 'Wi-Fi', mac: 'aa:bb:cc:dd:ee:02' }]

  it('turns on through the machine, lets a card be chosen and wakes a machine that is off', async () => {
    setCsrf('')
    let view = { enabled: false, nics: [] as typeof nics, machine_online: true, can_ask: true, helpers: 1, can_edit: true } as Record<string, unknown>
    const api = mockApi({ me: owner, handler: (r) => {
      if (r.path === '/api/v1/servers/s1/wol' && r.method === 'GET') return { status: 200, body: view }
      if (r.path === '/api/v1/servers/s1/wol' && r.method === 'PUT') { view = { ...view, enabled: true, mac: (r.body as { mac?: string }).mac ?? nics[0].mac, nics, machine_online: false }; return { status: 200, body: view } }
      if (r.path === '/api/v1/servers/s1/wake') return { status: 200, body: { ok: true } }
      return undefined
    } })
    render(<WakeOnLan serverId="s1" onChange={() => {}} />)
    fireEvent.click(await screen.findByLabelText('Разрешить включение по сети'))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/wol')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/wol')[0].body).toEqual({ enabled: true })
    expect(await screen.findByText('aa:bb:cc:dd:ee:02')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: /Wi-Fi/ }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/wol')).toHaveLength(2))
    expect(api.find('PUT', '/api/v1/servers/s1/wol')[1].body).toEqual({ enabled: true, mac: 'aa:bb:cc:dd:ee:02' })
    fireEvent.click(await screen.findByRole('button', { name: /Включить/ }))
    expect(await screen.findByText(/Сигнал отправлен/)).toBeInTheDocument()
  })

  it('says why it cannot be turned on while the machine is off or its agent is old', async () => {
    setCsrf('')
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/servers/s1/wol' ? { status: 200, body: { enabled: false, nics: [], machine_online: false, can_ask: false, helpers: 0, can_edit: true } } : undefined) })
    render(<WakeOnLan serverId="s1" onChange={() => {}} />)
    expect(await screen.findByText(/нужна более новая версия/)).toBeInTheDocument()
    expect(screen.getByLabelText('Разрешить включение по сети')).toBeDisabled()
  })

  it('shows the reason when waking fails, next to the button', async () => {
    setCsrf('')
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/servers/s1/wake' ? { status: 409, body: { code: 'no_helper', message: 'no other machine in the same network is on to send the signal', request_id: 'r' } } : undefined) })
    render(<WakeButton serverId="s1" />)
    fireEvent.click(screen.getByRole('button', { name: /Включить/ }))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })
})
