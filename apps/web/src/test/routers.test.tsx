import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Routers from '../pages/Routers'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderPage(path = '/routers') {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="routers" element={<Routers />} />
            <Route path="routers/:id" element={<Routers />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const device = (over: object = {}) => ({
  id: 'd1', name: 'Дом', kind: 'mikrotik', created_at: '2026-11-12T00:00:00Z', online: true, last_seen: new Date().toISOString(),
  view: {
    board: 'hAP ax3', version: '7.16', uptime: 86400, cpu: 7, mem_free: 600, mem_total: 1000, temp: 47, stats_at: new Date().toISOString(),
    ifaces: [{ name: 'ether1', rx: 2e9, tx: 1e9, up: true, rx_bps: 1.5e6, tx_bps: 3e5 }],
    clients: [{ ip: '192.168.88.20', mac: 'AA:BB:CC:DD:EE:01', host: 'home-pc' }],
  },
  ...over,
})

describe('Роутеры', () => {
  it('shows the state, the ports and the clients of a router', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device()] } } : undefined) })
    renderPage('/routers/d1')
    expect(await screen.findByText('Дом')).toBeInTheDocument()
    expect(screen.getByText('на связи')).toBeInTheDocument()
    expect(screen.getByText('7%')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
    expect(screen.getByText('47 °C')).toBeInTheDocument()
    expect(screen.getByText('ether1')).toBeInTheDocument()
    expect(screen.getByText('home-pc')).toBeInTheDocument()
    expect(screen.getByText('192.168.88.20')).toBeInTheDocument()
  })

  it('says so when a router has gone quiet or has never reported', async () => {
    mockApi({
      me: owner,
      handler: (r) =>
        r.path === '/api/v1/net-devices'
          ? { status: 200, body: { devices: [device({ online: false, last_seen: '2026-11-12T01:00:00Z' }), device({ id: 'd2', name: 'Дача', online: false, last_seen: null, view: { board: '', version: '', uptime: 0, cpu: 0, mem_free: 0, mem_total: 0, ifaces: [], clients: [] } })] } }
          : undefined,
    })
    const first = renderPage('/routers/d1')
    expect(await screen.findByText('не отвечает')).toBeInTheDocument()
    first.unmount()
    renderPage('/routers/d2')
    expect(await screen.findByText('ещё не присылал данные')).toBeInTheDocument()
    expect(screen.getByText(/Клиентов нет/)).toBeInTheDocument()
  })

  it('shows connections and NAT rules', async () => {
    const base = device()
    const view = { ...base.view, conn: 812, conn_max: 16384, top: [{ ip: '192.168.88.20', n: 300 }], nat: [{ chain: 'dstnat', action: 'dst-nat', packets: 5, bytes: 300, dst_port: '8080', to_addr: '192.168.88.20', to_ports: '80', comment: 'web' }] }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device({ view })] } } : undefined) })
    renderPage('/routers/d1')
    expect(await screen.findByText('812')).toBeInTheDocument()
    expect(screen.getByText('из 16384 возможных')).toBeInTheDocument()
    expect(screen.getByText('300')).toBeInTheDocument()
    expect(screen.getByText('dstnat · dst-nat')).toBeInTheDocument()
    expect(screen.getByText(':8080 → 192.168.88.20:80')).toBeInTheDocument()
  })

  it('folds ports without a cable away until asked', async () => {
    const base = device()
    const ifaces = [...base.view.ifaces, { name: 'ether5', rx: 0, tx: 0, up: false, rx_bps: 0, tx_bps: 0 }]
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device({ view: { ...base.view, ifaces } })] } } : undefined) })
    renderPage('/routers/d1')
    expect(await screen.findByText('ether1')).toBeInTheDocument()
    expect(screen.queryByText('ether5')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Ещё 1 без кабеля/ }))
    expect(screen.getByText('ether5')).toBeInTheDocument()
  })

  it('renames a router', async () => {
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/d1' && r.method === 'PATCH') { sent = JSON.stringify(r.body); return { status: 204, body: null } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [device({ name: 'Дои' })] } }
        return undefined
      },
    })
    renderPage('/routers/d1')
    fireEvent.click(await screen.findByRole('button', { name: 'Переименовать' }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Дом' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(sent).toBe('{"name":"Дом"}'))
  })

  it('lists routers as small cards, problems first, filters them by group, and opens one', async () => {
    const ok = device({ id: 'a', name: 'Дом', group: 'Дом' })
    const work = device({ id: 'b', name: 'Офис', group: 'Работа' })
    const down = device({ id: 'c', name: 'Склад', group: 'Работа', online: false })
    const loose = device({ id: 'e', name: 'Гараж' })
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [ok, work, down, loose] } } : undefined) })
    renderPage()
    await screen.findByText('Склад')
    const names = () => screen.getAllByRole('link').map((a) => a.textContent ?? '').filter((x) => /Дом|Офис|Склад|Гараж/.test(x))
    expect(names()[0]).toContain('Склад') // the one that does not answer comes first
    expect(screen.queryByText('Порты')).toBeNull() // the whole card is on its own page
    fireEvent.click(screen.getByRole('button', { name: 'Работа' }))
    expect(names()).toHaveLength(2)
    expect(screen.queryByText('Гараж')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Без группы' }))
    expect(names()).toHaveLength(1)
    fireEvent.click(within(screen.getByRole('group', { name: 'Группы роутеров' })).getByRole('button', { name: 'Все' }))
    fireEvent.click(screen.getByRole('button', { name: 'Есть проблемы' }))
    expect(names()).toHaveLength(1)
    expect(screen.getByRole('link', { name: /Склад/ })).toHaveAttribute('href', '/routers/c')
  })

  it('filters the routers by brand, and every card has the same shape', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device({ id: 'a', name: 'Дом' }), device({ id: 'k', name: 'Профит', kind: 'keenetic' }), device({ id: 'o', name: 'Дача', kind: 'openwrt' })] } } : undefined) })
    renderPage()
    await screen.findByText('Профит')
    expect(screen.getAllByText('без замечаний')).toHaveLength(3)
    const brands = within(screen.getByRole('group', { name: 'Марка роутера' }))
    fireEvent.click(brands.getByRole('button', { name: 'Keenetic' }))
    expect(screen.getByText('Профит')).toBeInTheDocument()
    expect(screen.queryByText('Дом')).toBeNull()
    expect(screen.queryByText('Дача')).toBeNull()
    fireEvent.click(brands.getByRole('button', { name: 'Все' }))
    expect(screen.getByText('Дача')).toBeInTheDocument()
  })

  it('puts a router in a group', async () => {
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/d1' && r.method === 'PATCH') { sent = JSON.stringify(r.body); return { status: 204 } }
        return r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device()] } } : undefined
      },
    })
    renderPage('/routers/d1')
    fireEvent.click(await screen.findByRole('button', { name: 'Группа' }))
    fireEvent.change(screen.getByLabelText('Группа', { selector: 'input' }), { target: { value: ' Работа ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(sent).toBe('{"group":"Работа"}'))
  })

  it('creates a router and shows the script with its token once', async () => {
    const made = { token: 'd9.secretsecretsecretsecret', script: ':local hdr "Authorization: Bearer d9.secretsecretsecretsecret"', device: { name: 'Новый' } }
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') return { status: 201, body: made }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Новый' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByText(/Bearer d9\.secretsecretsecretsecret/)).toBeInTheDocument()
    expect(screen.getByText(/System → Scripts → Add/)).toBeInTheDocument()
  })
})

describe('Роутеры: OpenWrt', () => {
  it('asks for the kind and shows the ssh steps without a MikroTik scheduler command', async () => {
    const made = { token: 'd9.secretsecretsecretsecret', script: 'cat > /usr/bin/owlery-report.sh', device: { name: 'RouteRich', kind: 'openwrt' } }
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') { sent = JSON.stringify(r.body); return { status: 201, body: made } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Тип роутера'), { target: { value: 'openwrt' } })
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'RouteRich' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByText(/по SSH/)).toBeInTheDocument()
    expect(sent).toBe('{"name":"RouteRich","kind":"openwrt"}')
    expect(screen.queryByText(/System → Scripts/)).toBeNull()
    expect(screen.queryByText(/system scheduler add/)).toBeNull()
  })
})

describe('Роутеры: Keenetic', () => {
  it('asks for the address, the user and the password, sends them once and does not show a script', async () => {
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') { sent = JSON.stringify(r.body); return { status: 201, body: { device: { name: 'Рабочий', kind: 'keenetic' } } } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Тип роутера'), { target: { value: 'keenetic' } })
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Рабочий' } })
    expect(screen.getByRole('button', { name: 'Создать' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Адрес роутера'), { target: { value: ' profite.keenetic.pro ' } })
    fireEvent.change(screen.getByLabelText('Пользователь'), { target: { value: 'Test' } })
    fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    await vi.waitFor(() => expect(sent).toBe('{"name":"Рабочий","kind":"keenetic","url":"profite.keenetic.pro","login":"Test","password":"pw"}'))
    expect(screen.queryByText(/Токен показывается/)).toBeNull()
  })

  it('says why a router was refused, in words', async () => {
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') return { status: 422, body: { code: 'router_auth', message: 'x', request_id: 'r' } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Тип роутера'), { target: { value: 'keenetic' } })
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Рабочий' } })
    fireEvent.change(screen.getByLabelText('Адрес роутера'), { target: { value: 'a.keenetic.link' } })
    fireEvent.change(screen.getByLabelText('Пользователь'), { target: { value: 'Test' } })
    fireEvent.change(screen.getByLabelText('Пароль'), { target: { value: 'bad' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByText(/Роутер не принял логин или пароль/)).toBeInTheDocument()
  })

  it('shows where a Keenetic is asked and why the last ask failed, and changes the password', async () => {
    let sent = ''
    const k = device({ id: 'k1', name: 'Рабочий', kind: 'keenetic', url: 'https://profite.keenetic.pro', pull_error: 'auth', online: false, last_seen: '2026-11-12T01:00:00Z' })
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/k1' && r.method === 'PATCH') { sent = JSON.stringify(r.body); return { status: 204, body: null } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [k] } }
        return undefined
      },
    })
    renderPage('/routers/k1')
    expect(await screen.findByText('роутер не принял пароль')).toBeInTheDocument()
    expect(screen.getByText(/profite\.keenetic\.pro/)).toBeInTheDocument()
    expect(screen.getByText(/KeeneticOS 7\.16/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Сменить пароль' }))
    fireEvent.change(screen.getByLabelText('Новый пароль'), { target: { value: 'fresh' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(sent).toBe('{"password":"fresh"}'))
  })

  it('opens a port on a Keenetic and takes one away, and says why when the router refuses', async () => {
    const calls: string[] = []
    let refuse = true
    const nat = [{ chain: 'dstnat', action: 'forward tcp', packets: -1, bytes: -1, dst_port: '8001', to_addr: '192.168.88.20', to_ports: '8001', comment: 'NVR', ref: 'ab12' }, { chain: 'dstnat', action: 'upnp udp', packets: 1, bytes: 2, dst_port: '5000', to_addr: '192.168.88.20', comment: 'app' }]
    const k = device({ id: 'k1', name: 'Рабочий', kind: 'keenetic', url: 'https://p.keenetic.pro' })
    ;(k.view as { nat?: unknown }).nat = nat
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/k1/forwards' && r.method === 'POST') {
          calls.push('POST ' + JSON.stringify(r.body))
          if (refuse) { refuse = false; return { status: 422, body: { code: 'forbidden', message: 'x', request_id: 'r' } } }
          return { status: 204 }
        }
        if (r.path === '/api/v1/net-devices/k1/forwards/ab12' && r.method === 'DELETE') { calls.push('DELETE'); return { status: 204 } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [k] } }
        return undefined
      },
    })
    renderPage('/routers/k1')
    await screen.findByText('Рабочий')
    expect(screen.getAllByRole('button', { name: 'Закрыть порт' })).toHaveLength(1) // only the forward Owlery may remove, not the UPnP one
    fireEvent.click(screen.getByRole('button', { name: 'Открыть порт' }))
    const dialog = within(screen.getByRole('dialog'))
    const open = dialog.getByRole('button', { name: 'Открыть порт' })
    expect(open).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Порт снаружи'), { target: { value: '8080' } })
    fireEvent.change(screen.getByLabelText('Порт на устройстве (если другой)'), { target: { value: '80' } })
    fireEvent.change(screen.getByLabelText('Заметка'), { target: { value: 'web' } })
    fireEvent.click(open)
    expect(await screen.findByText(/нет права менять настройки/)).toBeInTheDocument()
    fireEvent.click(open)
    await vi.waitFor(() => expect(calls).toHaveLength(2))
    expect(calls[1]).toBe('POST {"protocol":"tcp","port":8080,"to_addr":"192.168.88.20","to_port":80,"comment":"web"}')
    await vi.waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    fireEvent.click(screen.getByRole('button', { name: 'Закрыть порт' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Закрыть порт' }))
    await vi.waitFor(() => expect(calls.at(-1)).toBe('DELETE'))
  })

  it('restarts a Keenetic, keeps an address, blocks and lets back a device, and switches a forward off', async () => {
    const calls: string[] = []
    const k = device({ id: 'k1', name: 'Рабочий', kind: 'keenetic', url: 'https://p.keenetic.pro' })
    Object.assign(k.view, {
      nat: [{ chain: 'dstnat', action: 'forward tcp', packets: -1, bytes: -1, dst_port: '8001', to_addr: '192.168.88.20', to_ports: '8001', comment: 'NVR', ref: 'ab12' }],
      reserved: [{ mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.88.20' }],
      blocked: [{ mac: 'DE:AD:BE:EF:00:01', host: 'stranger', ip: '192.168.88.99' }],
    })
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path.startsWith('/api/v1/net-devices/k1/') && r.method !== 'GET') { calls.push(`${r.method} ${r.path.replace('/api/v1/net-devices/k1', '')} ${r.body ? JSON.stringify(r.body) : ''}`.trim()); return { status: 204 } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [k] } }
        return undefined
      },
    })
    renderPage('/routers/k1')
    await screen.findByText('Рабочий')
    const confirm = async (open: string, go: string) => {
      fireEvent.click(screen.getByRole('button', { name: open }))
      fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: go }))
      await vi.waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    }
    await confirm('Перезагрузить', 'Перезагрузить')
    await confirm('Снять закрепление', 'Снять закрепление')
    await confirm('Заблокировать', 'Заблокировать')
    await confirm('Разблокировать', 'Разблокировать')
    await confirm('Выключить', 'Выключить')
    expect(calls).toEqual([
      'POST /reboot {}',
      'DELETE /clients/AA:BB:CC:DD:EE:01/reserve {}',
      'POST /clients/AA:BB:CC:DD:EE:01/block {}',
      'DELETE /clients/DE:AD:BE:EF:00:01/block {}',
      'POST /forwards/ab12/switch {"off":true}',
    ])
  })

  it('asks a MikroTik through the queue once its script knows how, and offers a new script before that', async () => {
    const calls: string[] = []
    const old = device({ id: 'o1', name: 'Старый' })
    const fresh = device({ id: 'n1', name: 'Новый', commands: [{ id: 1, kind: 'block', a1: 'AA:BB:CC:DD:EE:01', state: 'done' }, { id: 2, kind: 'reserve', a1: 'AA:BB:CC:DD:EE:01', state: 'failed', note: 'no lease' }] })
    Object.assign(fresh.view, { control: true, blocked: [{ mac: 'DE:AD:BE:EF:00:01', host: 'stranger' }] })
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/n1/commands' && r.method === 'POST') { calls.push(JSON.stringify(r.body)); return { status: 202 } }
        if (r.path === '/api/v1/net-devices/o1/rotate' && r.method === 'POST') { calls.push('rotate'); return { status: 200, body: { token: 'T.secret', script: ':local url "x"' } } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [old, fresh] } }
        return undefined
      },
    })
    const first = renderPage('/routers/n1')
    await screen.findByText('Новый')
    expect(screen.queryByRole('button', { name: 'Включить управление' })).toBeNull()
    expect(screen.getByText('выполнено')).toBeInTheDocument()
    expect(screen.getByText(/no lease/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Заблокировать' }))
    expect(within(screen.getByRole('dialog')).getByText(/в течение минуты/)).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Заблокировать' }))
    await vi.waitFor(() => expect(calls).toEqual(['{"kind":"block","mac":"AA:BB:CC:DD:EE:01"}']))
    first.unmount()
    renderPage('/routers/o1')
    await screen.findByText('Старый')
    expect(screen.queryByRole('button', { name: 'Заблокировать' })).toBeNull() // its script does not know how yet
    fireEvent.click(screen.getByRole('button', { name: 'Включить управление' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Включить управление' }))
    expect(await screen.findByText(/:local url "x"/)).toBeInTheDocument()
    expect(calls.at(-1)).toBe('rotate')
  })

  it('offers a password change only for a router that is asked', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device()] } } : undefined) })
    renderPage('/routers/d1')
    await screen.findByText('Дом')
    expect(screen.queryByRole('button', { name: 'Сменить пароль' })).toBeNull()
  })
})
