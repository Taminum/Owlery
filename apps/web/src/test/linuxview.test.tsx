import { fireEvent, render, screen, within } from '@testing-library/react'
import { LinuxView } from '../components/LinuxView'

const units = [
  { name: 'nginx.service', desc: 'A high performance web server', load: 'loaded', active: 'active', sub: 'running', enabled: 'enabled', manage: true },
  { name: 'remnawave-node.service', desc: 'Remnawave node', load: 'loaded', active: 'failed', sub: 'failed', enabled: 'enabled', manage: true },
  { name: 'ssh.service', desc: 'OpenBSD Secure Shell server', load: 'loaded', active: 'active', sub: 'running', enabled: 'enabled', manage: false },
  { name: 'ghost.service', load: 'not-found', active: 'inactive', sub: 'dead', manage: false },
]

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const empty = { units: [], dir: '', dirs: [], entries: [], text: '', truncated: false, active: '' }

describe('Linux: службы и файлы', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

  it('says how to turn it on when the machine has no helper', () => {
    render(<LinuxView serverId="s1" enabled={false} />)
    expect(screen.getByText(/не включены службы и файлы/)).toBeInTheDocument()
  })

  it('lists services, puts the failed one first, hides the ones that do not exist and offers buttons only where allowed', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...empty, units })))
    render(<LinuxView serverId="s1" enabled />)
    expect(await screen.findByText('nginx.service')).toBeInTheDocument()
    expect(screen.queryByText('ghost.service')).toBeNull()
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('remnawave-node.service')
    expect(rows[0]).toHaveTextContent('упала')
    expect(screen.getByRole('button', { name: 'Перезапустить: nginx.service' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Перезапустить: ssh.service' })).toBeNull()
    expect(within(rows[2]).getByText('только чтение')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Журнал: ssh.service' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Упавшие' }))
    expect(screen.queryByText('nginx.service')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Можно управлять' }))
    expect(screen.getByText('nginx.service')).toBeInTheDocument()
    expect(screen.queryByText('ssh.service')).toBeNull()
  })

  it('asks before a restart and shows the journal in a window', async () => {
    const calls: { op: string; name?: string }[] = []
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      const b = JSON.parse(String(init?.body))
      calls.push(b)
      if (b.op === 'journal') return json({ ...empty, text: 'nginx[1]: started ok' })
      if (b.op === 'restart') return json({ ...empty, active: 'active' })
      return json({ ...empty, units })
    }))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true)
    render(<LinuxView serverId="s1" enabled />)
    fireEvent.click(await screen.findByRole('button', { name: 'Журнал: nginx.service' }))
    expect(await screen.findByText('nginx[1]: started ok')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Закрыть' }))
    fireEvent.click(screen.getByRole('button', { name: 'Перезапустить: nginx.service' }))
    expect(calls.some((c) => c.op === 'restart')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Перезапустить: nginx.service' }))
    expect(await screen.findByText(/nginx.service.*готово, служба сейчас работает/)).toBeInTheDocument()
    expect(calls).toContainEqual({ op: 'restart', name: 'nginx.service' })
    expect(confirm).toHaveBeenCalledTimes(2)
  })

  it('walks the allowed folders and reads a file', async () => {
    const calls: { op: string; path?: string }[] = []
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      const b = JSON.parse(String(init?.body))
      calls.push(b)
      if (b.op === 'ls' && !b.path) return json({ ...empty, dirs: ['/var/log'] })
      if (b.op === 'ls' && b.path === '/var/log') return json({ ...empty, dir: '/var/log', entries: [{ name: 'nginx', dir: true, size: 4096, mod: 1_700_000_000 }, { name: 'syslog', size: 2048, mod: 1_700_000_000 }] })
      if (b.op === 'ls') return json({ ...empty, dir: b.path, entries: [{ name: 'error.log', size: 10, mod: 1_700_000_000 }] })
      if (b.op === 'cat') return json({ ...empty, text: 'the end of the file', truncated: true })
      return json(empty, 500)
    }))
    render(<LinuxView serverId="s1" enabled />)
    fireEvent.click(screen.getByRole('button', { name: 'Файлы' }))
    fireEvent.click(await screen.findByRole('button', { name: '/var/log' }))
    fireEvent.click(await screen.findByRole('button', { name: 'nginx' }))
    fireEvent.click(await screen.findByRole('button', { name: 'error.log' }))
    expect(await screen.findByText('the end of the file')).toBeInTheDocument()
    expect(screen.getByText(/начало обрезано/)).toBeInTheDocument()
    expect(calls).toContainEqual({ op: 'cat', path: '/var/log/nginx/error.log', tail: 500 })
    fireEvent.click(screen.getByRole('button', { name: 'Закрыть' }))
    fireEvent.click(screen.getByRole('button', { name: 'Выше' }))
    expect(await screen.findByRole('button', { name: 'syslog' })).toBeInTheDocument()
  })

  it('shows the machine\'s refusal in words', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ code: 'not_allowed', message: 'x' }, 403)))
    render(<LinuxView serverId="s1" enabled />)
    expect(await screen.findByText(/Машина этого не разрешает/)).toBeInTheDocument()
  })
})
