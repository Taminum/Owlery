import { fireEvent, render, screen } from '@testing-library/react'
import { CommandTemplates } from '../components/CommandTemplates'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const items = [
  { id: 'a', os: 'linux', name: 'Контейнеры', command: 'docker ps -a', note: 'Все контейнеры', danger: false },
  { id: 'b', os: 'linux', name: 'Диск занят', command: 'df -h\ndu -xh / --max-depth=1', note: '', danger: false },
  { id: 'c', os: 'linux', name: 'Перезагрузка', command: 'reboot', note: '', danger: true },
]

describe('Заготовки команд', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

  it('puts a command into the terminal, several lines joined, and runs it only on request', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => { calls.push(`${init?.method ?? 'GET'} ${url}`); return json({ templates: items }) }))
    const sent: [string, boolean][] = []
    render(<CommandTemplates os="linux" send={(t, run) => { sent.push([t, run]); return true }} />)
    expect(await screen.findByText('Контейнеры')).toBeInTheDocument()
    expect(calls).toContain('GET /api/v1/command-templates?os=linux')
    fireEvent.click(screen.getByRole('button', { name: 'Вставить: Диск занят' }))
    fireEvent.click(screen.getByRole('button', { name: 'Вставить и выполнить: Контейнеры' }))
    expect(sent).toEqual([['df -h; du -xh / --max-depth=1', false], ['docker ps -a', true]])
  })

  it('asks before running a dangerous one in a single step, and says when no terminal is open', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ templates: items })))
    const ask = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true)
    const sent: string[] = []
    const { rerender } = render(<CommandTemplates os="linux" send={(t) => { sent.push(t); return true }} />)
    await screen.findByText('Перезагрузка')
    fireEvent.click(screen.getByRole('button', { name: 'Вставить и выполнить: Перезагрузка' }))
    expect(sent).toEqual([])
    fireEvent.click(screen.getByRole('button', { name: 'Вставить и выполнить: Перезагрузка' }))
    expect(sent).toEqual(['reboot'])
    expect(ask).toHaveBeenCalledTimes(2)
    fireEvent.click(screen.getByRole('button', { name: 'Вставить: Контейнеры' }))
    rerender(<CommandTemplates os="linux" send={() => false} />)
    fireEvent.click(screen.getByRole('button', { name: 'Вставить: Контейнеры' }))
    expect(await screen.findByText(/Сначала откройте терминал/)).toBeInTheDocument()
  })

  it('searches, adds and deletes', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url} ${init?.body ?? ''}`)
      return init?.method === 'POST' ? json({ id: 'n' }, 201) : init?.method === 'DELETE' ? json({ ok: true }) : json({ templates: items })
    }))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<CommandTemplates os="windows" send={() => true} />)
    await screen.findByText('Контейнеры')
    fireEvent.change(screen.getByLabelText('Найти заготовку'), { target: { value: 'диск' } })
    expect(screen.queryByText('Контейнеры')).toBeNull()
    expect(screen.getByText('Диск занят')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Добавить' }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Службы 1С' } })
    fireEvent.change(screen.getByLabelText('Команда'), { target: { value: 'Get-Service *1C*' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(calls.some((c) => c.startsWith('POST /api/v1/command-templates') && c.includes('"os":"windows"') && c.includes('Get-Service'))).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: 'Удалить: Диск занят' }))
    await vi.waitFor(() => expect(calls.some((c) => c.startsWith('DELETE /api/v1/command-templates/b'))).toBe(true))
  })
})
