import { fireEvent, render, screen } from '@testing-library/react'
import { DockerView } from '../components/DockerView'
import type { DockerContainer } from '../lib/types'

const base = { image: 'x:1', restarts: 0, restarts_1h: 0, ports: [] as string[] }
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString()

const list: DockerContainer[] = [
  { ...base, id: 'aaaaaaaaaaaa', name: 'rw-node', image: 'remnawave/node:2.1', state: 'running', started: ago(3 * 24 * 60), cpu: 3.05, mem: 210 * 2 ** 20, ports: ['2222'] },
  { ...base, id: 'bbbbbbbbbbbb', name: 'nginx', state: 'restarting', restarts: 14, restarts_1h: 6, exit: 1, policy: 'always', mem: 4 * 2 ** 20, ports: ['7443'] },
  { ...base, id: 'cccccccccccc', name: 'old-test', state: 'exited', finished: ago(40 * 24 * 60), exit: 0, policy: 'no' },
]

describe('Docker машины', () => {
  it('counts what runs, what stopped and what keeps falling', () => {
    render(<DockerView info={{ containers: list }} />)
    expect(screen.getByText('Работает').nextSibling).toHaveTextContent('1')
    expect(screen.getByText('Остановлено').nextSibling).toHaveTextContent('1')
    expect(screen.getByText('Падают и перезапускаются').nextSibling).toHaveTextContent('1')
    expect(screen.getByText('rw-node')).toBeInTheDocument()
    expect(screen.getByText(/перезапускается, 14 раз/)).toBeInTheDocument()
    expect(screen.getByText('2222')).toBeInTheDocument()
  })

  it('opens the details of a row on a click', () => {
    render(<DockerView info={{ containers: list }} />)
    expect(screen.queryByText('Политика перезапуска')).toBeNull()
    fireEvent.click(screen.getByText('nginx'))
    expect(screen.getByText('Политика перезапуска')).toBeInTheDocument()
    expect(screen.getByText('always')).toBeInTheDocument()
    fireEvent.click(screen.getByText('nginx'))
    expect(screen.queryByText('Политика перезапуска')).toBeNull()
  })

  it('says so when there is nothing to show', () => {
    const { rerender } = render(<DockerView info={{ containers: [] }} />)
    expect(screen.getByText('Контейнеров на этой машине нет.')).toBeInTheDocument()
    rerender(<DockerView info={null} />)
    expect(screen.getByText(/ещё не рассказал о контейнерах/)).toBeInTheDocument()
  })
})

describe('Docker: логи и перезапуск', () => {
  it('offers the buttons only where the machine allows them', () => {
    const { rerender } = render(<DockerView info={{ containers: list }} serverId="s1" />)
    expect(screen.queryByRole('button', { name: 'Логи: nginx' })).toBeNull()
    rerender(<DockerView info={{ containers: list }} serverId="s1" canCtl />)
    expect(screen.getByRole('button', { name: 'Логи: nginx' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Перезапустить: nginx' })).toBeInTheDocument()
  })

  it('asks before a restart and shows the log in a window', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`)
      const body = url.includes('/logs') ? { log: 'boom line', truncated: false } : { ok: true, running: true }
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }))
    render(<DockerView info={{ containers: list }} serverId="s1" canCtl />)
    fireEvent.click(screen.getByRole('button', { name: 'Логи: nginx' }))
    expect(await screen.findByText('boom line')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Закрыть' }))
    fireEvent.click(screen.getByRole('button', { name: 'Перезапустить: nginx' }))
    expect(calls.some((c) => c.includes('/restart'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Перезапустить' }))
    expect(await screen.findByText(/nginx перезапущен и работает/)).toBeInTheDocument()
    expect(calls).toContain('POST /api/v1/servers/s1/docker/nginx/restart')
    vi.unstubAllGlobals()
  })
})
