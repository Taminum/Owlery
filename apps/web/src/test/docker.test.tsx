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
