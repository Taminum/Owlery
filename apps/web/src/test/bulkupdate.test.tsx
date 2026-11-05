import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { setCsrf } from '../lib/api'
import { BulkUpdate, planUpdates, AgentChips } from '../components/BulkUpdate'
import type { Server } from '../components/ServerParts'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const srv = (id: string, name: string, agent: Server['agent'], over: Partial<Server> = {}) =>
  ({ id, name, group: 'Дом', can_edit: true, os: 'Ubuntu', agent, nodes: [], ...over }) as unknown as Server

const A = (version: string, o: Partial<NonNullable<Server['agent']>> = {}) => ({ version, online: true, can_update: true, ...o })

describe('planUpdates', () => {
  it('splits the fleet into what can be updated now and what cannot, and says why', () => {
    const list = [
      srv('a', 'ready', A('v0.5.15')),
      srv('b', 'offline', A('v0.5.15', { online: false })),
      srv('c', 'not allowed', A('v0.5.14', { can_update: false })),
      srv('d', 'newest', A('v0.5.16')),
      srv('e', 'no agent', null),
      srv('f', 'not yours', A('v0.5.15'), { can_edit: false }),
      srv('g', 'a build', A('dev')),
    ]
    const p = planUpdates(list, 'v0.5.16')
    expect(p.ready.map((s) => s.name)).toEqual(['ready'])
    expect(p.blocked.map((b) => [b.s.name, b.why])).toEqual([['offline', 'offline'], ['not allowed', 'notAllowed']])
    expect(planUpdates(list, '').ready).toHaveLength(0) // nothing is known about the newest release
  })
})

describe('AgentChips', () => {
  it('shows the version and, when there is a newer one, says so', () => {
    const { rerender } = render(<AgentChips s={srv('a', 'x', A('v0.5.15'))} latest="v0.5.16" />)
    expect(screen.getByText('агент v0.5.15')).toBeInTheDocument()
    expect(screen.getByText('есть v0.5.16')).toBeInTheDocument()
    rerender(<AgentChips s={srv('a', 'x', A('v0.5.16'))} latest="v0.5.16" />)
    expect(screen.queryByText(/есть v/)).toBeNull()
    rerender(<AgentChips s={srv('a', 'x', null)} latest="v0.5.16" />)
    expect(screen.queryByText(/агент v/)).toBeNull()
  })
})

describe('BulkUpdate', () => {
  const list = [
    srv('a', 'Senko exit-2', A('v0.5.15')),
    srv('b', 'Home', A('v0.5.15')),
    srv('c', 'UD', A('v0.5.14', { online: false })),
  ]
  function run(handler: (r: Req) => { status: number; body?: unknown } | undefined) {
    setCsrf('')
    const api = mockApi({ me: owner, handler })
    const progress = vi.fn()
    render(<BulkUpdate list={list} latest="v0.5.16" onProgress={progress} pollMs={5} />)
    return { api, progress }
  }

  it('offers the button only when something can be updated', () => {
    setCsrf('')
    mockApi({ me: owner })
    const { container } = render(<BulkUpdate list={[srv('x', 'x', A('v0.5.16'))]} latest="v0.5.16" onProgress={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('lists the ready machines ticked, and the others with the reason', async () => {
    run(() => undefined)
    await userEvent.click(screen.getByRole('button', { name: 'Обновить агентов · 2' }))
    expect(screen.getByRole('checkbox', { name: 'Senko exit-2' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Home' })).toBeChecked()
    expect(screen.getByText('Не обновить с панели (1)')).toBeInTheDocument()
    expect(screen.getByText('не на связи')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: 'Home' }))
    expect(screen.getByRole('button', { name: 'Обновить выбранные (1)' })).toBeInTheDocument()
  })

  it('updates the chosen machines, each with only the version, and shows each as done when its agent has the new version', async () => {
    const seen = new Set<string>()
    const { api, progress } = run((r) => {
      if (r.path.endsWith('/agent/update')) { seen.add(r.path.split('/')[5]); return { status: 200, body: { status: 'started', version: 'v0.5.16' } } }
      if (r.path.endsWith('/agent') && r.method === 'GET') return { status: 200, body: { agent: { agent_version: 'v0.5.16' } } }
    })
    await userEvent.click(screen.getByRole('button', { name: 'Обновить агентов · 2' }))
    await userEvent.click(screen.getByRole('button', { name: 'Обновить выбранные (2)' }))
    await waitFor(() => expect(screen.getAllByText('обновлена')).toHaveLength(2))
    expect([...seen].sort()).toEqual(['a', 'b'])
    const sent = api.find('POST', '/api/v1/security/vps/a/agent/update')
    expect(sent[0].body).toEqual({ version: 'v0.5.16' })
    expect(progress).toHaveBeenCalled()
    expect(screen.getByText('Готово: 2 из 2.')).toBeInTheDocument()
  })

  it('keeps the reason of a failure on the machine, and retries only the failed ones', async () => {
    let homeOk = false
    const { api } = run((r) => {
      if (r.path === '/api/v1/security/vps/b/agent/update') {
        return homeOk ? { status: 200, body: { status: 'started' } } : { status: 409, body: { code: 'update_failed', message: 'selfupdate: SHA256SUMS answered 504', request_id: 'r' } }
      }
      if (r.path.endsWith('/agent/update')) return { status: 200, body: { status: 'started' } }
      if (r.path.endsWith('/agent') && r.method === 'GET') return { status: 200, body: { agent: { agent_version: 'v0.5.16' } } }
    })
    await userEvent.click(screen.getByRole('button', { name: 'Обновить агентов · 2' }))
    await userEvent.click(screen.getByRole('button', { name: 'Обновить выбранные (2)' }))
    expect(await screen.findByText(/не вышло: Агент не смог обновиться: selfupdate: SHA256SUMS answered 504/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('обновлена')).toBeInTheDocument())
    homeOk = true
    await userEvent.click(await screen.findByRole('button', { name: 'Повторить неудавшиеся (1)' }))
    await waitFor(() => expect(screen.getAllByText('обновлена').length).toBe(2))
    expect(api.find('POST', '/api/v1/security/vps/a/agent/update')).toHaveLength(1) // the one that went well is not asked again
    expect(api.find('POST', '/api/v1/security/vps/b/agent/update')).toHaveLength(2)
  })
})
