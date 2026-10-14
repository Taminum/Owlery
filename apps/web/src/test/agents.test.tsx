import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { emptyOverview, member, mockApi, owner, panelDTO, renderApp, type Req } from './helpers'
import type { Agent } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

const TOKEN = 'agent-id.SECRET-agent-token-value-0123456789'

const nodes = [{ id: 'n-a', name: 'node-a' }, { id: 'n-b', name: 'node-b' }]
const agentA: Agent = {
  id: 'ag-1', panel_id: 'p-work', node_id: 'n-a', node_name: 'node-a', name: 'node-a', kind: 'node', status: 'active', agent_version: '0.1.0', source_id: 'x',
  last_seen: new Date().toISOString(), last_batch_at: null, last_event_at: null, last_ack_seq: 10, spool_bytes: 2048, dropped_total: 7, parse_errors: 0, events_total: 1234, created_at: '2026-10-12T00:00:00Z',
}

function routes(extra?: (r: Req) => { status: number; body?: unknown } | undefined) {
  return (r: Req) => {
    if (r.path === '/api/v1/panels/p-work/nodes') return { status: 200, body: { nodes } }
    if (r.method === 'GET' && r.path === '/api/v1/panels/p-work/agents') return { status: 200, body: { agents: [agentA], ingest_path: '/ingest/v1' } }
    return extra?.(r)
  }
}

async function openAgents() {
  await userEvent.click(await screen.findByRole('button', { name: 'Агенты' }))
  return screen.findByRole('dialog', { name: /Агенты на нодах/ })
}

describe('agents', () => {
  it('shows every node with its agent state and the numbers that matter, including loss', async () => {
    mockApi({ me: owner, panels: [panelDTO()], handler: routes() })
    renderApp('/panels')
    const dlg = await openAgents()
    const rowA = (await within(dlg).findByRole('cell', { name: 'node-a' })).closest('tr')!
    const rowB = within(dlg).getByRole('cell', { name: 'node-b' }).closest('tr')!
    expect(within(rowA).getByText('работает')).toBeInTheDocument()
    expect(within(rowA).getByText('1 234')).toBeInTheDocument()
    expect(within(rowA).getByText('7')).toHaveClass('text-red') // dropped lines are never hidden
    expect(within(rowB).getByText('агента нет')).toBeInTheDocument()
  })

  it('lets an operator see agents but not enrol or revoke them', async () => {
    mockApi({ me: member('operator'), panels: [panelDTO({ role: 'operator' })], canCreate: false, handler: routes() })
    renderApp('/panels')
    const dlg = await openAgents()
    await within(dlg).findByRole('cell', { name: 'node-a' })
    expect(within(dlg).queryByRole('button', { name: 'Создать агента' })).not.toBeInTheDocument()
    expect(within(dlg).queryByRole('button', { name: 'Отозвать' })).not.toBeInTheDocument()
  })

  it('does not offer agents to a viewer at all', async () => {
    mockApi({ me: member('viewer'), panels: [panelDTO({ role: 'viewer' })], canCreate: false, handler: routes() })
    renderApp('/panels')
    await screen.findByRole('heading', { name: 'Work' })
    expect(screen.queryByRole('button', { name: 'Агенты' })).not.toBeInTheDocument()
  })

  it('shows the credential once, with a warning, and never again', async () => {
    const api = mockApi({
      me: owner, panels: [panelDTO()],
      handler: routes((r) => (r.method === 'POST' && r.path === '/api/v1/panels/p-work/agents'
        ? { status: 201, body: { agent: { ...agentA, id: 'ag-2', node_id: 'n-b', node_name: 'node-b', status: 'enrolling' }, token: TOKEN, ingest_path: '/ingest/v1' } }
        : undefined)),
    })
    renderApp('/panels')
    const dlg = await openAgents()
    const rowB = (await within(dlg).findByRole('cell', { name: 'node-b' })).closest('tr')!
    await userEvent.click(within(rowB).getByRole('button', { name: 'Создать агента' }))
    expect(api.find('POST', '/api/v1/panels/p-work/agents')[0].body).toEqual({ node_id: 'n-b', name: 'node-b', kind: 'node' })

    const issued = await screen.findByRole('dialog', { name: /Данные для агента: node-b/ })
    expect(within(issued).getByRole('alert')).toHaveTextContent('показывается один раз')
    expect(within(issued).getByLabelText('Токен агента')).toHaveValue(TOKEN)
    expect(issued.textContent).toContain('-token-file /etc/remnascope/agent.token') // the token goes in a file, not on a command line
    expect(issued.textContent).not.toMatch(/-token [^f]/)
    expect(JSON.stringify({ ...localStorage })).not.toContain('SECRET-agent')

    await userEvent.click(within(issued).getByRole('button', { name: 'Я сохранил токен' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: /Данные для агента/ })).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain('SECRET-agent-token')
  })

  it('asks before revoking and then revokes', async () => {
    const api = mockApi({ me: owner, panels: [panelDTO()], handler: routes((r) => (r.method === 'DELETE' ? { status: 204 } : undefined)) })
    renderApp('/panels')
    const dlg = await openAgents()
    const rowA = (await within(dlg).findByRole('cell', { name: 'node-a' })).closest('tr')!
    await userEvent.click(within(rowA).getByRole('button', { name: 'Отозвать' }))
    expect(api.find('DELETE', '/api/v1/panels/p-work/agents/ag-1')).toHaveLength(0)
    const confirm = within(dlg).getByRole('alertdialog')
    expect(confirm).toHaveTextContent('Отозвать агента на ноде «node-a»?')
    await userEvent.click(within(confirm).getByRole('button', { name: 'Отозвать' }))
    await waitFor(() => expect(api.find('DELETE', '/api/v1/panels/p-work/agents/ag-1')).toHaveLength(1))
  })

  it('names the refusal when the node already has an agent', async () => {
    mockApi({
      me: owner, panels: [panelDTO()],
      handler: routes((r) => (r.method === 'POST' ? { status: 409, body: { code: 'agent_exists', message: 'x', request_id: 'r' } } : undefined)),
    })
    renderApp('/panels')
    const dlg = await openAgents()
    const rowB = (await within(dlg).findByRole('cell', { name: 'node-b' })).closest('tr')!
    await userEvent.click(within(rowB).getByRole('button', { name: 'Создать агента' }))
    expect(await within(dlg).findByRole('alert')).toHaveTextContent('У этой ноды уже есть агент')
  })
})

describe('overview without panel counters', () => {
  it('says bytes need the panel counters instead of drawing zeros', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/overview' ? { status: 200, body: emptyOverview({ demo: false }) } : undefined) })
    renderApp('/')
    await screen.findByLabelText('Принятые соединения', { selector: 'section' })
    expect(screen.getAllByText('нужны счётчики панели (этап M3)').length).toBeGreaterThan(0)
    expect(screen.queryByText('Трафик по времени')).not.toBeInTheDocument()
    expect(screen.getByText(/не из числа строк журнала/)).toBeInTheDocument()
  })
})
