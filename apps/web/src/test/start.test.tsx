import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Start, { steps } from '../pages/Start'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const none = { panels: 0, panels_synced: 0, nodes: 0, node_agents: 0, security_hosts: 0, security_agents: 0, awg_servers: 0, notify_channels: 0, bills: 0, dns_maps: 0 }

function renderStart() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/start']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="start" element={<Start />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('Getting started', () => {
  it('judges every step from what is already set up', () => {
    const byId = (c: typeof none, mfa = false) => Object.fromEntries(steps(c, mfa).map((s) => [s.id, s.state]))
    expect(byId(none)).toMatchObject({ panel: 'todo', node: 'todo', sec: 'todo', tg: 'todo', pay: 'todo', safe: 'todo', awg: 'todo' })
    expect(byId({ ...none, panels: 1 })).toMatchObject({ panel: 'partial' }) // added, not synced yet
    expect(byId({ ...none, panels: 1, panels_synced: 1, nodes: 2 })).toMatchObject({ panel: 'done', node: 'partial' })
    expect(byId({ ...none, security_hosts: 1 })).toMatchObject({ sec: 'partial' })
    expect(byId({ ...none, security_hosts: 1, security_agents: 1, notify_channels: 1, bills: 2 }, true)).toMatchObject({ sec: 'done', tg: 'done', pay: 'done', safe: 'done' })
    expect(steps(none, false).filter((s) => s.optional).map((s) => s.id)).toEqual(['awg', 'dns'])
  })

  it('shows the progress and opens the first step that is not done, with its instructions', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/onboarding' ? { status: 200, body: { ...none, panels: 1, panels_synced: 1, nodes: 1 } } : undefined) })
    renderStart()
    expect(await screen.findByText('Готово 1 из 6')).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '1')
    // The panel is done; the node agent is the first thing to do, and its steps are already shown.
    expect(screen.getByText(/Откройте «Панели», выберите панель и вкладку «Агенты»/)).toBeInTheDocument()
    expect(screen.queryByText(/Откройте «Панели» и нажмите «Добавить панель»/)).toBeNull()
    await userEvent.click(within(screen.getByText('1. Подключите панель Remnawave').closest('section') as HTMLElement).getByRole('button', { name: 'Как это сделать' }))
    expect(await screen.findByText(/Откройте «Панели» и нажмите «Добавить панель»/)).toBeInTheDocument()
  })
})
