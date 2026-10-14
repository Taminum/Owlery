import { screen } from '@testing-library/react'
import { emptyOverview, mockApi, owner, renderApp } from './helpers'

afterEach(() => vi.unstubAllGlobals())

// In production a Go nil slice reached the browser as JSON null and a sparkline called .map on it,
// which blanked the whole page. The UI must survive that shape even if a server bug sends it again.
describe('an overview with nulls where arrays belong', () => {
  it('still renders the page instead of going blank', async () => {
    const ov = emptyOverview({ demo: false }) as unknown as Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    ov.unique_hosts.series = null
    ov.unique_ips.series = null
    ov.connections.series = { ts: null, v: null }
    ov.nodes.series = null
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/overview' ? { status: 200, body: ov } : undefined) })
    renderApp('/')
    expect(await screen.findByLabelText('Принятые соединения', { selector: 'section' })).toBeInTheDocument()
    expect(screen.getByLabelText('Уникальные хосты')).toBeInTheDocument()
  })
})
