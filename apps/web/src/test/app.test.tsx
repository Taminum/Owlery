import { screen, waitFor } from '@testing-library/react'
import { emptyOverview, mockApi, owner, renderApp, type Req } from './helpers'
import type { Overview } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

const overviewReply = (ov: Overview) => (r: Req) => (r.path === '/api/v1/overview' ? { status: 200, body: ov } : undefined)

describe('page width', () => {
  it('gives the top bar and the page the same width, so they line up on a wide screen', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ demo: false })) })
    const { container } = renderApp('/')
    await screen.findByLabelText('Принятые соединения')
    const main = container.querySelector('main')!
    const bar = container.querySelector('header')!.firstElementChild!
    const widthClasses = (el: Element) => el.className.split(/\s+/).filter((c) => /^(max-w-|mx-auto|w-full|px-|lg:px-|2xl:px-)/.test(c)).sort().join(' ')
    expect(widthClasses(main)).toBe(widthClasses(bar))
    expect(widthClasses(main)).toContain('max-w-[2560px]')
    expect(widthClasses(main)).not.toContain('max-w-[1600px]')
  })
})

describe('overview traffic from panel counters', () => {
  it('shows one total (no up/down split) and its chart, and never invents a direction', async () => {
    const ov = emptyOverview({ demo: false })
    ov.traffic = { ...ov.traffic, source: 'panel_api_counters', up_bytes: 0, down_bytes: 0, series: [], total_bytes: 3_221_225_472, total_series: [{ ts: 1791500000, bytes: 1000 }, { ts: 1791503600, bytes: 2000 }], counter_resets: 1 }
    mockApi({ me: owner, handler: overviewReply(ov) })
    renderApp('/')
    expect(await screen.findByText('3,00 ГБ')).toBeInTheDocument()
    expect(screen.getByText('по счётчикам панели, суммарно')).toBeInTheDocument()
    expect(screen.queryByText(/↓/)).not.toBeInTheDocument()
    expect(screen.getByText(/без разделения на вход и выход/)).toBeInTheDocument()
  })

  it('still says there are no counters when the panel has sent none', async () => {
    const ov = emptyOverview({ demo: false })
    ov.traffic = { ...ov.traffic, series: [], total_bytes: null, total_series: [] }
    mockApi({ me: owner, handler: overviewReply(ov) })
    renderApp('/')
    expect(await screen.findByText('Трафик в байтах')).toBeInTheDocument()
  })
})

describe('overview states', () => {
  it('labels synthetic data as demo, and shows no live indicator', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ demo: true })) })
    renderApp('/')
    expect(await screen.findByText(/ДЕМО-ДАННЫЕ/)).toBeInTheDocument()
    await screen.findByLabelText('Принятые соединения')
    expect(screen.getByLabelText(/Автообновление/)).toHaveValue('off')
    expect(screen.queryByText(/live|в эфире|онлайн/i)).not.toBeInTheDocument()
  })

  it('does not show the demo banner when the data is not synthetic', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ demo: false })) })
    renderApp('/')
    await screen.findByLabelText('Принятые соединения')
    expect(screen.queryByText(/ДЕМО-ДАННЫЕ/)).not.toBeInTheDocument()
  })

  it('shows "no data" as its own state with a next action', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ state: 'no_data' })) })
    renderApp('/')
    expect(await screen.findByText('Нет данных за выбранный период')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Расширить период/ })).toBeInTheDocument()
  })

  it('says real panels have no event collection yet, instead of showing numbers', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ state: 'no_data', reason: 'agents_not_connected', demo: false })) })
    renderApp('/')
    expect(await screen.findByText('Сбор событий ещё не подключён')).toBeInTheDocument()
    expect(screen.queryByText('Нет данных за выбранный период')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Открыть панели' })).toBeInTheDocument()
  })

  it('shows "sync pending" differently from "no data"', async () => {
    mockApi({ me: owner, handler: overviewReply(emptyOverview({ state: 'sync_pending' })) })
    renderApp('/')
    expect(await screen.findByText('Синхронизация ещё не завершена')).toBeInTheDocument()
    expect(screen.queryByText('Нет данных за выбранный период')).not.toBeInTheDocument()
  })

  it('shows an API outage as an error, not as an empty result', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/overview' ? { status: 503, body: { code: 'api_unavailable', message: 'down', request_id: 'abc123' } } : undefined) })
    renderApp('/')
    expect(await screen.findByText('API недоступен')).toBeInTheDocument()
    expect(screen.getByText(/abc123/)).toBeInTheDocument()
    expect(screen.queryByText('Нет данных за выбранный период')).not.toBeInTheDocument()
  })

  it('shows a forbidden panel as an access problem', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/overview' ? { status: 403, body: { code: 'panel_forbidden', message: 'no', request_id: 'r1' } } : undefined) })
    renderApp('/')
    expect(await screen.findByText('Нет доступа к панели')).toBeInTheDocument()
  })

  it('flags partial collection with the affected node and window', async () => {
    mockApi({
      me: owner,
      handler: overviewReply(emptyOverview({ coverage: { pct: 91.7, gaps: [{ node_id: 'w1', node_name: 'work-1', panel_id: 'p', from: '2026-10-09T08:00:00Z', to: '2026-10-09T10:00:00Z' }] } })),
    })
    renderApp('/')
    expect(await screen.findByText(/Сбор неполный: покрытие 91,7%/)).toBeInTheDocument()
    expect(screen.getByText(/work-1: нет данных/)).toBeInTheDocument()
  })

  it('requests the scope from the URL and drops stale ids using the visible panels', async () => {
    const api = mockApi({ me: owner, handler: overviewReply(emptyOverview()) })
    renderApp('/?panels=p-work,ghost&nodes=n1,zzz&range=7d')
    await waitFor(() => expect(api.calls.some((c) => c.path === '/api/v1/overview' && c.url.includes('panel_ids=p-work') && c.url.includes('range=7d'))).toBe(true))
    const overviewUrls = api.calls.filter((c) => c.path === '/api/v1/overview').map((c) => c.url)
    expect(overviewUrls.at(-1)).not.toMatch(/ghost|zzz/)
  })

  it('loads the filter scope from the permission-aware endpoint, never from a public list', async () => {
    const api = mockApi({ me: owner, handler: overviewReply(emptyOverview()) })
    renderApp('/')
    await screen.findByLabelText('Принятые соединения')
    expect(api.calls.some((c) => c.path === '/api/v1/scope')).toBe(true)
    expect(api.calls.some((c) => c.path === '/api/v1/panels' && c.method === 'GET')).toBe(false)
  })
})
