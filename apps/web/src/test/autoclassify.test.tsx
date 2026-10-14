import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Settings from '../pages/Settings'
import { member, mockApi, owner, type Req } from './helpers'
import type { AutoDryRun, AutoItem, AutoModels, AutoStatus } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

function renderSettings() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/settings']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const status = (over: Partial<AutoStatus> = {}, settings: Partial<AutoStatus['settings']> = {}): AutoStatus => ({
  settings: { enabled: false, model: '', batch_size: 15, daily_limit: 300, updated_at: '2026-10-13T12:00:00Z', ...settings },
  key_present: true, running: false, categories: 17, ...over,
})
const models: AutoModels = { models: [{ name: 'gemini-a-flash', display_name: 'A Flash' }, { name: 'gemini-b-pro', display_name: 'B Pro' }] }
const item = (over: Partial<AutoItem>): AutoItem => ({ site: 'x.com', connections: 10, picked_by: 'top', valid: true, undetermined: false, category: 'Игры', confidence: 0.9, reason: 'game store', ...over })
const run = (over = {}) => ({ id: 'r1', started_at: '2026-10-13T12:00:00Z', finished_at: '2026-10-13T12:01:00Z', model: 'gemini-a-flash', state: 'done' as const, requested: 5, requests: 1, tokens_in: 1200, tokens_out: 340, ...over })

async function openTab() {
  await userEvent.click(await screen.findByRole('tab', { name: 'Автоклассификация' }))
}

describe('automatic classification settings', () => {
  it('tells the owner exactly what leaves the server, and shows the key as present or missing, never its value', async () => {
    mockApi({ me: owner, handler: (r) => {
      if (r.path === '/api/v1/autoclassify') return { status: 200, body: status({ key_present: false }) }
      if (r.path === '/api/v1/autoclassify/models') return { status: 200, body: { models: [], error: 'no_key' } }
      if (r.path === '/api/v1/autoclassify/dryrun') return { status: 200, body: { run: null, items: [], summary: { total: 0, valid: 0, undetermined: 0, invalid: 0, with_service: 0, low_confidence: 0, by_category: {}, issues: {} } } }
      return undefined
    } })
    renderSettings()
    await openTab()
    expect(await screen.findByText('Что уходит внешнему провайдеру')).toBeInTheDocument()
    expect(screen.getByText(/Только названия неизвестных сайтов/)).toBeInTheDocument()
    expect(screen.getByText(/Никогда не отправляются: IP-адреса/)).toBeInTheDocument()
    expect(screen.getByText('не задан')).toBeInTheDocument()
    expect(screen.getByText(/secrets\/gemini_api_key/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Ключ Gemini/i, { selector: 'input' })).not.toBeInTheDocument() // there is no field to type a key into
    expect(screen.getByRole('button', { name: 'Запустить прогон' })).toBeDisabled()
  })

  it('offers only the provider’s models, saves the choice, and then allows a dry run', async () => {
    const calls: Req[] = []
    let current = status()
    mockApi({ me: owner, handler: (r) => {
      calls.push(r)
      if (r.path === '/api/v1/autoclassify' && r.method === 'GET') return { status: 200, body: current }
      if (r.path === '/api/v1/autoclassify/models') return { status: 200, body: models }
      if (r.path === '/api/v1/autoclassify/settings') { current = status({}, { model: 'gemini-a-flash', batch_size: 12, daily_limit: 250 }); return { status: 200, body: current.settings } }
      if (r.path === '/api/v1/autoclassify/dryrun' && r.method === 'GET') return { status: 200, body: { run: null, items: [], summary: { total: 0, valid: 0, undetermined: 0, invalid: 0, with_service: 0, low_confidence: 0, by_category: {}, issues: {} } } }
      if (r.path === '/api/v1/autoclassify/dryrun' && r.method === 'POST') return { status: 202, body: { run_id: 'r1' } }
      return undefined
    } })
    renderSettings()
    await openTab()
    const select = await screen.findByLabelText('Модель')
    await waitFor(() => expect(within(select).getAllByRole('option').length).toBe(3)) // "not chosen" + the two models
    expect(screen.getByRole('button', { name: 'Запустить прогон' })).toBeDisabled() // no model yet
    await userEvent.selectOptions(select, 'gemini-a-flash')
    const batch = screen.getByLabelText('Размер пакета')
    await userEvent.clear(batch)
    await userEvent.type(batch, '12')
    const daily = screen.getByLabelText('Лимит сайтов в сутки')
    await userEvent.clear(daily)
    await userEvent.type(daily, '250')
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true))
    expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ model: 'gemini-a-flash', batch_size: 12, daily_limit: 250 })
    const start = await screen.findByRole('button', { name: 'Запустить прогон' })
    await waitFor(() => expect(start).toBeEnabled())
    await userEvent.click(start)
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true))
  })

  it('shows the dry-run result as a review table: valid share, guesses, failures, and a filter', async () => {
    const items: AutoItem[] = [
      item({ site: 'steamstuff.com', category: 'Игры', confidence: 0.92, service: 'Steam' }),
      item({ site: 'maybe-music.net', category: 'Музыка', confidence: 0.4, reason: 'name suggests music', picked_by: 'random' }),
      item({ site: 'who-knows.xyz', undetermined: true, category: undefined, confidence: 0.1, reason: 'unknown' }),
      item({ site: 'broken.io', valid: false, category: undefined, confidence: 0, issue: 'rate_limited', reason: undefined }),
    ]
    const body: AutoDryRun = { run: run({ requested: 4 }), items, summary: { total: 4, valid: 3, undetermined: 1, invalid: 1, with_service: 1, low_confidence: 1, by_category: { Игры: 1, Музыка: 1 }, issues: { rate_limited: 1 } } }
    mockApi({ me: owner, handler: (r) => {
      if (r.path === '/api/v1/autoclassify') return { status: 200, body: status({ latest_run: run() }, { model: 'gemini-a-flash' }) }
      if (r.path === '/api/v1/autoclassify/models') return { status: 200, body: models }
      if (r.path === '/api/v1/autoclassify/dryrun') return { status: 200, body: body }
      return undefined
    } })
    renderSettings()
    await openTab()
    const table = await screen.findByRole('table', { name: 'Пробный прогон' })
    expect(within(table).getByText('steamstuff.com')).toBeInTheDocument()
    expect(screen.getByText('75,0%')).toBeInTheDocument() // 3 of 4 answered
    expect(within(table).getByText('предположение')).toBeInTheDocument() // low confidence is shown as a guess
    expect(within(table).getByText('лимит запросов провайдера')).toBeInTheDocument()
    expect(within(table).getByText('не определено моделью')).toBeInTheDocument()
    expect(screen.getByText(/не доказанная вероятность/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Без ответа' , pressed: false }))
    expect(within(screen.getByRole('table', { name: 'Пробный прогон' })).queryByText('steamstuff.com')).not.toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Пробный прогон' })).getByText('broken.io')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Предположения' }))
    expect(within(screen.getByRole('table', { name: 'Пробный прогон' })).getByText('maybe-music.net')).toBeInTheDocument()
  })

  it('is not offered to anyone but the owner', async () => {
    mockApi({ me: member('admin', 'p-home') })
    renderSettings()
    expect(await screen.findByRole('tab', { name: 'Мой профиль' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Автоклассификация' })).not.toBeInTheDocument()
  })

  it('switches the automatic work on only after the owner confirms what is sent, shows the queue, and can switch off', async () => {
    const calls: Req[] = []
    let current = status({ queue: { counts: { pending: 7, retry: 2, done: 30, failed: 1 }, auto_rules: 30, spent_today: 12, requests_today: 3, tokens_today: 900, last_success_at: '2026-10-13T12:00:00Z', backfill: 'idle' } }, { model: 'gemini-a-flash' })
    mockApi({ me: owner, handler: (r) => {
      calls.push(r)
      if (r.path === '/api/v1/autoclassify' && r.method === 'GET') return { status: 200, body: current }
      if (r.path === '/api/v1/autoclassify/models') return { status: 200, body: models }
      if (r.path === '/api/v1/autoclassify/dryrun') return { status: 200, body: { run: null, items: [], summary: { total: 0, valid: 0, undetermined: 0, invalid: 0, with_service: 0, low_confidence: 0, by_category: {}, issues: {} } } }
      if (r.path === '/api/v1/autoclassify/enabled') { current = { ...current, settings: { ...current.settings, enabled: (r.body as { enabled: boolean }).enabled } }; return { status: 200, body: {} } }
      if (r.path === '/api/v1/autoclassify/backfill') return { status: 200, body: { backfill: 'running' } }
      return undefined
    } })
    renderSettings()
    await openTab()
    expect(await screen.findByText('В очереди')).toBeInTheDocument()
    expect(screen.getByText('9')).toBeInTheDocument() // pending + retry
    expect(screen.getByText('12 / 300')).toBeInTheDocument()
    const on = screen.getByRole('button', { name: 'Включить' })
    expect(on).toBeDisabled() // not without the confirmation
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(on)
    await waitFor(() => expect(calls.find((c) => c.path === '/api/v1/autoclassify/enabled')?.body).toEqual({ enabled: true, confirmed: true }))
    await userEvent.click(await screen.findByRole('button', { name: 'Разобрать историю' }))
    await waitFor(() => expect(calls.some((c) => c.path === '/api/v1/autoclassify/backfill')).toBe(true))
    await userEvent.click(await screen.findByRole('button', { name: 'Выключить' }))
    await waitFor(() => expect(calls.filter((c) => c.path === '/api/v1/autoclassify/enabled')).toHaveLength(2))
  })
})
