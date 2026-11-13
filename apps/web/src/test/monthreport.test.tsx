import { fireEvent, render, screen } from '@testing-library/react'
import MonthReport from '../pages/MonthReport'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const month = (m: string, over: object = {}) => ({ month: m, availability: 99.82, worst: [{ name: 'exit-2', down_mins: 190 }], alerts: 47, noisy: { label: 'Диск на panel-ru', count: 9 }, longest: null,
  events: [{ type: 'fail2ban.ban', severity: 'info', count: 1940 }], event_total: 1940, net_downs: 0, net_down_mins: 0, new_devices: 3, traffic_bytes: 4 * 2 ** 40, paid: [{ currency: 'RUB', amount: 9480 }], ...over })

describe('Отчёт за месяц', () => {
  afterEach(() => { vi.unstubAllGlobals() })

  it('shows the numbers against the month before, and leaves out what has no data', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ cur: month('2026-10'), prev: month('2026-09', { availability: 99.72, alerts: 59, traffic_bytes: null }), upcoming: [{ name: 'hel', due: '2026-11-20', amount: 700, currency: 'RUB' }] })))
    render(<MonthReport />)
    expect(await screen.findByText('99,82%')).toBeInTheDocument()
    expect(screen.getByText('+0,10 п.п.')).toBeInTheDocument()
    expect(screen.getByText('−12')).toBeInTheDocument()
    expect(screen.getByText(/exit-2, 3 ч 10 мин/)).toBeInTheDocument()
    expect(screen.getByText(/Диск на panel-ru, 9 раз/)).toBeInTheDocument()
    expect(screen.getByText('Блокировок Fail2ban')).toBeInTheDocument()
    expect(screen.getByText(/Роутеры не пропадали/)).toBeInTheDocument()
    expect(screen.getByText(/Скоро оплата: hel, 20.11/)).toBeInTheDocument()
  })

  it('goes to the month before and back, and sends to Telegram on request', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`)
      if (init?.method === 'POST') return json({ sent: 1, failed: 0 })
      return json({ cur: month('2026-10', { availability: null, traffic_bytes: null, paid: [] }), prev: month('2026-09'), upcoming: [] })
    }))
    render(<MonthReport />)
    fireEvent.click(await screen.findByRole('button', { name: 'Прошлый месяц' }))
    expect(await screen.findByRole('button', { name: 'Следующий месяц' })).toBeInTheDocument()
    expect(calls.filter((c) => c.startsWith('GET')).length).toBe(2)
    fireEvent.click(screen.getByRole('button', { name: 'Отправить в Telegram' }))
    expect(await screen.findByText('Отправлено: 1.')).toBeInTheDocument()
    expect(calls.some((c) => c.startsWith('POST /api/v1/reports/month/send?month='))).toBe(true)
    expect(screen.getAllByText('данных нет').length).toBeGreaterThan(0)
  })

  it('says when no channel is on', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init?: RequestInit) => (init?.method === 'POST' ? json({ code: 'no_channels', message: 'x' }, 409) : json({ cur: month('2026-10'), prev: month('2026-09'), upcoming: [] }))))
    render(<MonthReport />)
    fireEvent.click(await screen.findByRole('button', { name: 'Отправить в Telegram' }))
    expect(await screen.findByText('Нет включённого канала уведомлений.')).toBeInTheDocument()
  })
})
