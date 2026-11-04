import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { AlertRules } from '../components/AlertRules'
import Alerts from '../pages/Alerts'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const rows = [
  { rule: 'disk:C:', kind: 'disk', mount: 'C:', enabled: true, threshold: 90, default_enabled: true, default_threshold: 90, changed: false },
  { rule: 'disk:D:', kind: 'disk', mount: 'D:', enabled: false, threshold: 90, default_enabled: false, default_threshold: 90, changed: false },
  { rule: 'forecast', kind: 'forecast', enabled: true, threshold: 14, default_enabled: true, default_threshold: 14, changed: false },
  { rule: 'cpu', kind: 'cpu', enabled: true, threshold: 90, default_enabled: true, default_threshold: 90, changed: false },
  { rule: 'mem', kind: 'mem', enabled: true, threshold: 95, default_enabled: true, default_threshold: 95, changed: false },
]

function rulesBackend(view: object, extra?: (r: Req) => { status: number; body?: unknown } | undefined) {
  setCsrf('')
  return mockApi({ me: owner, handler: (r) => {
    if (r.method === 'GET' && r.path === '/api/v1/servers/s1/alert-rules') return { status: 200, body: view }
    return extra?.(r)
  } })
}

describe('Тревоги машины', () => {
  it('lists the rules with the defaults and sends only what differs from them', async () => {
    const api = rulesBackend({ rows, can_edit: true }, (r) => (r.method === 'PUT' ? { status: 200, body: { rows, can_edit: true } } : undefined))
    render(<AlertRules serverId="s1" name="home-pc" />)
    expect(await screen.findByText('Диск C:, почти полон')).toBeInTheDocument()
    expect(screen.getByText('не следим по умолчанию')).toBeInTheDocument() // the archive drive
    fireEvent.change(screen.getByLabelText('Диск C:, почти полон: Порог'), { target: { value: '97' } })
    fireEvent.click(screen.getByLabelText('Диск D:, почти полон: Вкл'))
    expect(screen.getAllByText(/изменено/)).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/alert-rules')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/alert-rules')[0].body).toEqual({ rules: [
      { rule: 'disk:C:', enabled: true, threshold: 97 },
      { rule: 'disk:D:', enabled: true },
    ] })
  })

  it('goes back to the defaults with an empty list, and is read-only for somebody who cannot edit', async () => {
    const changed = rows.map((r) => (r.rule === 'cpu' ? { ...r, threshold: 80, changed: true } : r))
    const api = rulesBackend({ rows: changed, can_edit: true }, (r) => (r.method === 'PUT' ? { status: 200, body: { rows, can_edit: true } } : undefined))
    const first = render(<AlertRules serverId="s1" name="home-pc" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Вернуть как у всех' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/alert-rules')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/alert-rules')[0].body).toEqual({ rules: [] })
    first.unmount()

    rulesBackend({ rows, can_edit: false })
    render(<AlertRules serverId="s1" name="home-pc" />)
    await screen.findByText('Диск C:, почти полон')
    expect(screen.queryByRole('button', { name: 'Сохранить' })).toBeNull()
    expect(screen.getByLabelText('Процессор, среднее за 10 минут: Вкл')).toBeDisabled()
  })
})

describe('Тревоги, buttons on an open alert', () => {
  const alert = (kind: string, subject: string) => ({ id: 'a1', panel_id: '', panel_name: 'Безопасность', kind, subject, label: 'Диск почти полон: home-pc C:', detail: 'занято 98%', opened_at: '2026-11-04T10:00:00Z', last_seen_at: '2026-11-04T10:00:00Z', resolved_at: null })
  function page(list: object[]) {
    setCsrf('')
    const api = mockApi({ me: owner, handler: (r) => {
      if (r.path === '/api/v1/alerts') return { status: 200, body: { alerts: list, open: list.length } }
      if (r.method === 'POST' && r.path === '/api/v1/alerts/a1/snooze') return { status: 200, body: { ok: true } }
      return undefined
    } })
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <AuthProvider>
          <Routes><Route element={<Layout />}><Route path="alerts" element={<Alerts />} /></Route></Routes>
        </AuthProvider>
      </MemoryRouter>,
    )
    return api
  }

  it('puts an alert off for a day or a week and links to the threshold of its machine', async () => {
    const api = page([alert('host_disk', 'vps-1:C:')])
    fireEvent.click(await screen.findByRole('button', { name: 'Отложить на сутки' }))
    await waitFor(() => expect(api.find('POST', '/api/v1/alerts/a1/snooze')).toHaveLength(1))
    expect(api.find('POST', '/api/v1/alerts/a1/snooze')[0].body).toEqual({ hours: 24 })
    expect(screen.getByRole('link', { name: 'Настроить порог…' })).toHaveAttribute('href', '/servers/vps-1?view=alerts')
    fireEvent.click(screen.getByRole('button', { name: 'Не тревожить 7 дней' }))
    await waitFor(() => expect(api.find('POST', '/api/v1/alerts/a1/snooze')).toHaveLength(2))
    expect(api.find('POST', '/api/v1/alerts/a1/snooze')[1].body).toEqual({ hours: 168 })
  })

  it('offers nothing for an alert that says something is down', async () => {
    page([alert('panel_sync', '')])
    await screen.findByText('Диск почти полон: home-pc C:')
    expect(screen.queryByRole('button', { name: 'Отложить на сутки' })).toBeNull()
  })
})
