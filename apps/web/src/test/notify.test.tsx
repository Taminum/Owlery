import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NotifyTab } from '../components/NotifyTab'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

describe('Telegram notifications', () => {
  it('finds the chat from the token and creates the channel without showing the token back', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/notify/channels' && r.method === 'GET') return { status: 200, body: { channels: [], max: 5 } }
      if (r.path === '/api/v1/notify/telegram/discover') return { status: 200, body: { bot: 'scope_bot', chats: [{ id: '424242', title: 'Mish (@mish)' }] } }
      if (r.path === '/api/v1/notify/channels' && r.method === 'POST') return { status: 201, body: { id: 'c1' } }
    } })
    render(<NotifyTab />)
    expect(await screen.findByText('Каналов пока нет.')).toBeInTheDocument()
    const token = '123456789:AAEhBP0av28wFoZxqlx-ab_cdEfGhIjKlMnOp'
    await userEvent.type(screen.getByLabelText('Токен бота'), token)
    await userEvent.click(screen.getByRole('button', { name: 'Найти чат' }))
    expect(await screen.findByText('бот @scope_bot')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Подключить' }))
    await vi.waitFor(() => expect(api.find('POST', '/api/v1/notify/channels')).toHaveLength(1))
    const sent = api.find('POST', '/api/v1/notify/channels')[0].body as Record<string, unknown>
    expect(sent.chat_id).toBe('424242')
    expect(sent.token).toBe(token)
    expect(sent.digest_hour).toBe(9)
    // The token field is emptied after saving.
    expect((screen.getByLabelText('Токен бота') as HTMLInputElement).value).toBe('')
  })

  it('opens the fine tuning of a channel and saves what was chosen', async () => {
    const ch = { id: 'c1', kind: 'telegram', name: 'Me', chat_hint: '…4242', enabled: true, on_alerts: true, digest_hour: 9, digest_tz: 'UTC', last_ok_at: null, last_error: null, prefs: {}, commands: true, muted_until: null }
    const groups = [{ id: 'dns', kinds: ['dns_change'] }, { id: 'flood', kinds: ['host_flood'] }]
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/notify/channels' && r.method === 'GET') return { status: 200, body: { channels: [ch], max: 5, groups, critical: ['host_flood'] } }
      if (r.path === '/api/v1/notify/channels/c1' && r.method === 'PATCH') return { status: 200, body: ch }
    } })
    render(<NotifyTab />)
    await userEvent.click(await screen.findByRole('button', { name: 'Настроить' }))
    await userEvent.click(screen.getByLabelText('DNS (изменения и сбои проверки)')) // switch a group off
    await userEvent.click(screen.getByLabelText('Сообщать, когда проблема закрылась («Закрыто: …»)'))
    await userEvent.click(screen.getByLabelText('Тихие часы: не беспокоить, кроме срочного'))
    await userEvent.selectOptions(screen.getByLabelText('Напоминать о том, что всё ещё открыто'), '3')
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(api.find('PATCH', '/api/v1/notify/channels/c1')).toHaveLength(1))
    const sent = api.find('PATCH', '/api/v1/notify/channels/c1')[0].body as { prefs: Record<string, unknown>; commands: boolean }
    expect(sent.prefs).toEqual({ off: ['dns'], no_resolved: true, quiet_on: true, quiet_from: '23:00', quiet_to: '08:00', remind_hours: 3 })
    expect(sent.commands).toBe(true)
    // The commands of the bot are listed.
    expect(screen.getByText('/stats')).toBeInTheDocument()
  })
})
