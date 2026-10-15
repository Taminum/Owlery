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
})
