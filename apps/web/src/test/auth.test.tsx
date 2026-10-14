import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { member, mockApi, owner, renderApp } from './helpers'

afterEach(() => vi.unstubAllGlobals())

describe('signing in', () => {
  it('shows only the sign-in form, and requests no data, without a session', async () => {
    const api = mockApi({ me: null })
    renderApp('/')
    expect(await screen.findByRole('heading', { name: 'Вход в RemnaScope' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    expect(screen.queryByText('Обзор')).not.toBeInTheDocument()
    const paths = api.calls.map((c) => c.path)
    expect(paths).toEqual(['/api/v1/auth/me'])
  })

  it('keeps the password field a password field and never stores credentials', async () => {
    mockApi({ me: null })
    renderApp('/')
    const pw = await screen.findByLabelText('Пароль')
    expect(pw).toHaveAttribute('type', 'password')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(pw, 'hunter2-hunter2')
    expect(JSON.stringify({ ...localStorage })).not.toContain('hunter2')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('hunter2')
    expect(document.cookie).not.toContain('hunter2')
  })

  it('answers a bad login generically and clears the password', async () => {
    mockApi({
      me: null,
      handler: (r) => (r.path === '/api/v1/auth/login' ? { status: 401, body: { code: 'invalid_credentials', message: 'x', request_id: 'r1' } } : undefined),
    })
    renderApp('/')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(screen.getByLabelText('Пароль'), 'wrong-password-123')
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Неверный логин или пароль, либо вход временно ограничен')
    expect(screen.getByLabelText('Пароль')).toHaveValue('')
    expect(screen.getByLabelText('Логин')).toHaveValue('owner')
  })

  it('tells the user when they are rate limited', async () => {
    mockApi({
      me: null,
      handler: (r) => (r.path === '/api/v1/auth/login' ? { status: 429, body: { code: 'rate_limited', message: 'x', request_id: 'r' } } : undefined),
    })
    renderApp('/')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(screen.getByLabelText('Пароль'), 'whatever-123456')
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Слишком много попыток входа')
  })

  it('opens the app after a good login and sends the CSRF token on writes', async () => {
    const api = mockApi({ me: null, loginAs: owner })
    renderApp('/')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(screen.getByLabelText('Пароль'), 'a-good-password-1')
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    expect(await screen.findByRole('link', { name: 'Обзор' })).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/auth/login')[0].body).toEqual({ username: 'owner', password: 'a-good-password-1' })

    await userEvent.click(await screen.findByRole('button', { name: 'Аккаунт' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Выйти' }))
    await waitFor(() => expect(api.find('POST', '/api/v1/auth/logout')).toHaveLength(1))
    expect(api.find('POST', '/api/v1/auth/logout')[0].headers['X-CSRF-Token']).toBe('csrf-owner')
  })
})

describe('an established session', () => {
  it('shows the app and the account menu, and signs out', async () => {
    const api = mockApi({ me: owner })
    renderApp('/')
    expect(await screen.findByRole('link', { name: 'Обзор' })).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Аккаунт' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Выйти' }))
    await waitFor(() => expect(api.find('POST', '/api/v1/auth/logout')).toHaveLength(1))
    expect(api.find('POST', '/api/v1/auth/logout')[0].headers['X-CSRF-Token']).toBe('csrf-owner')
    expect(await screen.findByRole('heading', { name: 'Вход в RemnaScope' })).toBeInTheDocument()
  })

  it('falls back to the sign-in form, with a notice, when the session dies mid-use', async () => {
    let dead = false
    mockApi({
      me: owner,
      handler: (r) => (dead && r.path !== '/api/v1/auth/me' ? { status: 401, body: { code: 'session_expired', message: 'x', request_id: 'r' } } : undefined),
    })
    renderApp('/')
    await screen.findByRole('link', { name: 'Обзор' })
    const refresh = await screen.findByRole('button', { name: 'Обновить' })
    dead = true
    await userEvent.click(refresh)
    expect(await screen.findByText('Сеанс завершён. Войдите снова.')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Вход в RemnaScope' })).toBeInTheDocument()
  })

  it('does not offer owner-only areas to a member', async () => {
    mockApi({ me: member('viewer') })
    renderApp('/settings')
    expect(await screen.findByRole('tab', { name: 'Мой профиль' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Аккаунты и доступ' })).not.toBeInTheDocument()
  })
})
