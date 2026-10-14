import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockApi, owner, renderApp, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const challenge = { mfa_required: true, mfa_token: 'tok-' + 'x'.repeat(30), expires_in: 300 }

describe('two-factor sign-in', () => {
  it('asks for a code after the password, then signs in', async () => {
    const calls: Req[] = []
    mockApi({
      me: null,
      loginAs: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/auth/login') return { status: 200, body: challenge }
        if (r.path === '/api/v1/auth/mfa') return r.body?.code === '123456' ? { status: 200, body: owner } : { status: 401, body: { code: 'invalid_code', message: 'x', request_id: 'r' } }
        return undefined
      },
    })
    renderApp('/')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(screen.getByLabelText('Пароль'), 'correct horse battery staple')
    await userEvent.click(screen.getByRole('button', { name: /Войти/ }))

    // The password step ended in a challenge: no session yet, the code form is shown, the password is gone.
    expect(await screen.findByRole('heading', { name: 'Код подтверждения' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Пароль')).not.toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('Код'), '000000')
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Код не подошёл')
    expect(screen.getByLabelText('Код')).toHaveValue('') // a rejected code is not kept

    await userEvent.type(screen.getByLabelText('Код'), '123456')
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Код подтверждения' })).not.toBeInTheDocument())
    const sent = calls.filter((c) => c.path === '/api/v1/auth/mfa').at(-1)!
    expect(sent.body).toEqual({ mfa_token: challenge.mfa_token, code: '123456' })
  })

  it('goes back to the password form without keeping the token', async () => {
    mockApi({ me: null, handler: (r) => (r.path === '/api/v1/auth/login' ? { status: 200, body: challenge } : undefined) })
    renderApp('/')
    await userEvent.type(await screen.findByLabelText('Логин'), 'owner')
    await userEvent.type(screen.getByLabelText('Пароль'), 'correct horse battery staple')
    await userEvent.click(screen.getByRole('button', { name: /Войти/ }))
    await userEvent.click(await screen.findByRole('button', { name: 'Назад ко входу' }))
    expect(await screen.findByLabelText('Пароль')).toBeInTheDocument()
  })
})

describe('two-factor settings', () => {
  it('turns it on: shows the key once, then the recovery codes once', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/account/mfa/setup') return { status: 200, body: { secret: 'JBSWY3DPEHPK3PXP', uri: 'otpauth://totp/RemnaScope:owner?secret=JBSWY3DPEHPK3PXP&issuer=RemnaScope' } }
        if (r.path === '/api/v1/account/mfa/enable') return { status: 200, body: { recovery_codes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] } }
        return undefined
      },
    })
    renderApp('/settings')
    await userEvent.click(await screen.findByRole('button', { name: 'Включить' }))
    expect(await screen.findByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument()
    expect(await screen.findByAltText('QR-код для приложения-аутентификатора')).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('Код из приложения'), '654321')
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить и включить' }))
    expect(await screen.findByLabelText('Коды восстановления')).toHaveTextContent('AAAAA-BBBBB')
    expect(screen.getByRole('alert')).toHaveTextContent('больше они показаны не будут')
    expect(calls.find((c) => c.path === '/api/v1/account/mfa/enable')!.body).toEqual({ code: '654321' })
  })

  it('shows when it is on, and needs the password and a code to turn it off', async () => {
    const calls: Req[] = []
    mockApi({
      me: { ...owner, mfa_enabled: true },
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/account/mfa/disable') return { status: 204 }
        return undefined
      },
    })
    renderApp('/settings')
    expect(await screen.findByText('Включён')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Выключить' }))
    const submit = screen.getAllByRole('button', { name: 'Выключить' }).at(-1)!
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getAllByLabelText('Текущий пароль').at(-1)!, 'correct horse battery staple')
    await userEvent.type(screen.getByLabelText('Код из приложения или код восстановления'), '111111')
    await userEvent.click(screen.getAllByRole('button', { name: 'Выключить' }).at(-1)!)
    await waitFor(() => expect(calls.some((c) => c.path === '/api/v1/account/mfa/disable')).toBe(true))
    expect(calls.find((c) => c.path === '/api/v1/account/mfa/disable')!.body).toEqual({ password: 'correct horse battery staple', code: '111111' })
  })
})
