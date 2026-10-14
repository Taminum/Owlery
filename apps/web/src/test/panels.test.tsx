import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { member, mockApi, okProbe, owner, panelDTO, renderApp, SECRET, type Req } from './helpers'
import type { ProbeSummary } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

const work = panelDTO()
const demo = panelDTO({ id: 'p-demo', name: 'Рабочая (демо)', demo: true, token: 'none', base_url: 'https://demo.invalid', node_count: 2, user_count: 0, last_sync_at: null, last_sync_status: null, role: 'owner' })

async function openWizard() {
  await userEvent.click(await screen.findByRole('button', { name: /Добавить панель/ }))
  return screen.findByRole('dialog', { name: 'Подключение панели' })
}

async function fillConnection(dialog: HTMLElement, token = SECRET, url = 'https://new.example.com') {
  await userEvent.type(within(dialog).getByLabelText('Название'), 'New panel')
  await userEvent.type(within(dialog).getByLabelText('Адрес панели (HTTPS)'), url)
  await userEvent.type(within(dialog).getByLabelText('API-токен'), token)
}

describe('panel list and roles', () => {
  it('shows the add button and every action to an owner', async () => {
    mockApi({ me: owner, panels: [work, demo] })
    renderApp('/panels')
    const card = (await screen.findByRole('heading', { name: 'Work' })).closest('section')!
    for (const name of ['Проверить', 'Синхронизировать', 'История', 'Заменить токен', 'Настройки', 'Отключить', 'Удалить']) {
      expect(within(card).getByRole('button', { name })).toBeInTheDocument()
    }
    expect(screen.getByRole('button', { name: /Добавить панель/ })).toBeInTheDocument()
  })

  it('gives a viewer no actions and no add button', async () => {
    mockApi({ me: member('viewer'), panels: [panelDTO({ role: 'viewer' })], canCreate: false })
    renderApp('/panels')
    const card = (await screen.findByRole('heading', { name: 'Work' })).closest('section')!
    expect(within(card).queryAllByRole('button')).toHaveLength(0)
    expect(screen.queryByRole('button', { name: /Добавить панель/ })).not.toBeInTheDocument()
  })

  it('gives an operator test and sync, but not token, settings or delete', async () => {
    mockApi({ me: member('operator'), panels: [panelDTO({ role: 'operator' })], canCreate: false })
    renderApp('/panels')
    const card = (await screen.findByRole('heading', { name: 'Work' })).closest('section')!
    expect(within(card).getByRole('button', { name: 'Проверить' })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Синхронизировать' })).toBeInTheDocument()
    for (const name of ['Заменить токен', 'Настройки', 'Отключить', 'Удалить']) expect(within(card).queryByRole('button', { name })).not.toBeInTheDocument()
  })

  it('lets a panel admin manage the panel but not delete it', async () => {
    mockApi({ me: member('admin'), panels: [panelDTO({ role: 'admin' })], canCreate: false })
    renderApp('/panels')
    const card = (await screen.findByRole('heading', { name: 'Work' })).closest('section')!
    for (const name of ['Заменить токен', 'Настройки', 'Отключить']) expect(within(card).getByRole('button', { name })).toBeInTheDocument()
    expect(within(card).queryByRole('button', { name: 'Удалить' })).not.toBeInTheDocument()
  })

  it('marks demo panels and offers them no connection actions', async () => {
    mockApi({ me: owner, panels: [demo] })
    renderApp('/panels')
    const card = (await screen.findByRole('heading', { name: 'Рабочая (демо)' })).closest('section')!
    expect(within(card).getByText('ДЕМО')).toBeInTheDocument()
    expect(within(card).queryAllByRole('button')).toHaveLength(0)
  })

  it('reports the credential as configured and never renders a token', async () => {
    mockApi({ me: owner, panels: [work] })
    renderApp('/panels')
    await screen.findByRole('heading', { name: 'Work' })
    expect(screen.getByText('настроен')).toBeInTheDocument()
    expect(document.body.innerHTML).not.toMatch(/tok-SECRET|api_token|Bearer/)
  })

  it('explains an empty list differently to owners and members', async () => {
    mockApi({ me: owner, panels: [] })
    const { unmount } = renderApp('/panels')
    expect(await screen.findByText(/Подключите первую панель/)).toBeInTheDocument()
    unmount()
    mockApi({ me: member('viewer'), panels: [], canCreate: false })
    renderApp('/panels')
    expect(await screen.findByText(/Вам пока не назначена ни одна панель/)).toBeInTheDocument()
  })

  it('shows failures and the paused-polling state without hiding them behind colour', async () => {
    mockApi({ me: owner, panels: [panelDTO({ status: 'error', consecutive_failures: 5, circuit_open_until: '2026-10-12T11:00:00Z', last_sync_status: 'failed' })] })
    renderApp('/panels')
    await screen.findByRole('heading', { name: 'Work' })
    expect(screen.getByText('ошибка', { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText(/Подряд неудач: 5/)).toBeInTheDocument()
    expect(screen.getByText(/Опрос приостановлен/)).toBeInTheDocument()
  })
})

describe('the connection wizard', () => {
  function probeRoutes(summary: ProbeSummary, saved = panelDTO({ id: 'p-new', name: 'New panel', node_count: 0 })) {
    return (r: Req) => {
      if (r.method === 'POST' && r.path === '/api/v1/panels/probe') return { status: 200, body: summary }
      if (r.method === 'POST' && r.path === '/api/v1/panels') return { status: 201, body: { panel: saved, probe: summary, partial_gaps: [] } }
      return undefined
    }
  }

  it('walks through all four steps and saves only after a passing server-side test', async () => {
    const api = mockApi({ me: owner, panels: [], handler: probeRoutes(okProbe()) })
    renderApp('/panels')
    const dialog = await openWizard()
    expect(within(dialog).getByLabelText('API-токен')).toHaveAttribute('type', 'password')
    await fillConnection(dialog)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' })) // collection -> test

    expect(await within(dialog).findByText('Подключение проверено', { exact: false })).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/panels/probe')[0].body).toEqual({ base_url: 'https://new.example.com', api_token: SECRET, use_custom_ca: false })
    expect(api.find('POST', '/api/v1/panels')).toHaveLength(0) // testing must not save

    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    expect(within(dialog).getByText(/node-1, node-2/)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Сохранить панель' }))

    expect(await screen.findByRole('dialog', { name: 'Панель сохранена' })).toBeInTheDocument()
    const save = api.find('POST', '/api/v1/panels')[0]
    expect(save.body).toMatchObject({ name: 'New panel', base_url: 'https://new.example.com', api_token: SECRET, allow_partial: false, sync_interval_seconds: 300, retention_days: 30 })
    expect(save.headers['X-CSRF-Token']).toBe('csrf-owner')
  })

  it('never leaves the token in browser storage, the URL or the page after saving', async () => {
    mockApi({ me: owner, panels: [], handler: probeRoutes(okProbe()) })
    renderApp('/panels')
    const dialog = await openWizard()
    await fillConnection(dialog)
    for (let i = 0; i < 2; i++) await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await within(dialog).findByText('Подключение проверено', { exact: false })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Сохранить панель' }))
    await screen.findByRole('dialog', { name: 'Панель сохранена' })
    expect(JSON.stringify({ ...localStorage })).not.toContain(SECRET)
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(SECRET)
    expect(window.location.href).not.toContain(SECRET)
    expect(document.cookie).not.toContain(SECRET)
    expect(document.body.innerHTML).not.toContain(SECRET)
  })

  it('validates step one before moving on', async () => {
    mockApi({ me: owner, panels: [] })
    renderApp('/panels')
    const dialog = await openWizard()
    await userEvent.type(within(dialog).getByLabelText('Адрес панели (HTTPS)'), 'http://insecure.example.com')
    await userEvent.type(within(dialog).getByLabelText('API-токен'), 'has space')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    expect(within(dialog).getByText(/Название: от 1 до 64 символов/)).toBeInTheDocument()
    expect(within(dialog).getByText(/Введите адрес вида https/)).toBeInTheDocument()
    expect(within(dialog).getByText(/Вставьте токен без пробелов/)).toBeInTheDocument()
    expect(within(dialog).getByRole('heading', { level: 2, name: 'Подключение панели' })).toBeInTheDocument()
    expect(screen.queryByText('Проверяем подключение…')).not.toBeInTheDocument()
  })

  it('blocks saving when a required check fails and says which one', async () => {
    const failed = okProbe({
      required_ok: false, authenticated: false, node_count: 0, nodes_preview: [],
      checks: [
        { name: 'url', status: 'ok', latency_ms: 0, required: true }, { name: 'connection', status: 'ok', latency_ms: 30, required: true },
        { name: 'auth', status: 'failed', latency_ms: 30, required: true, error_code: 'unauthorized' }, { name: 'nodes', status: 'skipped', latency_ms: 0, required: true },
      ],
    })
    const api = mockApi({ me: owner, panels: [], handler: probeRoutes(failed) })
    renderApp('/panels')
    const dialog = await openWizard()
    await fillConnection(dialog)
    for (let i = 0; i < 2; i++) await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    expect(await within(dialog).findByText('Панель отклонила токен.')).toBeInTheDocument()
    expect(within(dialog).getByText('Обязательные проверки не пройдены, сохранить нельзя.')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Далее' })).toBeDisabled()
    expect(api.find('POST', '/api/v1/panels')).toHaveLength(0)
  })

  it('shows unsafe-target and TLS failures in plain words', async () => {
    const failed = okProbe({ required_ok: false, checks: [{ name: 'url', status: 'failed', latency_ms: 0, required: true, error_code: 'unsafe_target' }, { name: 'connection', status: 'skipped', latency_ms: 0, required: true }] })
    mockApi({ me: owner, panels: [], handler: probeRoutes(failed) })
    renderApp('/panels')
    const dialog = await openWizard()
    await fillConnection(dialog, SECRET, 'https://10.0.0.5')
    for (let i = 0; i < 2; i++) await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    expect(await within(dialog).findByText(/заблокирован политикой безопасности/)).toBeInTheDocument()
  })

  it('needs an explicit confirmation to save with reduced capabilities', async () => {
    const partial = okProbe({
      capabilities: { nodes: true, users: false, system_stats: true, bandwidth_stats: false, metadata: true },
      checks: [...okProbe().checks.slice(0, 4), { name: 'users', status: 'failed', latency_ms: 30, required: false, error_code: 'missing_permission' }],
    })
    const api = mockApi({ me: owner, panels: [], handler: probeRoutes(partial) })
    renderApp('/panels')
    const dialog = await openWizard()
    await fillConnection(dialog)
    for (let i = 0; i < 2; i++) await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await within(dialog).findByText('У токена не хватает прав.')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))

    expect(within(dialog).getByText('Панель поддерживает не всё, что вы просили')).toBeInTheDocument()
    const save = within(dialog).getByRole('button', { name: 'Сохранить панель' })
    expect(save).toBeDisabled()
    await userEvent.click(within(dialog).getByLabelText('Сохранить с ограниченными возможностями'))
    expect(save).toBeEnabled()
    await userEvent.click(save)
    await screen.findByRole('dialog', { name: 'Панель сохранена' })
    expect(api.find('POST', '/api/v1/panels')[0].body?.allow_partial).toBe(true)
  })

  it('offers the admin CA only when the server has one', async () => {
    mockApi({ me: { ...owner, custom_ca_available: false }, panels: [] })
    const { unmount } = renderApp('/panels')
    let dialog = await openWizard()
    expect(within(dialog).queryByLabelText(/CA администратора/)).not.toBeInTheDocument()
    unmount()
    mockApi({ me: owner, panels: [] })
    renderApp('/panels')
    dialog = await openWizard()
    expect(within(dialog).getByLabelText(/CA администратора/)).toBeInTheDocument()
    // The only checkbox on this step trusts the admin-managed CA; nothing switches verification off.
    const boxes = within(dialog).getAllByRole('checkbox')
    expect(boxes).toHaveLength(1)
    expect(boxes[0].closest('label')?.textContent).toMatch(/CA администратора/)
  })

  it('shows the server error without echoing the token when saving fails', async () => {
    mockApi({
      me: owner, panels: [],
      handler: (r) => {
        if (r.path === '/api/v1/panels/probe') return { status: 200, body: okProbe() }
        if (r.method === 'POST' && r.path === '/api/v1/panels') return { status: 409, body: { code: 'name_taken', message: SECRET, request_id: 'r' } }
        return undefined
      },
    })
    renderApp('/panels')
    const dialog = await openWizard()
    await fillConnection(dialog)
    for (let i = 0; i < 2; i++) await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await within(dialog).findByText('Подключение проверено', { exact: false })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Далее' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Сохранить панель' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Панель с таким названием уже есть.')
    expect(document.body.innerHTML).not.toContain('tok-SECRET-typed')
  })
})

describe('destructive and secret-handling dialogs', () => {
  it('lets the owner delete only after choosing retention and typing the exact name', async () => {
    const api = mockApi({ me: owner, panels: [work], handler: (r) => (r.method === 'DELETE' ? { status: 204 } : undefined) })
    renderApp('/panels')
    await userEvent.click(await screen.findByRole('button', { name: 'Удалить' }))
    const dialog = await screen.findByRole('dialog', { name: /Удалить панель «Work»/ })
    const submit = within(dialog).getByRole('button', { name: 'Удалить панель' })
    expect(submit).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText(/Введите название панели/), 'work')
    await userEvent.click(within(dialog).getByLabelText(/Архивировать/))
    expect(submit).toBeDisabled() // wrong case
    await userEvent.clear(within(dialog).getByLabelText(/Введите название панели/))
    await userEvent.type(within(dialog).getByLabelText(/Введите название панели/), 'Work')
    expect(submit).toBeEnabled()
    await userEvent.click(submit)
    await waitFor(() => expect(api.find('DELETE', '/api/v1/panels/p-work')).toHaveLength(1))
    expect(api.find('DELETE', '/api/v1/panels/p-work')[0].body).toEqual({ confirm: 'Work', retention: 'archive' })
  })

  it('rotates a token through a password field and clears it afterwards', async () => {
    const api = mockApi({ me: owner, panels: [work], handler: (r) => (r.method === 'PUT' ? { status: 200, body: { panel: work, probe: okProbe() } } : undefined) })
    renderApp('/panels')
    await userEvent.click(await screen.findByRole('button', { name: 'Заменить токен' }))
    const dialog = await screen.findByRole('dialog', { name: /Заменить API-токен/ })
    const field = within(dialog).getByLabelText('API-токен')
    expect(field).toHaveAttribute('type', 'password')
    await userEvent.type(field, SECRET)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Проверить и заменить' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/panels/p-work/token')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/panels/p-work/token')[0].body).toEqual({ api_token: SECRET })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain('tok-SECRET-typed')
  })

  it('keeps the dialog open and says the old token stays when the new one fails', async () => {
    mockApi({
      me: owner, panels: [work],
      handler: (r) => (r.method === 'PUT'
        ? { status: 422, body: { code: 'probe_failed', message: 'x', request_id: 'r', details: okProbe({ required_ok: false, checks: [{ name: 'auth', status: 'failed', latency_ms: 10, required: true, error_code: 'unauthorized' }] }) } }
        : undefined),
    })
    renderApp('/panels')
    await userEvent.click(await screen.findByRole('button', { name: 'Заменить токен' }))
    const dialog = await screen.findByRole('dialog', { name: /Заменить API-токен/ })
    await userEvent.type(within(dialog).getByLabelText('API-токен'), 'another-token-value')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Проверить и заменить' }))
    expect(await within(dialog).findByText('Панель отклонила токен.')).toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Панель не прошла обязательные проверки.')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('runs a manual sync and a connection test through the API with CSRF', async () => {
    const api = mockApi({
      me: owner, panels: [work],
      handler: (r) => {
        if (r.path === '/api/v1/panels/p-work/sync') return { status: 202, body: { status: 'started' } }
        if (r.path === '/api/v1/panels/p-work/test') return { status: 200, body: okProbe() }
        return undefined
      },
    })
    renderApp('/panels')
    await userEvent.click(await screen.findByRole('button', { name: 'Синхронизировать' }))
    expect(await screen.findByText('Синхронизация запущена.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Проверить' }))
    expect(await screen.findByRole('dialog', { name: /Проверка пройдена/ })).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/panels/p-work/sync')[0].headers['X-CSRF-Token']).toBe('csrf-owner')
  })
})
