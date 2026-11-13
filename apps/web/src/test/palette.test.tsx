import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { fit } from '../components/CommandPalette'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { member, mockApi, owner } from './helpers'

describe('fit', () => {
  it('ranks a run of letters over scattered ones, the start over the middle, and rejects what does not fit', () => {
    expect(fit('Карта сети', 'карта')).toBeGreaterThan(fit('Устройства в сети', 'сети'))
    expect(fit('owlery', 'ow')).toBeGreaterThan(fit('Терминал: owlery', 'ow'))
    expect(fit('Отчёт за месяц', 'отчет')).toBeGreaterThan(0)
    expect(fit('Роутеры', 'ртр')).toBeGreaterThan(0)
    expect(fit('Роутеры', 'xyz')).toBe(-1)
    expect(fit('anything', '')).toBe(0)
  })
})

function Where() {
  const l = useLocation()
  return <p data-testid="where">{l.pathname + l.search}</p>
}

function renderApp(me: typeof owner) {
  setCsrf('')
  mockApi({
    me,
    handler: (r) => (r.path === '/api/v1/servers' ? { status: 200, body: { servers: [{ id: 's1', name: 'owlery', can_edit: true }, { id: 's2', name: 'exit-nl', can_edit: false }] } } : undefined),
  })
  return render(
    <MemoryRouter initialEntries={['/routers']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="*" element={<Where />} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const press = (init: KeyboardEventInit) => fireEvent.keyDown(window, init)

describe('Палитра команд', () => {
  beforeEach(() => localStorage.clear())
  afterEach(() => vi.unstubAllGlobals())

  it('opens on Ctrl+K, finds a machine and goes to its terminal, and closes on Escape', async () => {
    renderApp(owner)
    await screen.findByTestId('where')
    expect(screen.queryByRole('dialog')).toBeNull()
    press({ key: 'k', ctrlKey: true })
    const box = await screen.findByRole('combobox')
    fireEvent.change(box, { target: { value: 'ow' } })
    expect(await screen.findByRole('option', { name: /Терминал: owlery/ })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /exit-nl/ })).toBeNull()
    fireEvent.click(screen.getByRole('option', { name: /Терминал: owlery/ }))
    expect(screen.getByTestId('where')).toHaveTextContent('/servers/s1?view=terminal')
    expect(screen.queryByRole('dialog')).toBeNull()
    press({ key: 'k', ctrlKey: true })
    fireEvent.keyDown(await screen.findByRole('combobox'), { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('opens with Enter on the first match and remembers what was chosen', async () => {
    renderApp(owner)
    await screen.findByTestId('where')
    press({ key: 'k', metaKey: true })
    const box = await screen.findByRole('combobox')
    fireEvent.change(box, { target: { value: 'карта' } })
    fireEvent.keyDown(box, { key: 'Enter' })
    expect(screen.getByTestId('where')).toHaveTextContent('/map')
    expect(JSON.parse(localStorage.getItem('owl.palette.recent') ?? '[]')).toContain('p:/map')
    press({ key: 'k', ctrlKey: true })
    expect(await screen.findByText('Недавнее')).toBeInTheDocument()
  })

  it('gives the owner pages and an action that a member does not get', async () => {
    const { unmount } = renderApp(member('viewer'))
    await screen.findByTestId('where')
    press({ key: 'k', ctrlKey: true })
    const box = await screen.findByRole('combobox')
    fireEvent.change(box, { target: { value: 'карта сети' } })
    expect(screen.getByText('Ничего не нашлось.')).toBeInTheDocument()
    fireEvent.change(box, { target: { value: 'отчёт за месяц в' } })
    expect(screen.getByText('Ничего не нашлось.')).toBeInTheDocument()
    unmount()
    renderApp(owner)
    await screen.findByTestId('where')
    press({ key: 'k', ctrlKey: true })
    fireEvent.change(await screen.findByRole('combobox'), { target: { value: 'отчёт за месяц в' } })
    expect(screen.getByRole('option', { name: /Отправить отчёт за месяц в Telegram/ })).toBeInTheDocument()
  })
})
