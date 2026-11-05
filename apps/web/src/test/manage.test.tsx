import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { ManageView } from '../components/ManageView'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => { vi.unstubAllGlobals(); try { localStorage.clear() } catch { /* nothing to clear */ } })

const procs = [
  { pid: 4, ppid: 0, name: 'System', user: 'NT AUTHORITY\\SYSTEM', rss: 140000, cpu: 1.3 },
  { pid: 43884, ppid: 4, name: 'secagent.exe', user: 'NT AUTHORITY\\SYSTEM', rss: 61000000, cpu: 0.4 },
]

function show() {
  setCsrf('')
  mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/servers/s1/manage' ? { status: 200, body: { data: procs } } : undefined) })
  return render(<AuthProvider><ManageView serverId="s1" /></AuthProvider>)
}

describe('Machine management', () => {
  it('keeps the long note behind a question mark', async () => {
    show()
    await screen.findByText('secagent.exe')
    expect(screen.queryByText(/На экране человека при этом ничего не появляется/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Пояснение' }))
    expect(screen.getByText(/На экране человека при этом ничего не появляется/)).toBeInTheDocument()
  })

  it('has a handle on every column edge but the last, and a table of fixed layout', async () => {
    show()
    await screen.findByText('secagent.exe')
    const handles = screen.getAllByRole('separator', { name: 'Ширина колонки' })
    expect(handles).toHaveLength(6) // seven columns
    expect(screen.getByRole('table').className).toContain('table-fixed')
  })

  it('remembers the widths of the table', async () => {
    localStorage.setItem('owl.manage.cols.procs', JSON.stringify([40, 5, 20, 5, 10, 10, 10]))
    show()
    await screen.findByText('secagent.exe')
    const cols = screen.getByRole('table').querySelectorAll('col')
    expect(cols[0]).toHaveStyle({ width: '40%' })
    expect(cols[1]).toHaveStyle({ width: '5%' })
  })

  it('a double click on an edge puts the two columns back', async () => {
    localStorage.setItem('owl.manage.cols.procs', JSON.stringify([40, 5, 20, 5, 10, 10, 10]))
    show()
    await screen.findByText('secagent.exe')
    fireEvent.doubleClick(screen.getAllByRole('separator', { name: 'Ширина колонки' })[0])
    const cols = screen.getByRole('table').querySelectorAll('col')
    // 40 + 5 shared as the default 26 : 8
    expect(parseFloat((cols[0] as HTMLElement).style.width)).toBeCloseTo(45 * 26 / 34, 1)
    expect(parseFloat((cols[1] as HTMLElement).style.width)).toBeCloseTo(45 * 8 / 34, 1)
  })
})
