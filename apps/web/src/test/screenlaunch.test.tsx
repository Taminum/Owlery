import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { setCsrf } from '../lib/api'
import { ScreenView } from '../components/ScreenView'
import { mockApi, owner, type Req } from './helpers'

class FakeSocket {
  binaryType = ''
  readyState = 0
  send() {}
  close() {}
  addEventListener() {}
}

afterEach(() => vi.unstubAllGlobals())

function open(canLaunch: boolean, handler?: (r: Req) => { status: number; body?: unknown } | undefined) {
  setCsrf('')
  vi.stubGlobal('WebSocket', FakeSocket)
  const api = mockApi({ me: owner, handler })
  render(<ScreenView serverId="s1" canLaunch={canLaunch} />)
  return api
}

describe('PowerShell and cmd on the screen', () => {
  it('has the buttons only where the machine allowed a shell and management', async () => {
    open(false)
    await userEvent.click(screen.getByRole('button', { name: 'Показать экран' }))
    expect(await screen.findByRole('button', { name: 'Win' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'PowerShell' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'cmd' })).toBeNull()
  })

  it('asks first, then sends the shell and the session to the machine', async () => {
    const ask = vi.fn(() => true)
    vi.stubGlobal('confirm', ask)
    const api = open(true, (r) => (r.path === '/api/v1/servers/s1/manage' ? { status: 200, body: { data: null } } : undefined))
    await userEvent.click(screen.getByRole('button', { name: 'Показать экран' }))
    await userEvent.click(await screen.findByRole('button', { name: 'PowerShell' }))
    expect(ask).toHaveBeenCalledWith(expect.stringContaining('PowerShell'))
    expect(await screen.findByText(/Окно PowerShell открыто/)).toBeInTheDocument()
    const sent = api.find('POST', '/api/v1/servers/s1/manage')
    expect(sent).toHaveLength(1)
    expect(sent[0].body).toEqual({ op: 'launch', args: { shell: 'powershell', session: 0 } })
  })

  it('sends nothing when the question is answered no, and says why when the machine refuses', async () => {
    const ask = vi.fn(() => false)
    vi.stubGlobal('confirm', ask)
    const api = open(true, (r) => (r.path === '/api/v1/servers/s1/manage' ? { status: 409, body: { code: 'admin_failed', message: 'на этой машине терминал не разрешён', request_id: 'r' } } : undefined))
    await userEvent.click(screen.getByRole('button', { name: 'Показать экран' }))
    await userEvent.click(await screen.findByRole('button', { name: 'cmd' }))
    expect(api.find('POST', '/api/v1/servers/s1/manage')).toHaveLength(0)
    ask.mockReturnValue(true)
    await userEvent.click(screen.getByRole('button', { name: 'cmd' }))
    expect(await screen.findByText(/^cmd: /)).toBeInTheDocument()
    expect(api.find('POST', '/api/v1/servers/s1/manage')).toHaveLength(1)
  })
})
