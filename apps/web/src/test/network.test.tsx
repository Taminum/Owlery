import { render, screen } from '@testing-library/react'
import { NetworkView } from '../components/NetworkView'
import type { Server } from '../components/ServerParts'

const base = {
  nodes: [],
  external_ip: '80.94.95.14',
  host: null,
  hardware: {
    nics: [
      { name: 'Ethernet', speed_mbps: 10000, ips: ['192.168.10.5', '2001:db8::5'], gateway: '192.168.10.1', dns: ['192.168.10.2', '1.1.1.1'] },
      { name: 'WireGuard', ips: ['10.66.0.4'] },
    ],
  },
} as unknown as Server

describe('Network tab', () => {
  it('shows the outside address, the gateway and name servers of the machine, and its interfaces', () => {
    render(<NetworkView s={base} />)
    expect(screen.getByText('80.94.95.14')).toBeInTheDocument()
    expect(screen.getAllByText('192.168.10.1').length).toBeGreaterThan(1) // the fact and the table
    expect(screen.getByText('192.168.10.2 · 1.1.1.1')).toBeInTheDocument()
    expect(screen.getByText('10 Гбит/с')).toBeInTheDocument()
    expect(screen.getByText('WireGuard')).toBeInTheDocument()
    expect(screen.getAllByText('локальный').length).toBe(2) // 192.168.x and 10.x are private, the IPv6 documentation address is not
  })

  it('does not show nodes where there are none, and does where there are', () => {
    const { rerender } = render(<NetworkView s={base} />)
    expect(screen.queryByText('Ноды Remnawave')).toBeNull()
    rerender(<NetworkView s={{ ...base, nodes: [{ node_id: 'n1', name: 'Steal', panel_name: 'Main', xray: '25.9', users_online: 41, online: true }] } as unknown as Server} />)
    expect(screen.getByText('Ноды Remnawave')).toBeInTheDocument()
    expect(screen.getByText('Steal', { exact: false })).toBeInTheDocument()
  })

  it('says plainly that there is no data yet, and invents no addresses', () => {
    render(<NetworkView s={{ ...base, hardware: null, external_ip: undefined } as unknown as Server} />)
    expect(screen.getByText(/Данных пока нет/)).toBeInTheDocument()
    expect(screen.queryByText('192.168.10.1')).toBeNull()
  })

  it('shows the current rate only when the machine reports one', () => {
    const { rerender } = render(<NetworkView s={base} />)
    expect(screen.queryByText('Сейчас по сети')).toBeNull()
    rerender(<NetworkView s={{ ...base, host: { has_data: true, rx_bps: 2_400_000, tx_bps: 600_000 } } as unknown as Server} />)
    expect(screen.getByText('Сейчас по сети')).toBeInTheDocument()
  })
})
