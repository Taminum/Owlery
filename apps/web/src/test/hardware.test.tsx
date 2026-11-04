import { render, screen, within } from '@testing-library/react'
import { HardwareSection } from '../components/HardwareView'
import type { Hardware } from '../lib/types'
import type { Host } from '../components/HostView'

const GB = 1024 ** 3
const hw: Hardware = {
  vendor: 'ASUS', model: 'ROG STRIX B650-F', bios: '2611 12.03.2025', virtual: false, os_build: 'Microsoft Windows 11 Pro 26100',
  cpu: { model: 'AMD Ryzen 7 7800X3D', cores: 8, threads: 16, mhz: 4200, cache_mb: 96 },
  memory: { slots: 4, slots_used: 2, type: 'DDR5', speed_mt: 6000 },
  disks: [{ model: 'Samsung SSD 990 PRO 2TB', size: 2000 * GB, kind: 'nvme' }, { model: 'WDC WD40EZAZ', size: 4000 * GB, kind: 'hdd' }],
  gpus: [{ name: 'NVIDIA GeForce RTX 4070', mem: 4 * GB, driver: '32.0.15.6094' }],
  nics: [{ name: 'Ethernet', speed_mbps: 2500, ips: ['192.168.1.50'] }],
}
const host = { has_data: true, mem_total: 64 * GB, disks: [{ m: 'C:', fs: 'NTFS', t: 931 * GB, u: 883 * GB }] } as unknown as Host

describe('Hardware section', () => {
  it('lists what the machine is made of, with the volumes next to the physical disks', () => {
    render(<HardwareSection hw={hw} host={host} />)
    expect(screen.getByText('физическая машина')).toBeInTheDocument()
    expect(screen.getByText('ROG STRIX B650-F')).toBeInTheDocument()
    expect(screen.getByText('AMD Ryzen 7 7800X3D')).toBeInTheDocument()
    expect(screen.getByText('8 / 16')).toBeInTheDocument()
    expect(screen.getByText('2 из 4 слотов')).toBeInTheDocument()
    expect(screen.getByText('DDR5, 6000 МТ/с')).toBeInTheDocument()
    expect(screen.getByText('SSD NVMe')).toBeInTheDocument()
    expect(screen.getByText('HDD')).toBeInTheDocument()
    expect(screen.getByRole('meter', { name: 'C:' })).toHaveAttribute('aria-valuenow', '95')
    expect(screen.getByText('NVIDIA GeForce RTX 4070')).toBeInTheDocument()
    const net = screen.getByText('Ethernet').closest('li') as HTMLElement
    expect(within(net).getByText('2,5 Гбит/с')).toBeInTheDocument()
    expect(within(net).getByText('192.168.1.50')).toBeInTheDocument()
  })

  it('says a virtual machine is one, and does not invent parts it was not told about', () => {
    render(<HardwareSection hw={{ ...hw, virtual: true, hypervisor: 'kvm', gpus: [], nics: [], disks: [], memory: {}, cpu: { cores: 0, threads: 0 } }} host={null} />)
    expect(screen.getByText('виртуальная машина, kvm')).toBeInTheDocument()
    expect(screen.getAllByText('Машина об этом не сообщила.').length).toBe(3)
  })
})
