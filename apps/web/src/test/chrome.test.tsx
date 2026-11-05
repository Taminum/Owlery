import { pageUsesFilters } from '../components/TopBar'
import { loadDetail } from '../components/HostView'

describe('Верхняя полоса и нагрузка', () => {
  it('hides the filters on pages that do not read them', () => {
    for (const p of ['/servers', '/servers/abc', '/hosts', '/security', '/security/v1', '/billing', '/intel', '/start']) {
      expect(pageUsesFilters(p), p).toBe(false)
    }
    for (const p of ['/', '/vpn', '/alerts', '/users', '/panels', '/traffic', '/settings', '/serversx']) {
      expect(pageUsesFilters(p), p).toBe(true)
    }
  })

  it('says nothing about load on Windows and names the cores on Linux', () => {
    expect(loadDetail({ os: 'Microsoft Windows Server 2022', load1: 0, cpus: 8 })).toBe('')
    expect(loadDetail({ os: 'Ubuntu 24.04', load1: 0.5, cpus: 4 })).toBe('нагрузка 0,50 из 4 ядер')
    expect(loadDetail({ os: '', load1: 1.234, cpus: 0 })).toBe('нагрузка 1,23 из 1 ядер')
  })
})
