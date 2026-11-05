import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ServerGroups } from '../components/ServerGroups'
import type { Server } from '../components/ServerParts'
import { buildBlocks, parkSummary, shownAddress, splitGroup } from '../lib/parks'

function srv(over: Partial<Server> & { name: string }): Server {
  return {
    id: over.name, origin: 'manual', enabled: true, note: '', created_at: '', updated_at: '', addresses: [], links: [], can_edit: true,
    status: 'ok', reason: '', host: null, nodes: [], alerts_open: 0, alerts_critical: 0, ...over,
  } as Server
}

const fleet: Server[] = [
  srv({ name: 'Вентрейд 1С SQL', group: 'Офис / Вентрейд', status: 'bad', alerts_open: 1, note: 'главная база 1С', external_ip: '198.51.100.7' }),
  srv({ name: 'Вентрейд терминальный', group: 'Офис / Вентрейд' }),
  srv({ name: 'Уралнеруд 1С SQL', group: 'Офис / Уралнеруд' }),
  srv({ name: 'УСК', group: 'Офис' }),
  srv({ name: 'home-pc', group: 'Дом' }),
]

const renderGroups = (list: Server[] = fleet) => render(<MemoryRouter><ServerGroups list={list} /></MemoryRouter>)

describe('Парки', () => {
  beforeEach(() => localStorage.clear())

  it('splits a group into the group and its park', () => {
    expect(splitGroup('Офис / Вентрейд')).toEqual({ top: 'Офис', park: 'Вентрейд' })
    expect(splitGroup('Офис/Вентрейд')).toEqual({ top: 'Офис', park: 'Вентрейд' })
    expect(splitGroup('Дом')).toEqual({ top: 'Дом', park: '' })
    expect(splitGroup(undefined)).toEqual({ top: '', park: '' })
  })

  it('puts machines of one park together and the loose ones last', () => {
    const blocks = buildBlocks(fleet)
    expect(blocks.map((b) => b.name)).toEqual(['Дом', 'Офис'])
    const office = blocks[1]
    expect(office.hasParks).toBe(true)
    expect(office.parks.map((p) => p.name)).toEqual(['Вентрейд', 'Уралнеруд', ''])
    expect(office.count).toBe(4)
    expect(blocks[0].hasParks).toBe(false)
  })

  it('says how many machines of a park need a look', () => {
    expect(parkSummary(fleet.slice(0, 2))).toEqual({ attention: 1, worst: 'bad' })
    expect(parkSummary([fleet[2]])).toEqual({ attention: 0, worst: 'ok' })
  })

  it('shows where the agent connects from, else the first address somebody wrote down', () => {
    expect(shownAddress(fleet[0])).toBe('198.51.100.7')
    expect(shownAddress(srv({ name: 'x', addresses: [{ address: 'a.example.com', kind: 'domain' }, { address: '203.0.113.5', kind: 'ipv4' }] }))).toBe('203.0.113.5')
    expect(shownAddress(srv({ name: 'y' }))).toBe('')
  })

  it('folds a park, keeps its summary, and remembers it', () => {
    const { unmount } = renderGroups()
    expect(screen.getByText('Вентрейд 1С SQL')).toBeInTheDocument()
    const head = screen.getByRole('button', { name: /Вентрейд/ })
    expect(head).toHaveTextContent('внимание: 1')
    fireEvent.click(head)
    expect(screen.queryByText('Вентрейд 1С SQL')).toBeNull()
    expect(screen.getByRole('button', { name: /Вентрейд/ })).toHaveTextContent('внимание: 1')
    unmount()
    renderGroups()
    expect(screen.queryByText('Вентрейд 1С SQL')).toBeNull()
  })

  it('switches between cards and a list, and remembers the choice', () => {
    const { unmount } = renderGroups()
    expect(screen.getByRole('radio', { name: 'Карточки' })).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(screen.getByRole('radio', { name: 'Список' }))
    expect(screen.getByRole('radio', { name: 'Список' })).toHaveAttribute('aria-checked', 'true')
    unmount()
    renderGroups()
    expect(screen.getByRole('radio', { name: 'Список' })).toHaveAttribute('aria-checked', 'true')
  })

  it('starts as a list when a group is big, unless the person chose', () => {
    const big = Array.from({ length: 7 }, (_, i) => srv({ name: `m${i}`, group: 'Офис' }))
    renderGroups(big)
    expect(screen.getByRole('radio', { name: 'Список' })).toHaveAttribute('aria-checked', 'true')
  })

  it('shows the note on hover of the name and the address, in the list', () => {
    renderGroups()
    fireEvent.click(screen.getByRole('radio', { name: 'Список' }))
    expect(screen.getByTitle('главная база 1С')).toHaveTextContent('Вентрейд 1С SQL')
    expect(screen.getByText('198.51.100.7')).toBeInTheDocument()
  })
})
