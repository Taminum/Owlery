import { render, screen } from '@testing-library/react'
import { Availability } from '../components/Availability'

afterEach(() => vi.unstubAllGlobals())

const reply = (days: object[]) =>
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ days }), { status: 200, headers: { 'Content-Type': 'application/json' } })))

describe('availability strip', () => {
  it('shows the share of minutes and a cell for each day', async () => {
    reply([
      { day: '2026-11-10', minutes: 1440, of: 1440 },
      { day: '2026-11-11', minutes: 1296, of: 1440 },
    ])
    render(<Availability hostId="h1" />)
    expect(await screen.findByText('Доступность за 2 дн.')).toBeInTheDocument()
    expect(screen.getByText('95,0%')).toBeInTheDocument()
    expect(screen.getByTitle('2026-11-11: 90,0%')).toBeInTheDocument()
  })

  it('says nothing for a machine with no record yet', async () => {
    reply([])
    const { container } = render(<Availability hostId="h1" />)
    await new Promise((r) => setTimeout(r, 20))
    expect(container).toBeEmptyDOMElement()
  })
})
