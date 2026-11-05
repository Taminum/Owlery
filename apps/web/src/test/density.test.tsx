import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AppearanceTab } from '../ember/AppearanceTab'
import { setDensity } from '../lib/density'
import { Card } from '../components/ui'

afterEach(() => { setDensity('compact'); localStorage.clear() })

describe('table density', () => {
  it('is compact by default and the switch in Appearance changes the document and is remembered', async () => {
    render(<AppearanceTab />)
    expect(document.documentElement.getAttribute('data-density')).toBe('compact')
    expect(screen.getByRole('radio', { name: 'Плотно' })).toBeChecked()
    await userEvent.click(screen.getByRole('radio', { name: 'Свободно' }))
    expect(document.documentElement.getAttribute('data-density')).toBe('roomy')
    expect(screen.getByRole('radio', { name: 'Свободно' })).toBeChecked()
    expect(localStorage.getItem('owlery.density')).toBe('roomy')
    await userEvent.click(screen.getByRole('radio', { name: 'Плотно' }))
    expect(document.documentElement.getAttribute('data-density')).toBe('compact')
  })

  it('marks a card that holds only a table as bare, and leaves the others alone', () => {
    const { container } = render(<><Card bare title="a">x</Card><Card title="b">y</Card></>)
    const [a, b] = Array.from(container.querySelectorAll('section'))
    expect(a.className).toContain('card-bare')
    expect(b.className).not.toContain('card-bare')
  })
})
