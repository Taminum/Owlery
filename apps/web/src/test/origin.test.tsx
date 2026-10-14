import { render, screen } from '@testing-library/react'
import { OriginBadge } from '../components/Origin'

describe('origin label', () => {
  it('names where a classification came from, and shows nothing when it is unknown', () => {
    const { rerender, container } = render(<OriginBadge origin="rule" />)
    expect(screen.getByText('правило')).toBeInTheDocument()
    rerender(<OriginBadge origin="manual" />)
    expect(screen.getByText('вручную')).toBeInTheDocument()
    rerender(<OriginBadge origin="auto" />)
    expect(screen.getByText('авто')).toHaveAttribute('title', 'Определено автоматически моделью')
    rerender(<OriginBadge origin="guess" />)
    expect(screen.getByText('предположение')).toBeInTheDocument()
    rerender(<OriginBadge origin="" />)
    expect(container).toBeEmptyDOMElement()
    rerender(<OriginBadge origin="something-else" />)
    expect(container).toBeEmptyDOMElement()
  })
})
