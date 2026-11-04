import { fireEvent, render, screen } from '@testing-library/react'
import { About } from '../pages/ServerCard'
import type { Server } from '../components/ServerParts'

const base = { id: 'v1', name: 'Autocad', addresses: [], can_edit: true } as unknown as Server

describe('About the machine', () => {
  it('shows only what is filled in, and keeps the empty fields out of sight', () => {
    render(<About s={{ ...base, provider: 'Selectel', note: 'AutoCAD, nonstandard ports' } as Server} onEdit={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /О машине/ }))
    expect(screen.getByText('Selectel')).toBeInTheDocument()
    expect(screen.getByText('AutoCAD, nonstandard ports')).toBeInTheDocument()
    expect(screen.queryByText('не указано')).toBeNull()
    expect(screen.queryByText('Теги')).toBeNull()
  })

  it('offers to add a note when nothing is filled, and opens the editor from the panel', () => {
    const edit = vi.fn()
    render(<About s={base} onEdit={edit} />)
    fireEvent.click(screen.getByRole('button', { name: /Добавить заметку/ }))
    expect(screen.getByText(/Пока ничего не заполнено/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Изменить' }))
    expect(edit).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('is not there at all for someone who cannot edit and has nothing to read', () => {
    const { container } = render(<About s={{ ...base, can_edit: false } as Server} onEdit={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
