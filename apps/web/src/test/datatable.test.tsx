import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DataTable, type Column } from '../components/DataTable'
import { GhostButton } from '../components/Modal'
import { Segmented } from '../components/ui'

type Row = { id: string; name: string; size: number | null }
const columns: Column<Row>[] = [
  { key: 'name', title: 'Имя', sort: (r) => r.name, cell: (r) => r.name },
  { key: 'size', title: 'Размер', sort: (r) => r.size, align: 'right', cell: (r) => r.size ?? '' },
  { key: 'big', title: 'Сначала большие', sort: (r) => r.size, descFirst: true, cell: () => 'x' },
  { key: 'plain', title: 'Заметка', cell: () => 'x' },
]
const names = () => screen.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('cell')[0].textContent)

describe('the one data table', () => {
  it('sorts by a header, turns round on the second click, and keeps empty values last', async () => {
    const rows: Row[] = [{ id: '1', name: 'б10', size: 5 }, { id: '2', name: 'а', size: null }, { id: '3', name: 'б2', size: 30 }]
    render(<DataTable caption="Список" columns={columns} rows={rows} rowKey={(r) => r.id} />)
    expect(names()).toEqual(['б10', 'а', 'б2']) // as given until somebody asks
    await userEvent.click(screen.getByRole('button', { name: 'Имя' }))
    expect(names()).toEqual(['а', 'б2', 'б10']) // numbers inside names count as numbers
    expect(screen.getByRole('columnheader', { name: 'Имя' })).toHaveAttribute('aria-sort', 'ascending')
    await userEvent.click(screen.getByRole('button', { name: 'Размер' }))
    expect(names()).toEqual(['б10', 'б2', 'а'])
    await userEvent.click(screen.getByRole('button', { name: 'Размер' }))
    expect(names()).toEqual(['б2', 'б10', 'а']) // the empty one stays at the bottom
    await userEvent.click(screen.getByRole('button', { name: 'Сначала большие' }))
    expect(names()).toEqual(['б2', 'б10', 'а']) // a column of dates or counts starts from the top
    expect(screen.queryByRole('button', { name: 'Заметка' })).toBeNull() // a column with nothing to sort by is plain
  })

  it('shows a page at a time and says how much is left', async () => {
    const rows: Row[] = Array.from({ length: 7 }, (_, i) => ({ id: String(i), name: `n${i}`, size: i }))
    render(<DataTable caption="Список" columns={columns} rows={rows} rowKey={(r) => r.id} pageSize={3} />)
    expect(names()).toHaveLength(3)
    expect(screen.getByRole('status')).toHaveTextContent('показано 3 из 7')
    await userEvent.click(screen.getByRole('button', { name: 'Показать ещё 3' }))
    expect(names()).toHaveLength(6)
    await userEvent.click(screen.getByRole('button', { name: 'Показать ещё 1' }))
    expect(names()).toHaveLength(7)
    expect(screen.queryByRole('button', { name: /Показать ещё/ })).toBeNull()
  })

  it('says so when there is nothing, and a short list has no footer', () => {
    const { rerender } = render(<DataTable caption="Список" columns={columns} rows={[]} rowKey={(r) => r.id} />)
    expect(screen.getByText('Здесь пока пусто.')).toBeInTheDocument()
    rerender(<DataTable caption="Список" columns={columns} rows={[{ id: '1', name: 'a', size: 1 }]} rowKey={(r) => r.id} />)
    expect(screen.queryByRole('status')).toBeNull()
  })
})

describe('shared controls', () => {
  it('a button has three sizes and is large unless told otherwise', () => {
    render(<><GhostButton>L</GhostButton><GhostButton size="m">M</GhostButton><GhostButton size="s">S</GhostButton></>)
    expect(screen.getByRole('button', { name: 'L' }).className).toContain('h-10')
    expect(screen.getByRole('button', { name: 'M' }).className).toContain('h-8')
    expect(screen.getByRole('button', { name: 'S' }).className).toContain('h-6')
  })

  it('the segmented control marks the chosen option and reports a click', async () => {
    const seen: string[] = []
    render(<Segmented label="Период" value="24h" options={[{ value: '1h', label: '1ч' }, { value: '24h', label: '24ч' }]} onChange={(v) => seen.push(v)} />)
    expect(screen.getByRole('button', { name: '24ч' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.click(screen.getByRole('button', { name: '1ч' }))
    expect(seen).toEqual(['1h'])
  })
})

describe('tabs of a page and the menu of a row', () => {
  it('tabs mark the chosen one, show a badge, and report a click', async () => {
    const { Tabs } = await import('../components/ui')
    const seen: string[] = []
    render(<Tabs label="Машина" value="a" onChange={(x) => seen.push(x)} tabs={[{ id: 'a', label: 'Обзор' }, { id: 'b', label: 'История', badge: 2 }]} />)
    expect(screen.getByRole('tab', { name: 'Обзор' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /История/ })).toHaveTextContent('2')
    await userEvent.click(screen.getByRole('tab', { name: /История/ }))
    expect(seen).toEqual(['b'])
  })

  it('a row menu lists what is not hidden, the dangerous last, closes after a choice, and is absent when empty', async () => {
    const { RowMenu } = await import('../components/ui')
    const done: string[] = []
    const { rerender } = render(<RowMenu label="nas" actions={[
      { label: 'Убрать', onClick: () => done.push('rm'), danger: true },
      { label: 'Изменить', onClick: () => done.push('edit') },
      { label: 'Скрытое', onClick: () => done.push('no'), hidden: true },
    ]} />)
    expect(screen.queryByRole('menu')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Действия: nas' }))
    expect(screen.getAllByRole('menuitem').map((x) => x.textContent)).toEqual(['Изменить', 'Убрать'])
    await userEvent.click(screen.getByRole('menuitem', { name: 'Изменить' }))
    expect(done).toEqual(['edit'])
    expect(screen.queryByRole('menu')).toBeNull()
    rerender(<RowMenu label="nas" actions={[{ label: 'Скрытое', onClick: () => {}, hidden: true }]} />)
    expect(screen.queryByRole('button', { name: 'Действия: nas' })).toBeNull()
  })
})
