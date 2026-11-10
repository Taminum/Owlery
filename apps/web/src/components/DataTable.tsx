import { useMemo, useState, type ReactNode } from 'react'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { t } from '../i18n'
import { GhostButton } from './Modal'

export type Column<T> = {
  key: string
  title: string
  cell: (row: T) => ReactNode
  /** The value the column sorts by. A column without it has a plain header. */
  sort?: (row: T) => string | number | null | undefined
  /** The first click puts the largest on top: for dates and counts, where the newest or the biggest is what one looks for. */
  descFirst?: boolean
  align?: 'right'
  /** A note shown when the pointer rests on the header: what the figures in the column are and are not. */
  hint?: string
  /** Extra classes for the cells of this column (text-muted, whitespace-nowrap and the like). */
  className?: string
}

type SortState = { key: string; desc: boolean }

function compare(a: string | number | null | undefined, b: string | number | null | undefined): number {
  if (a == null || a === '') return b == null || b === '' ? 0 : 1 // empty values go last either way
  if (b == null || b === '') return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), 'ru', { numeric: true, sensitivity: 'base' })
}

/**
 * The one data table of the application: its look comes from the shared table rules in index.css, and this adds what every
 * table needs. A header with a sort value sorts on click (again to turn it round), numbers sit on the right in figures
 * of one width, and a long list shows a page at a time with a button for more instead of one endless sheet.
 */
export function DataTable<T>({ caption, columns, rows, rowKey, initialSort, pageSize = 50, empty, rowClass }: {
  caption: string
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  initialSort?: SortState
  pageSize?: number
  empty?: ReactNode
  /** Extra classes of a row, e.g. the highlight of the selected one. */
  rowClass?: (row: T) => string
}) {
  const [sort, setSort] = useState<SortState | null>(initialSort ?? null)
  const [shown, setShown] = useState(pageSize)
  const sorted = useMemo(() => {
    const col = sort && columns.find((c) => c.key === sort.key)
    if (!sort || !col?.sort) return rows
    const by = col.sort
    const dir = sort.desc ? -1 : 1
    return rows
      .map((row, i) => ({ row, i, v: by(row) }))
      .sort((a, b) => {
        const emptyA = a.v == null || a.v === '', emptyB = b.v == null || b.v === ''
        if (emptyA || emptyB) return compare(a.v, b.v) || a.i - b.i
        return dir * compare(a.v, b.v) || a.i - b.i
      })
      .map((x) => x.row)
  }, [rows, sort, columns])

  if (rows.length === 0) return <>{empty ?? <p className="py-4 text-center text-[13px] text-muted">{t('tbl.empty')}</p>}</>
  const page = sorted.slice(0, shown)
  const rest = sorted.length - page.length

  function toggle(c: Column<T>) {
    setSort((s) => (s?.key === c.key ? { key: c.key, desc: !s.desc } : { key: c.key, desc: !!c.descFirst }))
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr>
              {columns.map((c) => {
                const active = sort?.key === c.key
                const right = c.align === 'right'
                return (
                  <th key={c.key} scope="col" title={c.hint} aria-sort={c.sort ? (active ? (sort.desc ? 'descending' : 'ascending') : 'none') : undefined} className={`whitespace-nowrap ${right ? '!text-right' : ''}`}>
                    {c.sort ? (
                      <button type="button" onClick={() => toggle(c)} className={`inline-flex items-center gap-1 hover:text-fg ${active ? 'text-fg' : ''}`}>
                        {c.title}
                        {active && (sort.desc ? <ArrowDown size={12} aria-hidden className="text-cyan" /> : <ArrowUp size={12} aria-hidden className="text-cyan" />)}
                      </button>
                    ) : c.title}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {page.map((row) => (
              <tr key={rowKey(row)} className={rowClass?.(row)}>
                {columns.map((c) => <td key={c.key} className={`${c.align === 'right' ? 'tnum text-right' : ''} ${c.className ?? ''}`}>{c.cell(row)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sorted.length > pageSize && (
        <div className="mt-2.5 flex flex-wrap items-center justify-between gap-3">
          <span role="status" className="tnum text-xs text-muted">{t('tbl.shown', { n: page.length, total: sorted.length })}</span>
          {rest > 0 && <GhostButton size="m" onClick={() => setShown((n) => n + pageSize)}>{t('tbl.more', { n: Math.min(pageSize, rest) })}</GhostButton>}
        </div>
      )}
    </div>
  )
}
