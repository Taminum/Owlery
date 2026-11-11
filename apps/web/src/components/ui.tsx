import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { MoreHorizontal, type LucideIcon } from 'lucide-react'
import { t } from '../i18n'

export function Card({
  title,
  note,
  right,
  className = '',
  bare = false,
  children,
}: {
  title?: string
  note?: string
  right?: ReactNode
  className?: string
  /** A card that holds only a title and a table: in the compact look it has no backing and lies on the page. */
  bare?: boolean
  children: ReactNode
}) {
  return (
    <section className={`rounded-card border border-line bg-surface p-4 ${bare ? 'card-bare' : ''} ${className}`}>
      {(title || right) && (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="text-[15px] font-semibold leading-5 text-fg">{title}</h2>}
            {note && <p className="mt-0.5 text-xs text-muted">{note}</p>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  )
}

/** Status is always icon + text, never colour alone. */
export function Chip({ icon: Icon, tone = 'muted', children }: { icon?: LucideIcon; tone?: 'muted' | 'amber' | 'green' | 'red' | 'cyan'; children: ReactNode }) {
  const color = { muted: 'text-muted border-line', amber: 'text-amber border-amber/40', green: 'text-green border-green/40', red: 'text-red border-red/40', cyan: 'text-cyan border-cyan/40' }[tone]
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium ${color}`}>
      {Icon && <Icon size={13} aria-hidden />}
      {children}
    </span>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />
}

/** One look for every "pick one of a few" control: periods, list or cards, open or all. */
export function Segmented<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void }) {
  return (
    <div role="group" aria-label={label} className="inline-flex max-w-full gap-0.5 overflow-x-auto rounded-control border border-line bg-surface p-[3px] [scrollbar-width:thin]">
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}
          className={`h-[26px] shrink-0 whitespace-nowrap rounded-[7px] px-2.5 text-[13px] ${o.value === value ? 'bg-elevated text-fg ring-1 ring-inset ring-cyan' : 'text-muted hover:text-fg'}`}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

/**
 * The tabs of a page: they change what the page is about. An underline, one row that scrolls sideways when it does
 * not fit (never a second row). The choice inside a page ("cards or list", a period) is Segmented, not this.
 * `controls` ties each tab to a panel with id `panel-<id>`, for pages that give their panels those ids.
 */
export function Tabs<T extends string>({ label, value, tabs, onChange, controls = false }: { label: string; value: T; tabs: { id: T; label: ReactNode; badge?: ReactNode }[]; onChange: (id: T) => void; controls?: boolean }) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-0.5 overflow-x-auto whitespace-nowrap border-b border-line [scrollbar-width:thin]">
      {tabs.map((x) => (
        <button key={x.id} role="tab" type="button" id={`tab-${x.id}`} aria-selected={value === x.id} aria-controls={controls ? `panel-${x.id}` : undefined} onClick={() => onChange(x.id)}
          className={`-mb-px shrink-0 border-b-2 px-3.5 py-2.5 text-[14px] ${value === x.id ? 'border-cyan font-medium text-fg' : 'border-transparent text-muted hover:text-fg'}`}>
          {x.label}
          {x.badge != null && x.badge !== false && <span className="ml-1.5 text-xs text-amber">{x.badge}</span>}
        </button>
      ))}
    </div>
  )
}

export type RowAction = { label: string; onClick: () => void; danger?: boolean; hidden?: boolean }

/**
 * The "..." of a row: every action of the row except the one it is there for. A dangerous one is listed last and set
 * apart; the action itself must still ask for confirmation, as it always did.
 */
export function RowMenu({ label, actions }: { label: string; actions: RowAction[] }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const id = useId()
  const shown = actions.filter((a) => !a.hidden)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [open])
  if (shown.length === 0) return null
  const safe = shown.filter((a) => !a.danger)
  const danger = shown.filter((a) => a.danger)
  const item = (a: RowAction) => (
    <button key={a.label} type="button" role="menuitem" onClick={() => { setOpen(false); a.onClick() }}
      className={`block !h-auto w-full whitespace-nowrap !rounded-[8px] !px-2.5 !py-1.5 text-left !text-[13px] hover:bg-surface ${a.danger ? 'text-red' : 'text-fg'}`}>{a.label}</button>
  )
  return (
    <div ref={ref} className="relative inline-block text-left">
      <button type="button" aria-haspopup="menu" aria-expanded={open} aria-controls={id} aria-label={`${t('row.actions')}: ${label}`} title={t('row.actions')} onClick={() => setOpen((o) => !o)}
        className="grid !h-6 w-6 place-items-center !rounded-[8px] border border-line bg-elevated !p-0 text-muted hover:border-cyan/60 hover:text-fg">
        <MoreHorizontal size={14} aria-hidden />
      </button>
      {open && (
        <div id={id} role="menu" aria-label={label} className="absolute right-0 z-30 mt-1.5 min-w-[190px] rounded-card border border-line bg-elevated p-1 shadow-2xl">
          {safe.map(item)}
          {safe.length > 0 && danger.length > 0 && <hr className="my-1 border-line" />}
          {danger.map(item)}
        </div>
      )}
    </div>
  )
}
