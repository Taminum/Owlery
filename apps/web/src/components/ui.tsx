import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

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
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${color}`}>
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
    <div role="group" aria-label={label} className="inline-flex gap-0.5 rounded-control border border-line bg-surface p-[3px]">
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}
          className={`h-[26px] rounded-[7px] px-2.5 text-[13px] ${o.value === value ? 'bg-elevated text-fg ring-1 ring-inset ring-cyan' : 'text-muted hover:text-fg'}`}>
          {o.label}
        </button>
      ))}
    </div>
  )
}
