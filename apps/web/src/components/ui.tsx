import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

export function Card({
  title,
  note,
  right,
  className = '',
  children,
}: {
  title?: string
  note?: string
  right?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <section className={`rounded-card border border-line bg-surface p-4 ${className}`}>
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
