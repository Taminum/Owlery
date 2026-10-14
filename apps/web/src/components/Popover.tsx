import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'

export const controlCls =
  'h-10 rounded-control border border-line bg-surface px-3 text-[13px] text-fg hover:border-line/80 focus-visible:border-cyan'

/** Button + floating panel; closes on outside click and Escape. */
export function Popover({ label, value, icon, children, align = 'left' }: { label: string; value: ReactNode; icon?: ReactNode; children: (close: () => void) => ReactNode; align?: 'left' | 'right' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const id = useId()

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button type="button" aria-haspopup="dialog" aria-expanded={open} aria-controls={id} aria-label={label} onClick={() => setOpen((o) => !o)} className={`${controlCls} flex min-w-[140px] items-center gap-2 text-left`}>
        {icon}
        <span className="min-w-0 flex-1 truncate">{value}</span>
        <ChevronDown size={14} className="shrink-0 text-muted" aria-hidden />
      </button>
      {open && (
        <div id={id} role="dialog" aria-label={label} className={`absolute z-30 mt-2 min-w-[240px] rounded-card border border-line bg-elevated p-3 shadow-2xl ${align === 'right' ? 'right-0' : 'left-0'}`}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  )
}
