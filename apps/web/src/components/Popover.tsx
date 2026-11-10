import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'

export const controlCls =
  'h-10 rounded-control border border-line bg-surface px-3 text-[13px] text-fg hover:border-line/80 focus-visible:border-cyan'

/** Button + floating panel; closes on outside click and Escape. A compact one is only its icon until the screen is wide (it then
    needs an icon, and `active` marks it when its value is the one in force, since the words that said so are hidden). */
export function Popover({ label, value, icon, children, align = 'left', compact = false, active = false }: { label: string; value: ReactNode; icon?: ReactNode; children: (close: () => void) => ReactNode; align?: 'left' | 'right'; compact?: boolean; active?: boolean }) {
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
      <button type="button" aria-haspopup="dialog" aria-expanded={open} aria-controls={id} aria-label={label} onClick={() => setOpen((o) => !o)} title={compact ? label : undefined}
        className={`${controlCls} flex items-center gap-2 text-left ${compact ? 'w-10 justify-center px-0 xl:w-auto xl:min-w-[140px] xl:justify-start xl:px-3' : 'min-w-[140px]'} ${compact && active ? 'max-xl:border-cyan' : ''}`}>
        {icon}
        <span className={`min-w-0 flex-1 truncate ${compact ? 'hidden xl:block' : ''}`}>{value}</span>
        <ChevronDown size={14} className={`shrink-0 text-muted ${compact ? 'hidden xl:block' : ''}`} aria-hidden />
      </button>
      {open && (
        <div id={id} role="dialog" aria-label={label} className={`absolute z-30 mt-2 min-w-[240px] rounded-card border border-line bg-elevated p-3 shadow-2xl ${align === 'right' ? 'right-0' : 'left-0'}`}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  )
}
