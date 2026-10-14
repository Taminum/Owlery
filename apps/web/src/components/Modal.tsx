import { useEffect, useId, useRef, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { t } from '../i18n'

/** Accessible dialog: focus moves in, Tab stays inside, Escape closes, focus returns. */
export function Modal({ title, onClose, children, wide = false, busy = false }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean; busy?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const titleId = useId()

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const node = ref.current
    const focusables = () => node?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? []
    ;(node?.querySelector<HTMLElement>('[data-autofocus]') ?? focusables()[0] ?? node)?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        e.stopPropagation()
        onClose()
      }
      if (e.key !== 'Tab') return
      const list = Array.from(focusables()).filter((el) => !el.hasAttribute('disabled'))
      if (list.length === 0) return
      const first = list[0]
      const last = list[list.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      previous?.focus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-black/70 p-4" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} className={`my-8 w-full rounded-card border border-line bg-surface shadow-2xl ${wide ? 'max-w-[760px]' : 'max-w-[520px]'}`}>
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <h2 id={titleId} className="text-[17px] font-semibold leading-6">{title}</h2>
          <button type="button" onClick={onClose} disabled={busy} aria-label={t('common.close')} className="grid h-8 w-8 shrink-0 place-items-center rounded-control text-muted hover:bg-elevated disabled:opacity-40">
            <X size={18} aria-hidden />
          </button>
        </header>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

export const inputCls =
  'h-10 w-full rounded-control border border-line bg-canvas px-3 text-[14px] text-fg placeholder:text-muted/60 focus-visible:border-cyan'

export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: string; error?: string; children: ReactNode; htmlFor: string }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-[13px] font-medium text-fg">{label}</label>
      {children}
      {error ? <p role="alert" className="text-xs text-red">{error}</p> : hint ? <p className="text-xs text-muted">{hint}</p> : null}
    </div>
  )
}

export function PrimaryButton({ children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...p} className={`h-10 rounded-control bg-blue px-4 text-[14px] font-medium text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40 ${p.className ?? ''}`}>
      {children}
    </button>
  )
}

export function GhostButton({ children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...p} className={`h-10 rounded-control border border-line bg-elevated px-4 text-[14px] text-fg hover:border-cyan/60 disabled:cursor-not-allowed disabled:opacity-40 ${p.className ?? ''}`}>
      {children}
    </button>
  )
}

export function DangerButton({ children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...p} className={`h-10 rounded-control border border-red/60 bg-red/15 px-4 text-[14px] font-medium text-red hover:bg-red/25 disabled:cursor-not-allowed disabled:opacity-40 ${p.className ?? ''}`}>
      {children}
    </button>
  )
}
