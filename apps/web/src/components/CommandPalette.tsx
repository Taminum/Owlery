import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { HardDrive, LogOut, Search, Send, Terminal, SlidersHorizontal, type LucideIcon } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useModulesOff } from '../lib/modules'
import { OPEN_PALETTE } from '../lib/palette'
import { SECTIONS } from './Sidebar'

type Group = 'recent' | 'machines' | 'pages' | 'actions'
interface Entry { id: string; group: Group; label: string; hint?: string; icon: LucideIcon; run: () => void }
interface Machine { id: string; name: string; can_edit?: boolean }

const RECENT_KEY = 'owl.palette.recent'
const MAX_RECENT = 5
const MAX_SHOWN = 40

function loadRecent(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]')
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, MAX_RECENT) : []
  } catch { return [] }
}
function saveRecent(ids: string[]) {
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(ids.slice(0, MAX_RECENT))) } catch { /* a convenience only */ }
}

const norm = (s: string) => s.toLowerCase().replace(/ё/g, 'е')

/** How well a query fits a label: -1 for not at all, higher is better. A run of the letters beats letters spread out, the start beats the middle. */
export function fit(label: string, query: string): number {
  const q = norm(query.trim())
  if (!q) return 0
  const l = norm(label)
  const at = l.indexOf(q)
  if (at >= 0) return 1000 - at * 5 - (l.length - q.length)
  let i = 0
  let gaps = 0
  let last = -1
  for (const ch of q) {
    const f = l.indexOf(ch, i)
    if (f < 0) return -1
    if (last >= 0) gaps += f - last - 1
    last = f
    i = f + 1
  }
  return 500 - gaps * 10 - (l.length - q.length)
}

function Marked({ text, query }: { text: string; query: string }): ReactNode {
  const q = norm(query.trim())
  const at = q ? norm(text).indexOf(q) : -1
  if (at < 0) return text
  return <>{text.slice(0, at)}<b className="font-medium text-cyan">{text.slice(at, at + q.length)}</b>{text.slice(at + q.length)}</>
}

const GROUP_KEY: Record<Group, MsgKey> = { recent: 'pal.g.recent', machines: 'pal.g.machines', pages: 'pal.g.pages', actions: 'pal.g.actions' }

/**
 * A search box over the whole panel, opened with Ctrl+K (or Cmd+K): the pages of the menu the person may use, the machines (a
 * card, its terminal, its services and files) and a few harmless actions. It only goes somewhere; nothing runs on a machine from here.
 */
export function CommandPalette() {
  const navigate = useNavigate()
  const { state: auth, logout } = useAuth()
  const off = useModulesOff()
  const owner = auth.status === 'authed' && auth.me.account.is_owner
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [machines, setMachines] = useState<Machine[]>([])
  const [recent, setRecent] = useState<string[]>(loadRecent)
  const input = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => !v)
      }
    }
    const show = () => setOpen(true)
    window.addEventListener('keydown', key)
    window.addEventListener(OPEN_PALETTE, show)
    return () => { window.removeEventListener('keydown', key); window.removeEventListener(OPEN_PALETTE, show) }
  }, [])

  useEffect(() => {
    if (!open || auth.status !== 'authed') return
    const ac = new AbortController()
    api.get<{ servers: Machine[] }>('/api/v1/servers', ac.signal).then((r) => setMachines(r.servers ?? [])).catch(() => { /* the pages still work */ })
    return () => ac.abort()
  }, [open, auth.status])

  const close = () => { setOpen(false); setQuery(''); setActive(0) }

  const all = useMemo<Entry[]>(() => {
    const go = (to: string) => () => navigate(to)
    const out: Entry[] = []
    for (const m of machines) {
      out.push({ id: `m:${m.id}`, group: 'machines', label: m.name, hint: t('pal.card'), icon: HardDrive, run: go(`/servers/${m.id}`) })
      if (m.can_edit) {
        out.push({ id: `mt:${m.id}`, group: 'machines', label: t('pal.terminal', { name: m.name }), hint: t('pal.terminalHint'), icon: Terminal, run: go(`/servers/${m.id}?view=terminal`) })
        out.push({ id: `mm:${m.id}`, group: 'machines', label: t('pal.manage', { name: m.name }), hint: t('pal.manageHint'), icon: SlidersHorizontal, run: go(`/servers/${m.id}?view=manage`) })
      }
    }
    for (const sec of SECTIONS) {
      for (const i of sec.items) {
        if ((i.owner && !owner) || (i.module && off.has(i.module)) || i.disabled) continue
        out.push({ id: `p:${i.to}`, group: 'pages', label: t(i.key), hint: i.to, icon: i.icon, run: go(i.to) })
      }
    }
    out.push({ id: 'p:/settings', group: 'pages', label: t('nav.settings'), hint: '/settings', icon: SlidersHorizontal, run: go('/settings') })
    if (owner) {
      out.push({
        id: 'a:report', group: 'actions', label: t('pal.report'), icon: Send,
        run: () => {
          if (!window.confirm(t('pal.reportAsk'))) return
          const month = new Date()
          month.setUTCMonth(month.getUTCMonth() - 1)
          const m = `${month.getUTCFullYear()}-${String(month.getUTCMonth() + 1).padStart(2, '0')}`
          api.post(`/api/v1/reports/month/send?month=${m}`).then(() => window.alert(t('pal.reportDone'))).catch(() => window.alert(t('pal.reportFail')))
        },
      })
    }
    out.push({ id: 'a:logout', group: 'actions', label: t('pal.logout'), icon: LogOut, run: () => void logout() })
    return out
  }, [machines, owner, off, navigate, logout])

  const shown = useMemo<Entry[]>(() => {
    if (!query.trim()) {
      const byId = new Map(all.map((e) => [e.id, e]))
      const rec = recent.map((id) => byId.get(id)).filter((e): e is Entry => !!e).map((e) => ({ ...e, group: 'recent' as Group }))
      const seen = new Set(rec.map((e) => e.id))
      // With nothing typed, a machine is offered by its card only: its terminal and services appear once its name is typed.
      return [...rec, ...all.filter((e) => !seen.has(e.id) && (e.group !== 'machines' || e.id.startsWith('m:')))].slice(0, MAX_SHOWN)
    }
    return all
      .map((e) => ({ e, s: fit(e.label, query) + (recent.includes(e.id) ? 50 : 0) }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, MAX_SHOWN)
      .map((x) => x.e)
  }, [all, query, recent])

  useEffect(() => { if (open) input.current?.focus() }, [open])
  useEffect(() => { listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' }) }, [active, shown])

  function choose(e: Entry) {
    if (e.group !== 'actions') {
      const next = [e.id, ...recent.filter((x) => x !== e.id)].slice(0, MAX_RECENT)
      setRecent(next)
      saveRecent(next)
    }
    close()
    e.run()
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === 'Escape') { e.preventDefault(); close() }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(shown.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter' && shown[active]) { e.preventDefault(); choose(shown[active]) }
  }

  if (!open || auth.status !== 'authed') return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 px-3 pt-[12vh]" onMouseDown={(e) => { if (e.target === e.currentTarget) close() }}>
      <div role="dialog" aria-modal="true" aria-label={t('pal.open')} onKeyDown={onKey} className="w-full max-w-[540px] overflow-hidden rounded-card border border-line bg-surface shadow-xl">
        <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <Search size={16} aria-hidden className="text-muted" />
          <input ref={input} value={query} onChange={(e) => { setQuery(e.target.value); setActive(0) }} placeholder={t('pal.placeholder')} aria-label={t('pal.placeholder')}
            role="combobox" aria-expanded="true" aria-controls="pal-list" aria-activedescendant={shown[active] ? `pal-${active}` : undefined} autoComplete="off" spellCheck={false}
            className="min-w-0 flex-1 bg-transparent text-[15px] outline-none placeholder:text-muted" />
          <button type="button" onClick={close} aria-label={t('pal.close')} className="rounded-md border border-line px-1.5 text-[11px] text-muted hover:text-fg">Esc</button>
        </div>
        <ul id="pal-list" ref={listRef} role="listbox" aria-label={t('pal.list')} className="max-h-[52vh] overflow-auto p-1.5">
          {shown.length === 0 && <li className="px-3 py-4 text-[13px] text-muted">{t('pal.none')}</li>}
          {shown.map((e, i) => {
            const head = i === 0 || shown[i - 1].group !== e.group ? <li role="presentation" className="px-3 pb-1 pt-2 text-[11px] text-muted">{t(GROUP_KEY[e.group])}</li> : null
            const Icon = e.icon
            return (
              <li key={`${e.group}:${e.id}`} role="presentation">
                {head}
                <div id={`pal-${i}`} role="option" aria-selected={i === active} onMouseMove={() => setActive(i)} onClick={() => choose(e)}
                  className={`flex cursor-pointer items-center gap-3 rounded-control px-3 py-2 text-[14px] ${i === active ? 'bg-blue/20' : ''}`}>
                  <Icon size={16} aria-hidden className="shrink-0 text-muted" />
                  <span className="min-w-0 flex-1 truncate"><Marked text={e.label} query={query} /></span>
                  {e.hint && <span className="shrink-0 text-xs text-muted">{e.hint}</span>}
                </div>
              </li>
            )
          })}
        </ul>
        <div className="border-t border-line px-4 py-1.5 text-[11px] text-muted">{t('pal.keys')}</div>
      </div>
    </div>
  )
}
