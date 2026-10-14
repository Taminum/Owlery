import { useState } from 'react'
import { PAGE_WIDTH } from '../lib/layout'
import { CalendarClock, LogOut, Menu, RefreshCw, Server, Spline, UserRound } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { t } from '../i18n'
import { RANGES, REFRESH, TIMEZONES, setPanelScope, type Filters, type Range } from '../lib/filters'
import type { PanelInfo } from '../lib/types'
import { Popover, controlCls } from './Popover'
import { setSmooth, useSmooth } from '../lib/chartLook'

interface Props {
  filters: Filters
  panels: PanelInfo[]
  update: (patch: Partial<Filters> | ((f: Filters) => Filters)) => void
  onRefresh: () => void
  loading: boolean
  onMenu: () => void
}

const tzLabel = (tz: string) => (tz === 'local' ? t('filter.tzLocal') : tz)
const toLocalInput = (iso?: string) => {
  if (!iso) return ''
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

function NodePicker({ filters, panels, update }: Pick<Props, 'filters' | 'panels' | 'update'>) {
  const scope = filters.panels.length ? panels.filter((p) => filters.panels.includes(p.id)) : panels
  const label = filters.nodes.length ? t('filter.nodesSelected', { n: filters.nodes.length }) : t('filter.nodesAll')
  const toggle = (id: string) =>
    update((f) => ({ ...f, nodes: f.nodes.includes(id) ? f.nodes.filter((n) => n !== id) : [...f.nodes, id] }))
  return (
    <Popover label={t('filter.nodes')} value={label} icon={<Server size={15} className="shrink-0 text-muted" aria-hidden />}>
      {() => (
        <div className="space-y-3">
          <button type="button" onClick={() => update({ nodes: [] })} className="text-xs text-cyan hover:underline">{t('filter.nodesAll')}</button>
          {scope.map((p) => (
            <fieldset key={p.id}>
              <legend className="mb-1 text-xs font-medium text-muted">{p.name}</legend>
              {p.nodes.map((n) => (
                <label key={n.id} className="flex cursor-pointer items-center gap-2 rounded-md px-1.5 py-1.5 text-[13px] hover:bg-surface">
                  <input type="checkbox" className="accent-cyan" checked={filters.nodes.includes(n.id)} onChange={() => toggle(n.id)} />
                  <span className="flex-1 text-fg">{n.name}</span>
                  <span className="text-xs text-muted">{n.agent_status === 'ok' ? t('a11y.statusOk') : t('a11y.statusLag')}</span>
                </label>
              ))}
            </fieldset>
          ))}
        </div>
      )}
    </Popover>
  )
}

function CustomRange({ filters, update }: Pick<Props, 'filters' | 'update'>) {
  const [from, setFrom] = useState(toLocalInput(filters.from))
  const [to, setTo] = useState(toLocalInput(filters.to))
  const valid = from && to && new Date(from) < new Date(to)
  return (
    <Popover label={t('filter.custom')} value={filters.range === 'custom' ? t('range.custom') : t('filter.custom')} icon={<CalendarClock size={15} className="shrink-0 text-muted" aria-hidden />} align="right">
      {(close) => (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            if (!valid) return
            update({ range: 'custom', from: new Date(from).toISOString(), to: new Date(to).toISOString() })
            close()
          }}
        >
          <label className="block text-xs text-muted">{t('filter.from')}
            <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} className={`${controlCls} mt-1 block w-full`} />
          </label>
          <label className="block text-xs text-muted">{t('filter.to')}
            <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} className={`${controlCls} mt-1 block w-full`} />
          </label>
          <button type="submit" disabled={!valid} className="h-9 w-full rounded-control bg-blue text-[13px] font-medium text-white disabled:opacity-40">{t('filter.apply')}</button>
        </form>
      )}
    </Popover>
  )
}

function AccountMenu() {
  const { state, logout } = useAuth()
  if (state.status !== 'authed') return null
  const { account } = state.me
  return (
    <Popover label={t('auth.account')} value={account.username} icon={<UserRound size={15} className="shrink-0 text-muted" aria-hidden />} align="right">
      {(close) => (
        <div className="space-y-3">
          <div className="text-[13px]"><div className="font-medium text-fg">{account.username}</div><div className="text-xs text-muted">{account.is_owner ? t('role.owner') : t('profile.roles').toLowerCase()}</div></div>
          <button type="button" onClick={() => { close(); void logout() }} className="flex w-full items-center gap-2 rounded-control border border-line px-3 py-2 text-[13px] hover:border-cyan/60"><LogOut size={15} aria-hidden />{t('auth.logout')}</button>
        </div>
      )}
    </Popover>
  )
}

export function TopBar({ filters, panels, update, onRefresh, loading, onMenu }: Props) {
  const smooth = useSmooth()
  const presets = RANGES.filter((r): r is Exclude<Range, 'custom'> => r !== 'custom')
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/95 backdrop-blur">
      <div className={`${PAGE_WIDTH} flex flex-wrap items-center gap-2.5 py-3`}>
        <button type="button" onClick={onMenu} aria-label={t('nav.menu')} className={`${controlCls} grid w-10 place-items-center px-0 lg:hidden`}>
          <Menu size={18} aria-hidden />
        </button>

        <label className="sr-only" htmlFor="panel-select">{t('filter.panel')}</label>
        <select id="panel-select" value={filters.panels.length === 1 ? filters.panels[0] : ''} onChange={(e) => update((f) => setPanelScope(f, e.target.value ? [e.target.value] : [], panels))} className={`${controlCls} min-w-[150px]`}>
          <option value="">{t('filter.panelAll')}</option>
          {panels.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>

        <NodePicker filters={filters} panels={panels} update={update} />

        <div role="group" aria-label={t('filter.range')} className="flex h-10 items-center rounded-control border border-line bg-surface p-0.5">
          {presets.map((r) => (
            <button key={r} type="button" aria-pressed={filters.range === r} onClick={() => update({ range: r })} className={`h-8 rounded-[8px] px-2.5 text-[13px] ${filters.range === r ? 'bg-elevated font-medium text-fg shadow-[inset_0_0_0_1px_var(--color-cyan)]' : 'text-muted hover:text-fg'}`}>
              {r}
            </button>
          ))}
        </div>
        <CustomRange filters={filters} update={update} />

        <div className="ml-auto flex flex-wrap items-center gap-2.5">
          <label className="sr-only" htmlFor="tz-select">{t('filter.tz')}</label>
          <select id="tz-select" value={filters.tz} onChange={(e) => update({ tz: e.target.value })} className={`${controlCls} min-w-[120px]`}>
            {TIMEZONES.map((z) => <option key={z} value={z}>{tzLabel(z)}</option>)}
          </select>
          <label className="sr-only" htmlFor="refresh-select">{t('filter.refresh')}</label>
          <select id="refresh-select" value={filters.refresh} onChange={(e) => update({ refresh: e.target.value as Filters['refresh'] })} className={controlCls} title={t('filter.refresh')} aria-label={t('filter.refresh')}>
            {REFRESH.map((r) => <option key={r} value={r}>{r === 'off' ? `${t('filter.refreshShort')}: ${t('filter.refreshOff')}` : `${t('filter.refreshShort')}: ${r}`}</option>)}
          </select>
          <button type="button" aria-pressed={smooth} onClick={() => setSmooth(!smooth)} title={t('filter.smoothHint')} aria-label={t('filter.smooth')}
            className={`${controlCls} grid w-10 place-items-center px-0 ${smooth ? 'border-cyan text-fg' : 'text-muted'}`}>
            <Spline size={16} aria-hidden />
          </button>
          <button type="button" onClick={onRefresh} aria-label={t('filter.refreshNow')} title={t('filter.refreshNow')} className={`${controlCls} grid w-10 place-items-center px-0`}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} aria-hidden />
          </button>
          <AccountMenu />
        </div>
      </div>
    </header>
  )
}
