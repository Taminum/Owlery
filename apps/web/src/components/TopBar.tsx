import { useState } from 'react'
import { PAGE_WIDTH } from '../lib/layout'
import { CalendarClock, Menu, RefreshCw, Server, SlidersHorizontal, Spline } from 'lucide-react'
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
  /** Only the menu button and the account: for pages that do not read the filters. */
  slim?: boolean
  /** The panel choice and nothing else: for pages that depend on the panel but on no period. */
  panelOnly?: boolean
}

// What a page reads decides what its bar holds. Pages that read none of the filters (panel, nodes, period, refresh) get
// a bar without them; pages whose content depends on the panel but not on a period get the panel alone, so a period
// that changes nothing is not offered (AmneziaWG has its own, of another kind).
const NO_FILTERS = ['/servers', '/hosts', '/security', '/billing', '/intel', '/start', '/channels', '/panels', '/settings']
const PANEL_ONLY = ['/alerts', '/awg']
const under = (list: string[], pathname: string) => list.some((p) => pathname === p || pathname.startsWith(p + '/'))
export function filterMode(pathname: string): 'full' | 'panel' | 'none' {
  return under(NO_FILTERS, pathname) ? 'none' : under(PANEL_ONLY, pathname) ? 'panel' : 'full'
}
export function pageUsesFilters(pathname: string): boolean {
  return filterMode(pathname) !== 'none'
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
    <Popover label={t('filter.custom')} value={filters.range === 'custom' ? t('range.custom') : t('filter.custom')} icon={<CalendarClock size={15} className="shrink-0 text-muted" aria-hidden />} align="right" compact active={filters.range === 'custom'}>
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
          <button type="submit" disabled={!valid} className="h-9 w-full rounded-control bg-btn text-[13px] font-medium text-white disabled:opacity-40">{t('filter.apply')}</button>
        </form>
      )}
    </Popover>
  )
}

export function TopBar({ filters, panels, update, onRefresh, loading, onMenu, slim, panelOnly }: Props) {
  const smooth = useSmooth()
  const [more, setMore] = useState(false)
  const presets = RANGES.filter((r): r is Exclude<Range, 'custom'> => r !== 'custom')
  if (slim) {
    return (
      // A page with no filters has nothing to put in a bar: on a wide screen there is none, and on a phone there is
      // only the button that opens the menu (the account is at the foot of the menu).
      <header className="top-0 z-20 border-b border-line bg-canvas lg:hidden [@media(min-height:700px)]:sticky">
        <div className={`${PAGE_WIDTH} flex items-center gap-2.5 py-2`}>
          <button type="button" onClick={onMenu} aria-label={t('nav.menu')} className={`${controlCls} grid w-10 place-items-center px-0`}>
            <Menu size={18} aria-hidden />
          </button>
        </div>
      </header>
    )
  }
  return (
    <header className="top-0 z-20 border-b border-line bg-canvas [@media(min-height:700px)]:sticky">
      <div className={`${PAGE_WIDTH} flex flex-wrap items-center gap-2.5 py-3`}>
        <button type="button" onClick={onMenu} aria-label={t('nav.menu')} className={`${controlCls} grid w-10 place-items-center px-0 lg:hidden`}>
          <Menu size={18} aria-hidden />
        </button>

        <label className="sr-only" htmlFor="panel-select">{t('filter.panel')}</label>
        <select id="panel-select" value={filters.panels.length === 1 ? filters.panels[0] : ''} onChange={(e) => update((f) => setPanelScope(f, e.target.value ? [e.target.value] : [], panels))} className={`${controlCls} min-w-0 flex-1 basis-[90px] lg:min-w-[150px] lg:flex-none lg:basis-auto`}>
          <option value="">{t('filter.panelAll')}</option>
          {panels.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>

        {!panelOnly && <NodePicker filters={filters} panels={panels} update={update} />}

        {!panelOnly && <button type="button" onClick={() => setMore((v) => !v)} aria-expanded={more} aria-label={t('filter.more')} title={t('filter.more')}
          className={`${controlCls} ml-auto grid w-10 place-items-center px-0 sm:order-2 2xl:hidden ${more ? 'border-cyan text-fg' : ''}`}>
          <SlidersHorizontal size={16} aria-hidden />
        </button>}

        {/* On a phone the period, time zone and refresh controls sit behind the button above, so the page is not
            pushed down by five rows of filters. From the sm width up the period is in the bar, and the rarely touched ones
            (time zone, auto refresh, smoothing) stay behind the button until the bar is wide enough to hold them in one row. */}
        {!panelOnly && <div className={`${more ? 'flex' : 'hidden'} w-full flex-wrap items-center gap-2.5 sm:contents`}>

        <div role="group" aria-label={t('filter.range')} className="flex h-10 items-center rounded-control border border-line bg-surface p-0.5">
          {presets.map((r) => (
            <button key={r} type="button" aria-pressed={filters.range === r} onClick={() => update({ range: r })} className={`h-8 rounded-[8px] px-2.5 text-[13px] ${filters.range === r ? 'bg-elevated font-medium text-fg shadow-[inset_0_0_0_1px_var(--color-cyan)]' : 'text-muted hover:text-fg'}`}>
              {r}
            </button>
          ))}
        </div>
        <CustomRange filters={filters} update={update} />

        <div className={`${more ? 'flex' : 'hidden'} flex-wrap items-center gap-2.5 sm:order-3 sm:w-full sm:justify-end 2xl:ml-auto 2xl:flex 2xl:w-auto`}>
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
        </div>
        </div>}
      </div>
    </header>
  )
}
