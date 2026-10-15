import { NavLink, useLocation } from 'react-router-dom'
import { BarChart3, Bell, Compass, Gauge, Globe2, Laptop, Shield, ShieldCheck, Telescope, LayoutDashboard, Radio, Server, Settings, Users, Waypoints, X, type LucideIcon } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import type { AlertsResponse } from '../lib/types'

interface Item { to: string; key: MsgKey; icon: LucideIcon; disabled?: boolean }

const MAIN: Item[] = [
  { to: '/', key: 'nav.overview', icon: LayoutDashboard },
  { to: '/live', key: 'nav.live', icon: Radio },
  { to: '/traffic', key: 'nav.traffic', icon: BarChart3 },
  { to: '/sites', key: 'nav.sites', icon: Compass },
  { to: '/domains', key: 'nav.domains', icon: Globe2 },
  { to: '/users', key: 'nav.users', icon: Users },
  { to: '/awg', key: 'nav.awg', icon: Shield },
  { to: '/security', key: 'nav.security', icon: ShieldCheck },
  { to: '/intel', key: 'nav.intel', icon: Telescope },
  { to: '/nodes', key: 'nav.nodes', icon: Server },
  { to: '/channels', key: 'nav.channels', icon: Gauge },
  { to: '/devices', key: 'nav.devices', icon: Laptop },
  { to: '/panels', key: 'nav.panels', icon: Waypoints },
  { to: '/alerts', key: 'nav.alerts', icon: Bell },
]

/** How many alerts are open right now; checked once a minute. */
function useOpenAlerts(enabled: boolean): number {
  const { data } = useLoad((s) => (enabled ? api.get<AlertsResponse>('/api/v1/alerts', s) : Promise.resolve(null)), [enabled], 60_000)
  return data?.open ?? 0
}

function NavItem({ item, onNavigate }: { item: Item; onNavigate: () => void }) {
  const { search } = useLocation()
  const alerts = useOpenAlerts(item.to === '/alerts' && !item.disabled)
  const badge = item.to === '/alerts' ? alerts : 0
  const Icon = item.icon
  const base = 'flex h-11 items-center gap-3 rounded-control px-3 text-[14px]'
  if (item.disabled) {
    return (
      <span aria-disabled="true" className={`${base} cursor-not-allowed text-muted/60`}>
        <Icon size={18} aria-hidden />
        <span className="flex-1">{t(item.key)}</span>
        <span className="text-[11px]">{t('nav.soon')}</span>
      </span>
    )
  }
  return (
    <NavLink to={{ pathname: item.to, search }} end={item.to === '/'} onClick={onNavigate}
      className={({ isActive }) => `${base} ${isActive ? 'bg-blue/20 font-medium text-fg shadow-[inset_0_0_0_1px_rgba(81,139,250,0.45)]' : 'text-muted hover:bg-surface hover:text-fg'}`}>
      <Icon size={18} aria-hidden />
      <span className="flex-1">{t(item.key)}</span>
      {badge > 0 && <span aria-label={t('nav.alertsOpen', { n: badge })} className="grid h-5 min-w-5 place-items-center rounded-full bg-amber px-1.5 text-[11px] font-semibold text-black">{badge}</span>}
    </NavLink>
  )
}

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={onClose} aria-hidden />}
      <aside aria-label={t('nav.menu')} className={`fixed inset-y-0 left-0 z-40 flex w-[244px] flex-col border-r border-line bg-sidebar transition-transform lg:sticky lg:top-0 lg:z-auto lg:h-screen lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-[68px] items-center justify-between px-5">
          <div>
            <div className="text-xl font-semibold leading-6 tracking-tight text-fg">{t('app.name')}</div>
            <div className="text-xs text-muted">{t('app.tagline')}</div>
          </div>
          <button type="button" onClick={onClose} aria-label={t('nav.close')} className="grid h-9 w-9 place-items-center rounded-control text-muted hover:bg-surface lg:hidden">
            <X size={18} aria-hidden />
          </button>
        </div>
        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
          {MAIN.map((i) => <NavItem key={i.to} item={i} onNavigate={onClose} />)}
        </nav>
        <div className="border-t border-line p-3">
          <NavItem item={{ to: '/settings', key: 'nav.settings', icon: Settings }} onNavigate={onClose} />
        </div>
      </aside>
    </>
  )
}
