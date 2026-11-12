import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, StickyNote } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatDateTime, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { ServerAlert } from '../lib/types'
import { Card, Chip, Segmented, Tabs } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { GhostButton } from '../components/Modal'
import { HardwareSection } from '../components/HardwareView'
import { HostDetail, Line, Meter, loadDetail, uptimeText, type Point } from '../components/HostView'
import { AgentBlock } from '../components/AgentSetup'
import { InventoryDialog, RoleChips, StatusChip, durationText, placeText, type Server } from '../components/ServerParts'
import { SecurityTabs } from './Security'
import { TerminalView } from '../components/TerminalView'
import { DesktopView } from '../components/DesktopView'
import { ScreenView } from '../components/ScreenView'
import { ManageView } from '../components/ManageView'
import { ServicesView } from '../components/ServicesView'
import { RdpProtect } from '../components/RdpProtect'
import { AlertRules } from '../components/AlertRules'
import { Maintenance, MaintenanceBanner } from '../components/Maintenance'
import { WakeOnLan } from '../components/WakeOnLan'
import { DockerView } from '../components/DockerView'
import { NetworkView } from '../components/NetworkView'

type Tab = 'overview' | 'resources' | 'terminal' | 'desktop' | 'screen' | 'manage' | 'services' | 'security' | 'protect' | 'docker' | 'alerts' | 'network' | 'history'
const TABS: Tab[] = ['overview', 'resources', 'terminal', 'desktop', 'screen', 'manage', 'services', 'security', 'protect', 'docker', 'alerts', 'network', 'history']

/**
 * The thirteen views of a machine are shown as six tabs. The address still names the view (?view=protect), so every link
 * that was ever made keeps working: a group is only what a view is shown under, and a view that is not a tab of its own
 * (network, history) is a part of the page of its group.
 */
type Group = 'overview' | 'load' | 'access' | 'manage' | 'protect' | 'alerts'
const GROUPS: { id: Group; views: Tab[] }[] = [
  { id: 'overview', views: ['overview', 'network'] },
  { id: 'load', views: ['resources', 'docker'] },
  { id: 'access', views: ['terminal', 'desktop', 'screen'] },
  { id: 'manage', views: ['manage', 'services'] },
  { id: 'protect', views: ['security', 'protect'] },
  { id: 'alerts', views: ['alerts', 'history'] },
]
const groupOf = (v: Tab): Group => GROUPS.find((g) => g.views.includes(v))?.id ?? 'overview'
/** The views that a group offers as a choice inside it; the others (network, history) are sections of a page. */
const CHOICE: Record<Group, Tab[]> = { overview: [], load: ['resources', 'docker'], access: ['terminal', 'desktop', 'screen'], manage: ['manage', 'services'], protect: ['security', 'protect'], alerts: [] }
const PART_LABEL: Partial<Record<Tab, MsgKey>> = { terminal: 'srv.tab.terminal', desktop: 'srv.tab.desktop', screen: 'srv.tab.screen', resources: 'srv.part.resources', docker: 'srv.part.docker', manage: 'srv.part.manage', services: 'srv.part.services', security: 'srv.part.security', protect: 'srv.part.protect' }

function AlertList({ items, empty }: { items: ServerAlert[]; empty: string }) {
  if (items.length === 0) return <p className="text-[13px] text-muted">{empty}</p>
  return (
    <ul className="divide-y divide-line">
      {items.map((a) => (
        <li key={a.id} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2 text-[13px]">
          <span className="min-w-0">
            <span className={a.resolved_at ? 'text-fg' : 'font-medium text-amber'}>{a.label}</span>
            {a.detail && <span className="block text-xs text-muted">{a.detail}</span>}
          </span>
          <span className="shrink-0 text-xs text-muted">
            {formatDateTime(a.opened_at, 'local')} · {a.resolved_at ? t('srv.history.lasted', { d: durationText(a.opened_at, a.resolved_at) }) : `${t('srv.history.open')}, ${durationText(a.opened_at, null)}`}
          </span>
        </li>
      ))}
    </ul>
  )
}

/** What is known about the machine, as a note by its name: a button that opens a small panel with only the filled fields. */
export function About({ s, onEdit }: { s: Server; onEdit: () => void }) {
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', away)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc) }
  }, [open])
  const rows: [MsgKey, ReactNode][] = []
  if (s.roles?.length) rows.push(['srv.inv.roles', <RoleChips roles={s.roles} />])
  if (s.os || s.host?.os) rows.push(['srv.inv.os', s.os || s.host?.os])
  if (s.provider) rows.push(['srv.inv.provider', s.provider])
  if (placeText(s)) rows.push(['srv.inv.place', placeText(s)])
  if (s.group) rows.push(['srv.inv.group', s.group])
  if (s.tags?.length) rows.push(['srv.inv.tags', s.tags.join(', ')])
  if (s.purchased_on) rows.push(['srv.inv.purchased', s.purchased_on.slice(0, 10)])
  if (s.addresses.length) rows.push(['srv.inv.addresses', <span className="font-mono">{s.addresses.map((a) => a.address).join(', ')}</span>])
  if (s.note) rows.push(['srv.inv.note', s.note])
  const filled = rows.length > 0
  if (!filled && !s.can_edit) return null
  return (
    <div ref={box} className="relative">
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)}
        className="inline-flex h-8 items-center gap-1.5 rounded-control border border-line px-3 text-[13px] text-muted hover:text-fg">
        <StickyNote size={14} aria-hidden />{filled ? t('srv.about') : t('srv.about.add')}
      </button>
      {open && (
        <div role="dialog" aria-label={t('srv.about')} className="absolute right-0 top-full z-20 mt-2 w-[340px] max-w-[88vw] rounded-card border border-line bg-surface p-3 shadow-lg">
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="text-[13px] font-semibold">{t('srv.about')}</span>
            {s.can_edit && <GhostButton onClick={() => { setOpen(false); onEdit() }}>{t('srv.inv.edit')}</GhostButton>}
          </div>
          {filled ? (
            <>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[13px]">
                {rows.map(([k, v]) => <div key={k} className="contents"><dt className="text-muted">{t(k)}</dt><dd className="min-w-0 break-words">{v}</dd></div>)}
              </dl>
              <p className="mt-2 text-xs text-muted">{t('srv.about.hidden')}</p>
            </>
          ) : <p className="text-[13px] text-muted">{t('srv.about.empty')}</p>}
          {!s.can_edit && <p className="mt-2 text-xs text-muted">{t('srv.inv.readonly')}</p>}
        </div>
      )}
    </div>
  )
}

function Now({ s }: { s: Server }) {
  const h = s.host
  // The last hour of the processor and memory, inside the card; looked at again every 15 seconds.
  const hostId = h?.has_data ? h.id : ''
  const hour = useLoad((sig) => (hostId ? api.get<{ points: Point[] }>(`/api/v1/hosts/${hostId}/series?hours=1`, sig) : Promise.resolve(null)), [hostId], 15_000)
  const pts = hour.data?.points ?? []
  const series = (f: (p: Point) => number | null) => pts.map((p) => ({ x: new Date(p.at).getTime(), y: f(p) }))
  if (!h?.has_data) return <Card title={t('srv.now')}><p className="text-[13px] text-muted">{t('srv.noData')}</p></Card>
  const root = h.disks.find((d) => d.m === '/') ?? h.disks[0]
  const memPct = h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  return (
    <Card title={t('srv.now')} note={`${t('host.up')} ${uptimeText(h.uptime)}`}>
      <div className="space-y-3">
        <Meter label={t('host.cpu')} pct={h.cpu} detail={loadDetail(h)} />
        <Meter label={t('host.mem')} pct={memPct} detail={`${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}`} />
        <Meter label={root ? `${t('host.disk')} ${root.m}` : t('host.disk')} pct={root && root.t > 0 ? (root.u * 100) / root.t : null} detail={root ? `${formatBytes(root.u)} / ${formatBytes(root.t)}` : ''} />
        {(h.reboot_required || (h.updates_pending ?? 0) > 0) && (
          <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
            {(h.updates_pending ?? 0) > 0 && <span>{t('host.updates', { n: h.updates_pending ?? 0 })}{(h.updates_security ?? 0) > 0 && <> · <span className="text-amber">{t('host.updatesSec', { n: h.updates_security ?? 0 })}</span></>}</span>}
            {h.reboot_required && <Chip tone="amber">{t('host.reboot')}</Chip>}
          </p>
        )}
        <p className="text-xs text-muted">{t('host.net')}: ↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {t('host.conns', { n: h.estab })}</p>
        {pts.length > 1 && (
          <div>
            <p className="mb-1 text-xs text-muted">{t('srv.lastHour')}</p>
            <div className="grid gap-4 sm:grid-cols-2">
              <Line title={t('host.cpu')} points={series((p) => p.cpu)} max={100} format={(v) => `${Math.round(v)}%`} />
              <Line title={t('host.mem')} points={series((p) => p.mem_pct)} max={100} format={(v) => `${Math.round(v)}%`} color="var(--color-blue)" />
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}

export default function ServerCard() {
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const q = useLoad((sig) => api.get<Server>(`/api/v1/servers/${id}`, sig), [id], 5_000)
  const [editing, setEditing] = useState(false)
  const wanted = params.get('view') as Tab | null
  const requested: Tab = wanted && TABS.includes(wanted) ? wanted : 'overview'
  const setTab = (x: Tab) => setParams(x === 'overview' ? {} : { view: x }, { replace: true })
  const s = q.data
  const tab = requested

  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!s) return <TableSkeleton />
  const open = (s.alerts ?? []).filter((a) => !a.resolved_at)
  const isWindows = /windows/i.test(s.os || s.host?.os || '')
  // What of a group is offered on this machine: what needs the owner, Windows or Docker is left out where it does not apply.
  const views = (g: Group): Tab[] => GROUPS.find((x) => x.id === g)!.views.filter((x) => ((x !== 'terminal' && x !== 'desktop' && x !== 'screen' && x !== 'manage' && x !== 'services') || s.can_edit) && (x !== 'protect' || isWindows) && (x !== 'docker' || !!s.docker))
  const offered = views
  const firstOf = (g: Group): Tab => views(g)[0]
  const group = groupOf(tab)
  const choice = CHOICE[group].filter((x) => views(group).includes(x))
  return (
    <div className="space-y-4">
      <Link to="/servers" className="inline-flex items-center gap-2 py-2 text-[13px] text-muted hover:text-fg"><ArrowLeft size={15} aria-hidden />{t('srv.back')}</Link>
      <PageHead title={s.name} subtitle={[s.os || s.host?.os, s.provider, placeText(s)].filter(Boolean).join(' · ') || t('srv.subtitle')} right={<div className="flex items-center gap-3"><About s={s} onEdit={() => setEditing(true)} /><StatusChip s={s} /></div>} />

      {s.maint_until && <MaintenanceBanner until={s.maint_until} note={s.maint_note} canEdit={s.can_edit} serverId={s.id} onChange={q.reload} />}

      <Tabs label={s.name} value={group} onChange={(g) => setTab(firstOf(g))}
        tabs={GROUPS.filter((g) => offered(g.id).length > 0).map((g) => ({ id: g.id, label: t(`srv.group.${g.id}` as MsgKey), badge: g.id === 'alerts' && open.length > 0 ? open.length : undefined }))} />
      {choice.length > 1 && (
        <Segmented label={t(`srv.group.${group}` as MsgKey)} value={tab} onChange={setTab} options={choice.map((x) => ({ value: x, label: t(PART_LABEL[x] as MsgKey) }))} />
      )}

      {group === 'overview' && (
        <div className="space-y-5">
          <div className="grid gap-4 lg:grid-cols-2">
            <Now s={s} />
            <Card title={t('srv.openAlerts')}><AlertList items={open} empty={t('srv.noAlerts')} /></Card>
          </div>
          {s.hardware && <HardwareSection hw={s.hardware} host={s.host} />}
          {s.can_edit && s.agent && <WakeOnLan serverId={s.id} onChange={q.reload} />}
          <NetworkView s={s} />
        </div>
      )}
      {tab === 'resources' && (s.host?.has_data ? <HostDetail host={s.host} /> : <p className="text-[13px] text-muted">{t('srv.noData')}</p>)}
      {tab === 'docker' && <DockerView info={s.docker} serverId={s.id} canCtl={!!s.docker_ctl} />}
      {tab === 'security' && (
        <div className="space-y-4">
          <AgentBlock vpsId={s.id} canEdit={s.can_edit} hostOS={s.os || s.host?.os} />
          <SecurityTabs v={s} />
          <p className="text-[13px] text-muted">{t('srv.security.full')}: <Link to={`/security/${s.id}`} className="text-cyan underline-offset-2 hover:underline">{t('srv.security.open')}</Link></p>
        </div>
      )}
      {tab === 'protect' && isWindows && <RdpProtect serverId={s.id} />}
      {group === 'alerts' && (
        <div className="space-y-4">
          {s.host?.has_data && (
            <>
              <Maintenance serverId={s.id} canEdit={s.can_edit} until={s.maint_until} note={s.maint_note} onChange={q.reload} />
              <AlertRules serverId={s.id} name={s.name} />
            </>
          )}
          <Card title={t('srv.history.title')}><AlertList items={s.alerts ?? []} empty={t('srv.history.empty')} /></Card>
        </div>
      )}
      {tab === 'terminal' && s.can_edit && <TerminalView serverId={s.id} />}
      {tab === 'desktop' && s.can_edit && <DesktopView serverId={s.id} />}
      {tab === 'screen' && s.can_edit && <ScreenView serverId={s.id} canLaunch={!!s.agent?.can_shell && !!s.agent?.can_admin} />}
      {tab === 'manage' && s.can_edit && <ManageView serverId={s.id} />}
      {tab === 'services' && s.can_edit && <ServicesView serverId={s.id} serverName={s.name} />}

      {editing && <InventoryDialog s={s} onClose={() => setEditing(false)} onDone={() => { setEditing(false); q.reload() }} />}
    </div>
  )
}
