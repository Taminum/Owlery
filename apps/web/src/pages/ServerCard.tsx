import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, StickyNote } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatDateTime, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { ServerAlert } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { GhostButton } from '../components/Modal'
import { HardwareSection } from '../components/HardwareView'
import { HostDetail, Meter, uptimeText } from '../components/HostView'
import { AgentBlock } from '../components/AgentSetup'
import { InventoryDialog, RoleChips, StatusChip, durationText, placeText, type Server } from '../components/ServerParts'
import { SecurityTabs } from './Security'
import { TerminalView } from '../components/TerminalView'
import { DesktopView } from '../components/DesktopView'
import { ScreenView } from '../components/ScreenView'
import { ManageView } from '../components/ManageView'
import { ServicesView } from '../components/ServicesView'

type Tab = 'overview' | 'resources' | 'terminal' | 'desktop' | 'screen' | 'manage' | 'services' | 'security' | 'network' | 'history'
const TABS: Tab[] = ['overview', 'resources', 'terminal', 'desktop', 'screen', 'manage', 'services', 'security', 'network', 'history']

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
  if (!h?.has_data) return <Card title={t('srv.now')}><p className="text-[13px] text-muted">{t('srv.noData')}</p></Card>
  const root = h.disks.find((d) => d.m === '/') ?? h.disks[0]
  const memPct = h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  return (
    <Card title={t('srv.now')} note={`${t('host.up')} ${uptimeText(h.uptime)}`}>
      <div className="space-y-3">
        <Meter label={t('host.cpu')} pct={h.cpu} detail={t('host.loadAvg', { n: h.load1.toFixed(2) })} />
        <Meter label={t('host.mem')} pct={memPct} detail={`${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}`} />
        <Meter label={root ? `${t('host.disk')} ${root.m}` : t('host.disk')} pct={root && root.t > 0 ? (root.u * 100) / root.t : null} detail={root ? `${formatBytes(root.u)} / ${formatBytes(root.t)}` : ''} />
        <p className="text-xs text-muted">{t('host.net')}: ↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {t('host.conns', { n: h.estab })}</p>
      </div>
    </Card>
  )
}

function Network({ s }: { s: Server }) {
  return (
    <Card title={t('srv.nodes.title')}>
      {s.nodes.length === 0 ? <p className="text-[13px] text-muted">{t('srv.nodes.empty')}</p> : (
        <ul className="divide-y divide-line">
          {s.nodes.map((n) => (
            <li key={n.node_id} className="flex flex-wrap items-center justify-between gap-3 py-2 text-[13px]">
              <span>{n.name} <span className="text-xs text-muted">· {n.panel_name}{n.xray && ` · Xray ${n.xray}`}</span></span>
              <span className="flex items-center gap-3 text-xs text-muted">
                {t('srv.nodes.users', { n: n.users_online })}
                <Chip tone={n.online ? 'green' : 'red'}>{n.online ? t('srv.nodes.on') : t('srv.nodes.off')}</Chip>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

export default function ServerCard() {
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const q = useLoad((sig) => api.get<Server>(`/api/v1/servers/${id}`, sig), [id], 30_000)
  const [editing, setEditing] = useState(false)
  const wanted = params.get('view') as Tab | null
  const tab: Tab = wanted && TABS.includes(wanted) ? wanted : 'overview'
  const setTab = (x: Tab) => setParams(x === 'overview' ? {} : { view: x }, { replace: true })
  const s = q.data

  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!s) return <TableSkeleton />
  const open = (s.alerts ?? []).filter((a) => !a.resolved_at)
  return (
    <div className="space-y-4">
      <Link to="/servers" className="inline-flex items-center gap-2 text-[13px] text-muted hover:text-fg"><ArrowLeft size={15} aria-hidden />{t('srv.back')}</Link>
      <PageHead title={s.name} subtitle={[s.os || s.host?.os, s.provider, placeText(s)].filter(Boolean).join(' · ') || t('srv.subtitle')} right={<div className="flex items-center gap-3"><About s={s} onEdit={() => setEditing(true)} /><StatusChip s={s} /></div>} />

      <div role="tablist" aria-label={s.name} className="flex flex-wrap gap-2">
        {TABS.filter((x) => (x !== 'terminal' && x !== 'desktop' && x !== 'screen' && x !== 'manage' && x !== 'services') || s.can_edit).map((x) => (
          <button key={x} role="tab" type="button" aria-selected={tab === x} onClick={() => setTab(x)}
            className={`h-8 rounded-control border px-3 text-[13px] ${tab === x ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>
            {t(`srv.tab.${x}` as MsgKey)}{x === 'history' && open.length > 0 && <span className="ml-1.5 text-amber">{open.length}</span>}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="space-y-5">
          <div className="grid gap-4 lg:grid-cols-2">
            <Now s={s} />
            <Card title={t('srv.openAlerts')}><AlertList items={open} empty={t('srv.noAlerts')} /></Card>
          </div>
          {s.hardware && <HardwareSection hw={s.hardware} host={s.host} />}
        </div>
      )}
      {tab === 'resources' && (s.host?.has_data ? <HostDetail host={s.host} /> : <p className="text-[13px] text-muted">{t('srv.noData')}</p>)}
      {tab === 'security' && (
        <div className="space-y-4">
          <AgentBlock vpsId={s.id} canEdit={s.can_edit} hostOS={s.os || s.host?.os} />
          <SecurityTabs v={s} />
          <p className="text-[13px] text-muted">{t('srv.security.full')}: <Link to={`/security/${s.id}`} className="text-cyan underline-offset-2 hover:underline">{t('srv.security.open')}</Link></p>
        </div>
      )}
      {tab === 'terminal' && s.can_edit && <TerminalView serverId={s.id} />}
      {tab === 'desktop' && s.can_edit && <DesktopView serverId={s.id} />}
      {tab === 'screen' && s.can_edit && <ScreenView serverId={s.id} />}
      {tab === 'manage' && s.can_edit && <ManageView serverId={s.id} />}
      {tab === 'services' && s.can_edit && <ServicesView serverId={s.id} serverName={s.name} />}
      {tab === 'network' && <Network s={s} />}
      {tab === 'history' && <Card title={t('srv.history.title')}><AlertList items={s.alerts ?? []} empty={t('srv.history.empty')} /></Card>}

      {editing && <InventoryDialog s={s} onClose={() => setEditing(false)} onDone={() => { setEditing(false); q.reload() }} />}
    </div>
  )
}
