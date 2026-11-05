import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, LayoutGrid, List } from 'lucide-react'
import { t } from '../i18n'
import { formatBytes, formatRate } from '../lib/format'
import { buildBlocks, loadFolded, loadView, parkSummary, saveFolded, saveView, shownAddress, type View } from '../lib/parks'
import { Card } from './ui'
import { Meter, tone, uptimeText } from './HostView'
import { RoleChips, StatusChip, StatusDot, placeText, type Server } from './ServerParts'

function Tile({ s }: { s: Server }) {
  const h = s.host
  const root = h?.disks.find((d) => d.m === '/') ?? h?.disks[0]
  const memPct = h && h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  const sub = [s.os || h?.os, s.provider, placeText(s)].filter(Boolean).join(' · ')
  const addr = shownAddress(s)
  return (
    <Link to={`/servers/${s.id}`} title={s.note || undefined} className="block rounded-card focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan">
      <Card title={s.name} note={sub || undefined} right={<StatusChip s={s} />} className="h-full transition-colors hover:border-cyan/50">
        <div className="space-y-3">
          <RoleChips roles={s.roles} />
          {h?.has_data ? (
            <>
              <Meter label={t('host.cpu')} pct={h.cpu} detail={t('host.loadAvg', { n: h.load1.toFixed(2) })} />
              <Meter label={t('host.mem')} pct={memPct} detail={`${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}`} />
              <Meter label={root ? `${t('host.disk')} ${root.m}` : t('host.disk')} pct={root && root.t > 0 ? (root.u * 100) / root.t : null} detail={root ? `${formatBytes(root.u)} / ${formatBytes(root.t)}` : ''} />
              <p className="text-xs text-muted">↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {t('host.up')} {uptimeText(h.uptime)}</p>
            </>
          ) : <p className="text-[13px] text-muted">{t('srv.reason.no_agent')}</p>}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
            {addr && <span className="tnum">{addr}</span>}
            {s.alerts_open > 0 && <span className={s.alerts_critical > 0 ? 'text-red' : 'text-amber'}>{t('srv.alerts', { n: s.alerts_open })}</span>}
            {s.nodes.length > 0 && <span className="truncate">{t('srv.nodesShort', { names: s.nodes.map((n) => n.name).join(', ') })}</span>}
          </div>
        </div>
      </Card>
    </Link>
  )
}

const BAR = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' } as const

function Mini({ label, pct }: { label: string; pct: number | null }) {
  const v = pct === null ? 0 : Math.max(0, Math.min(100, pct))
  return (
    <div className="hidden min-w-0 md:block">
      <div className="h-1.5 overflow-hidden rounded-full bg-elevated" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)}>
        <div className={`h-full rounded-full ${BAR[tone(v)]}`} style={{ width: `${v}%` }} />
      </div>
      <span className="tnum text-[11px] text-muted">{label} {pct === null ? '—' : `${Math.round(pct)}%`}</span>
    </div>
  )
}

const ROW = 'grid items-center gap-3 border-t border-line/60 px-3 py-2 text-[13px] hover:bg-elevated focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan grid-cols-[10px_minmax(0,1fr)_auto] md:grid-cols-[10px_minmax(0,1.6fr)_minmax(0,0.9fr)_70px_70px_70px_100px]'

function Row({ s }: { s: Server }) {
  const h = s.host
  const root = h?.disks.find((d) => d.m === '/') ?? h?.disks[0]
  const memPct = h && h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  const sub = [s.os || h?.os, h?.has_data ? `${t('host.up')} ${uptimeText(h.uptime)}` : ''].filter(Boolean).join(' · ')
  const noData = !h?.has_data
  return (
    <Link to={`/servers/${s.id}`} className={ROW}>
      <StatusDot s={s} />
      <span className="min-w-0" title={s.note || undefined}>
        <span className="block truncate font-medium">{s.name}</span>
        <span className="block truncate text-xs text-muted">{sub || '—'}</span>
      </span>
      <span className="tnum hidden truncate text-xs text-muted md:block">{shownAddress(s) || '—'}</span>
      <Mini label="ЦП" pct={noData ? null : h!.cpu} />
      <Mini label="ОЗУ" pct={noData ? null : memPct} />
      <Mini label={root ? root.m : t('host.disk')} pct={noData || !root || root.t <= 0 ? null : (root.u * 100) / root.t} />
      <span className="justify-self-end"><StatusChip s={s} /></span>
    </Link>
  )
}

function Machines({ servers, view }: { servers: Server[]; view: View }) {
  if (view === 'list') {
    return <div className="overflow-hidden rounded-card border border-line bg-surface [&>a:first-child]:border-t-0">{servers.map((s) => <Row key={s.id} s={s} />)}</div>
  }
  return <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{servers.map((s) => <Tile key={s.id} s={s} />)}</div>
}

function ParkHeader({ name, servers, folded, onToggle }: { name: string; servers: Server[]; folded: boolean; onToggle: () => void }) {
  const sum = parkSummary(servers)
  return (
    <button type="button" aria-expanded={!folded} onClick={onToggle}
      className="flex w-full items-center gap-2 rounded-control border border-line bg-elevated px-3 py-2 text-left text-[13px] hover:border-cyan/50">
      {folded ? <ChevronRight size={16} aria-hidden /> : <ChevronDown size={16} aria-hidden />}
      <span className="font-semibold">{name}</span>
      <span className="text-xs text-muted">{t('srv.machines', { n: servers.length })}</span>
      <span className="ml-auto flex items-center gap-1.5">
        {servers.map((s) => <StatusDot key={s.id} s={s} />)}
        {sum.attention > 0
          ? <span className={`rounded-full border px-2 py-0.5 text-xs ${sum.worst === 'bad' ? 'border-red/40 text-red' : 'border-amber/40 text-amber'}`}>{t('srv.attention', { n: sum.attention })}</span>
          : sum.worst === 'ok' ? <span className="text-xs text-muted">{t('srv.allOk')}</span> : null}
      </span>
    </button>
  )
}

/** The fleet as the Servers page shows it: groups, the parks inside them, and the machines as cards or as a list. */
export function ServerGroups({ list }: { list: Server[] }) {
  const blocks = buildBlocks(list)
  const biggest = Math.max(0, ...blocks.map((b) => b.count))
  const [chosen, setChosen] = useState<View | null>(loadView())
  const view: View = chosen ?? (biggest > 6 ? 'list' : 'cards')
  const [folded, setFolded] = useState<Set<string>>(loadFolded())
  function pick(v: View) { setChosen(v); saveView(v) }
  function toggle(key: string) {
    const next = new Set(folded)
    if (!next.delete(key)) next.add(key)
    setFolded(next)
    saveFolded(next)
  }
  const btn = (v: View, label: string, icon: ReactNode) => (
    <button type="button" role="radio" aria-checked={view === v} onClick={() => pick(v)}
      className={`flex h-8 items-center gap-1.5 px-3 text-[13px] ${view === v ? 'bg-elevated text-fg' : 'text-muted hover:text-fg'}`}>{icon}{label}</button>
  )
  return (
    <div className="space-y-5">
      <div className="flex justify-end">
        <div role="radiogroup" aria-label={t('srv.view')} className="flex overflow-hidden rounded-control border border-line">
          {btn('cards', t('srv.view.cards'), <LayoutGrid size={14} aria-hidden />)}
          {btn('list', t('srv.view.list'), <List size={14} aria-hidden />)}
        </div>
      </div>
      {blocks.map((b) => {
        const groupKey = `group:${b.name}`
        const groupFolded = folded.has(groupKey)
        const all = b.parks.flatMap((p) => p.servers)
        const sum = parkSummary(all)
        return (
        <section key={b.name || '-'} className="space-y-3" aria-label={b.name || t('srv.noGroup')}>
          {(blocks.length > 1 || b.name) && (
            <h2 className="text-[13px] font-semibold uppercase tracking-wide text-muted">
              <button type="button" aria-expanded={!groupFolded} onClick={() => toggle(groupKey)} className="flex items-center gap-1.5 uppercase hover:text-fg">
                {groupFolded ? <ChevronRight size={14} aria-hidden /> : <ChevronDown size={14} aria-hidden />}
                {b.name || t('srv.noGroup')} <span className="font-normal">· {b.count}</span>
                {groupFolded && sum.attention > 0 && <span className={`ml-1 rounded-full border px-2 py-0.5 text-xs font-normal normal-case ${sum.worst === 'bad' ? 'border-red/40 text-red' : 'border-amber/40 text-amber'}`}>{t('srv.attention', { n: sum.attention })}</span>}
              </button>
            </h2>
          )}
          {groupFolded ? null : !b.hasParks ? <Machines servers={b.parks[0].servers} view={view} /> : b.parks.map((p) => {
            const key = `${b.name}/${p.name}`
            const isFolded = folded.has(key)
            return (
              <div key={key} className="space-y-2">
                <ParkHeader name={p.name || t('srv.noPark')} servers={p.servers} folded={isFolded} onToggle={() => toggle(key)} />
                {!isFolded && <Machines servers={p.servers} view={view} />}
              </div>
            )
          })}
        </section>
        )
      })}
    </div>
  )
}
