import { Link } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { Meter, uptimeText } from '../components/HostView'
import { RoleChips, StatusChip, placeText, type Server } from '../components/ServerParts'

function Tile({ s }: { s: Server }) {
  const h = s.host
  const root = h?.disks.find((d) => d.m === '/') ?? h?.disks[0]
  const memPct = h && h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  const sub = [s.os || h?.os, s.provider, placeText(s)].filter(Boolean).join(' · ')
  return (
    <Link to={`/servers/${s.id}`} className="block rounded-card focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan">
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
            {s.alerts_open > 0 && <span className={s.alerts_critical > 0 ? 'text-red' : 'text-amber'}>{t('srv.alerts', { n: s.alerts_open })}</span>}
            {s.nodes.length > 0 && <span className="truncate">{t('srv.nodesShort', { names: s.nodes.map((n) => n.name).join(', ') })}</span>}
          </div>
        </div>
      </Card>
    </Link>
  )
}

export default function Servers() {
  const q = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 30_000)
  const list = q.data?.servers ?? []
  // Machines of one group stand together; groups go by name, machines without a group last.
  const groups = new Map<string, Server[]>()
  for (const s of list) groups.set(s.group ?? '', [...(groups.get(s.group ?? '') ?? []), s])
  const order = [...groups.keys()].sort((a, b) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b, 'ru')))
  return (
    <div className="space-y-5">
      <PageHead title={t('srv.title')} subtitle={t('srv.subtitle')}
        right={<Link to="/security" className="inline-flex h-9 items-center rounded-control border border-line px-3 text-[13px] text-muted hover:text-fg">{t('srv.add')}</Link>} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && list.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('srv.empty')}</p>}
      {order.map((g) => (
        <section key={g || '-'} className="space-y-3" aria-label={g || t('srv.noGroup')}>
          {(order.length > 1 || g) && <h2 className="text-[13px] font-semibold uppercase tracking-wide text-muted">{g || t('srv.noGroup')} <span className="font-normal">· {groups.get(g)!.length}</span></h2>}
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {groups.get(g)!.map((s) => <Tile key={s.id} s={s} />)}
          </div>
        </section>
      ))}
    </div>
  )
}
