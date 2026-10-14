import { Activity, ArrowDownUp, Clock, Globe2, Network, Server, TriangleAlert, CircleCheck } from 'lucide-react'
import { t } from '../i18n'
import { useApp } from '../lib/context'
import { C } from '../lib/colors'
import { formatBytes, formatClock, formatDateTime, formatInt, formatPct } from '../lib/format'
import { Kpi } from '../components/Kpi'
import { RecentTable, TopTable, CountriesPlaceholder } from '../components/Tables'
import { CountriesCard } from '../components/Countries'
import { TimelineCard, TrafficCard, TrafficTotalCard, UsersDonut } from '../components/Charts'
import { AgentsNotConnected, FailureState, NoData, OverviewSkeleton, SyncPending } from '../components/States'
import { useNavigate } from 'react-router-dom'
import { Card, Chip } from '../components/ui'
import type { Overview as OverviewData } from '../lib/types'

function NoCountersCard() {
  return (
    <Card title={t('traffic.noCountersTitle')} className="h-full">
      <div className="flex h-full min-h-[150px] flex-col items-start justify-center gap-3">
        <Chip icon={Clock}>{t('traffic.noCounters')}</Chip>
        <p className="text-[13px] leading-5 text-muted">{t('traffic.noCountersText')}</p>
      </div>
    </Card>
  )
}

function ScopeBar({ ov, tz, panelName, fetchedAt }: { ov: OverviewData; tz: string; panelName: (id: string) => string; fetchedAt: Date | null }) {
  const n = ov.meta.panel_ids.length
  const scope = n > 1 ? t('scope.all') : t('scope.single', { name: panelName(ov.meta.panel_ids[0]) })
  const partial = ov.meta.coverage.pct < 100
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
        <span className="font-medium text-fg">{scope}</span>
        <span className="tnum">{formatDateTime(ov.meta.from, tz)} → {formatDateTime(ov.meta.to, tz)}</span>
        {partial ? (
          <Chip icon={TriangleAlert} tone="amber">{t('coverage.partial', { pct: formatPct(ov.meta.coverage.pct) })}</Chip>
        ) : (
          <Chip icon={CircleCheck} tone="muted">{t('coverage.full', { pct: formatPct(ov.meta.coverage.pct) })}</Chip>
        )}
        {fetchedAt && <span className="tnum ml-auto">Обновлено {formatClock(fetchedAt.toISOString(), tz, true)}</span>}
      </div>
      {partial && (
        <ul className="rounded-control border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
          {ov.meta.coverage.gaps.map((g) => (
            <li key={g.node_id} className="tnum">▨ {t('coverage.gap', { node: g.node_name, from: formatClock(g.from, tz), to: formatClock(g.to, tz) })}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function Overview() {
  const { panels, filters, update, overview, reset } = useApp()
  const { data: ov, failure, loading, fetchedAt, refresh } = overview
  const panelName = (id: string) => panels.find((p) => p.id === id)?.name ?? id
  const navigate = useNavigate()

  if (failure) return <FailureState failure={failure} onRetry={refresh} onReset={reset} />
  if (!ov) return loading ? <OverviewSkeleton /> : null
  if (ov.meta.state === 'no_data' && ov.meta.reason === 'agents_not_connected') return <AgentsNotConnected onOpenPanels={() => navigate({ pathname: '/panels', search: location.search })} />
  if (ov.meta.state === 'no_data') return <NoData onWiden={() => update({ range: '7d' })} />
  if (ov.meta.state === 'sync_pending') return <SyncPending onRetry={refresh} />

  const tz = filters.tz
  const multi = ov.meta.panel_ids.length > 1
  const c = ov.connections
  const udpShare = c.total ? (c.udp / c.total) * 100 : 0
  const delta = c.delta_pct
  const stale = ov.freshness.status === 'stale'
  const hasTotal = ov.traffic.total_bytes != null
  const noCounters = ov.traffic.series.length === 0 && !hasTotal

  return (
    <div className={`space-y-4 transition-opacity ${loading ? 'opacity-70' : ''}`} aria-busy={loading}>
      <ScopeBar ov={ov} tz={tz} panelName={panelName} fetchedAt={fetchedAt} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi id="conn" icon={Activity} color={C.blue} label={t('kpi.connections')} note={t('kpi.connectionsNote')} value={formatInt(c.total)}
          sub={<><div>{delta === null ? '—' : `${delta >= 0 ? '↑ +' : '↓ '}${formatPct(delta).replace('-', '')} ${t('kpi.vsPrev')}`}</div><div>TCP {formatPct(100 - udpShare)} · UDP {formatPct(udpShare)}</div></>}
          series={c.series} />
        <Kpi id="hosts" icon={Globe2} color={C.amber} label={t('kpi.hosts')} value={formatInt(ov.unique_hosts.value)} sub={t('table.host')} series={ov.unique_hosts.series} />
        <Kpi id="ips" icon={Network} color={C.red} label={t('kpi.ips')} value={formatInt(ov.unique_ips.value)} sub={t('table.ip')} series={ov.unique_ips.series} />
        <Kpi id="nodes" icon={Server} color={C.cyan} label={t('kpi.nodes')} value={`${ov.nodes.reporting} / ${ov.nodes.total}`} sub={`${ov.meta.panel_ids.length} ${ov.meta.panel_ids.length === 1 ? 'панель' : 'панели'}`} />
        {noCounters
          ? <Kpi id="traffic" icon={ArrowDownUp} color={C.green} label={t('kpi.traffic')} value="—" sub={t('traffic.noCounters')} />
          : hasTotal
          ? <Kpi id="traffic" icon={ArrowDownUp} color={C.green} label={t('kpi.traffic')} note={t('kpi.trafficTotalNote')} value={formatBytes(ov.traffic.total_bytes ?? 0)} sub={t('kpi.trafficTotalSub')} />
          : <Kpi id="traffic" icon={ArrowDownUp} color={C.green} label={t('kpi.traffic')} value={`↓ ${formatBytes(ov.traffic.down_bytes)}`}
            sub={<><div>↑ {formatBytes(ov.traffic.up_bytes)}</div><div>покрытие {formatPct(ov.traffic.coverage_pct)}</div></>} />}
        <Kpi id="fresh" icon={Clock} color={stale ? C.amber : C.cyan} label={t('kpi.freshness')} value={formatClock(ov.freshness.last_event_at, tz, true)}
          sub={stale ? t('kpi.stale') : t('kpi.lag', { s: ov.freshness.lag_seconds })} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 [&>*]:min-w-0">
        <div className="lg:col-span-8"><TimelineCard ov={ov} tz={tz} /></div>
        <div className="lg:col-span-4"><UsersDonut ov={ov} multiPanel={multi} onSelectPanel={(id) => update({ panels: [id], nodes: [] })} /></div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 [&>*]:min-w-0">
        <div className="lg:col-span-8">{noCounters ? <NoCountersCard /> : hasTotal ? <TrafficTotalCard ov={ov} tz={tz} /> : <TrafficCard ov={ov} tz={tz} />}</div>
        <div className="lg:col-span-4">{ov.meta.demo ? <CountriesPlaceholder /> : <CountriesCard compact />}</div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 [&>*]:min-w-0">
        <TopTable title={t('table.hosts')} note="connection_count" firstCol={t('table.host')} rows={ov.top_hosts} />
        <TopTable title={t('table.ips')} note="connection_count" firstCol={t('table.ip')} rows={ov.top_ips} mono />
        <TopTable title={t('table.ports')} note="connection_count" firstCol={t('table.port')} rows={ov.top_ports} mono />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 [&>*]:min-w-0">
        <div className="lg:col-span-5"><TopTable title={t('table.services')} note="connection_count · правила классификатора, уверенность указана" firstCol={t('table.service')} rows={ov.services} showConfidence /></div>
        <div className="lg:col-span-7"><RecentTable ov={ov} tz={tz} multiPanel={multi} /></div>
      </div>
    </div>
  )
}
