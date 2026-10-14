import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Inbox, Server } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { formatAxisTime, formatDateTime, formatInt, formatPct } from '../lib/format'
import type { AMeta } from '../lib/types'
import { Chip, Skeleton } from './ui'

export function PageHead({ title, subtitle, right }: { title: string; subtitle: string; right?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-[22px] font-semibold leading-8">{title}</h1>
        <p className="mt-1 max-w-2xl text-[13px] text-muted">{subtitle}</p>
      </div>
      {right}
    </header>
  )
}

const REASONS: Record<string, [MsgKey, MsgKey]> = {
  no_real_panels: ['an.state.noReal.title', 'an.state.noReal.text'],
  agents_not_connected: ['an.state.noAgents.title', 'an.state.noAgents.text'],
  no_events: ['an.state.noEvents.title', 'an.state.noEvents.text'],
  no_router: ['dev.state.noRouter.title', 'dev.state.noRouter.text'],
  no_counters: ['tr.state.noCounters.title', 'tr.state.noCounters.text'],
}

/** The three "nothing to show" cases are different things and are worded differently. */
export function NoDataPanel({ meta }: { meta: AMeta }) {
  const nav = useNavigate()
  const [title, text] = REASONS[meta.reason ?? 'no_events'] ?? REASONS.no_events
  const Icon = meta.reason === 'no_events' ? Inbox : Server
  return (
    <div role="status" className="flex flex-col items-center rounded-card border border-line bg-surface px-6 py-14 text-center">
      <span className="mb-4 grid h-12 w-12 place-items-center rounded-full border border-line bg-elevated text-cyan"><Icon size={22} aria-hidden /></span>
      <h2 className="text-lg font-semibold">{t(title)}</h2>
      <p className="mt-1.5 max-w-md text-[13px] leading-5 text-muted">{t(text)}</p>
      {meta.reason !== 'no_events' && (
        <button type="button" onClick={() => nav({ pathname: '/panels', search: location.search })} className="mt-5 rounded-control border border-line bg-elevated px-4 py-2 text-[13px] font-medium hover:border-cyan/60">{t('an.state.action')}</button>
      )}
    </div>
  )
}

export function CoverageLine({ meta, tz }: { meta: AMeta; tz: string }) {
  const partial = meta.coverage.nodes_total > 0 && meta.coverage.nodes_with_agent < meta.coverage.nodes_total
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
      <span className="tnum">{formatDateTime(meta.from, tz)} → {formatDateTime(meta.to, tz)}</span>
      <Chip tone={partial ? 'amber' : 'muted'}>{t('an.nodes.coverage', { a: meta.coverage.nodes_with_agent, n: meta.coverage.nodes_total })}</Chip>
      <span>connection_count · {meta.source}</span>
    </div>
  )
}

export function ShareBar({ share, max }: { share: number; max: number }) {
  const w = max > 0 ? Math.max(2, Math.min(100, (share / max) * 100)) : 0
  return (
    <div className="flex items-center gap-2">
      <span className="tnum w-12 shrink-0 text-right text-muted">{formatPct(share)}</span>
      <div className="h-1.5 w-full min-w-10 overflow-hidden rounded-full bg-elevated" aria-hidden><div className="h-full rounded-full bg-blue/80" style={{ width: `${w}%` }} /></div>
    </div>
  )
}

export function TableSkeleton() {
  return <div className="space-y-2" aria-busy="true" aria-label={t('state.loading')}>{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div>
}

export const confidenceLabel = (c?: string) => (c === 'high' ? t('an.conf.high') : c === 'medium' ? t('an.conf.medium') : c === 'low' ? t('an.conf.low') : '')

export function formatCount(n: number) { return formatInt(n) }

export function MiniTimeline({ points, granularity, tz }: { points: { ts: number; tcp: number; udp: number }[]; granularity: number; tz: string }) {
  const look = useLook()
  return (
    <div className="h-[170px]" role="img" aria-label={t('an.users.timeline')}>
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <AreaChart data={points} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
          <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
          <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => formatAxisTime(v, tz, granularity)} />
          <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={38} tickFormatter={(v: number) => formatInt(v)} />
          <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v), tz)} />
          <Area {...look(points.length)} dataKey="tcp" name="TCP" stroke={C.blue} fill={C.blue} fillOpacity={0.25} isAnimationActive={false} />
          <Area {...look(points.length)} dataKey="udp" name="UDP" stroke={C.green} fill={C.green} fillOpacity={0.3} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
