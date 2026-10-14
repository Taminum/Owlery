import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { C, SERIES } from '../lib/colors'
import { formatAxisTime, formatBytes, formatDateTime, formatInt, formatPct } from '../lib/format'
import { t } from '../i18n'
import { useLook } from '../lib/chartLook'
import type { Overview, Row } from '../lib/types'
import { Card } from './ui'

const axis = { stroke: C.muted, fontSize: 11, tickLine: false, axisLine: false } as const

/** Contiguous runs of buckets that have no collection data. */
export function gapRuns(timeline: Overview['timeline'], granularity: number): { x1: number; x2: number }[] {
  const runs: { x1: number; x2: number }[] = []
  for (const p of timeline) {
    if (!p.gap) continue
    const last = runs[runs.length - 1]
    if (last && last.x2 === p.ts) last.x2 = p.ts + granularity
    else runs.push({ x1: p.ts, x2: p.ts + granularity })
  }
  return runs
}

interface TipProps {
  active?: boolean
  payload?: { dataKey: string; value: number; color: string; payload: Record<string, number | boolean> }[]
  label?: number
  tz: string
  source: string
  fmt: (v: number) => string
  names: Record<string, string>
}

function Tip({ active, payload, label, tz, source, fmt, names }: TipProps) {
  if (!active || !payload?.length || label === undefined) return null
  const gap = payload[0]?.payload?.gap === true
  return (
    <div className="rounded-control border border-line bg-elevated px-3 py-2 text-xs shadow-lg">
      <div className="tnum mb-1 font-medium text-fg">{formatDateTime(label, tz)}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="tnum flex items-center justify-between gap-4 text-muted">
          <span className="flex items-center gap-1.5"><i className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color }} />{names[p.dataKey] ?? p.dataKey}</span>
          <span className="text-fg">{fmt(p.value)}</span>
        </div>
      ))}
      {gap && <div className="mt-1 text-amber">{t('chart.gap')}</div>}
      <div className="mt-1 text-[11px] text-muted/80">источник: {source}</div>
    </div>
  )
}

function Legend({ items }: { items: { color: string; label: string }[] }) {
  return (
    <ul className="flex items-center gap-3 text-xs text-muted">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          <i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: i.color }} aria-hidden />
          {i.label}
        </li>
      ))}
    </ul>
  )
}

export function TimelineCard({ ov, tz }: { ov: Overview; tz: string }) {
  const look = useLook()
  const g = ov.meta.granularity_seconds
  const runs = gapRuns(ov.timeline, g)
  return (
    <Card
      title={t('chart.timeline')}
      note={`connection_count · ${ov.connections.source}`}
      right={<Legend items={[{ color: C.blue, label: t('chart.tcp') }, { color: C.green, label: t('chart.udp') }]} />}
      className="h-full"
    >
      <div className="h-[300px]" role="img" aria-label={t('chart.timeline')}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={ov.timeline} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="tl-tcp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.blue} stopOpacity={0.55} /><stop offset="100%" stopColor={C.blue} stopOpacity={0.08} /></linearGradient>
              <linearGradient id="tl-udp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.green} stopOpacity={0.6} /><stop offset="100%" stopColor={C.green} stopOpacity={0.1} /></linearGradient>
            </defs>
            <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" {...axis} tickCount={7} tickFormatter={(v: number) => formatAxisTime(v, tz, g)} />
            <YAxis {...axis} width={44} tickFormatter={(v: number) => formatInt(v)} />
            {runs.map((r) => (
              <ReferenceArea key={r.x1} x1={r.x1} x2={r.x2} fill={C.amber} fillOpacity={0.12} stroke={C.amber} strokeOpacity={0.4} strokeDasharray="4 3" ifOverflow="visible" />
            ))}
            <Tooltip cursor={{ stroke: C.muted, strokeOpacity: 0.4 }} content={<Tip tz={tz} source={ov.connections.source} fmt={formatInt} names={{ tcp: 'TCP', udp: 'UDP' }} />} />
            <Area {...look(ov.timeline.length)} dataKey="tcp" stroke={C.blue} strokeWidth={1.5} fill="url(#tl-tcp)" isAnimationActive={false} />
            <Area {...look(ov.timeline.length)} dataKey="udp" stroke={C.green} strokeWidth={1.5} fill="url(#tl-udp)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      {runs.length > 0 && <p className="mt-2 flex items-center gap-1.5 text-xs text-amber">▨ {t('chart.gap')}</p>}
    </Card>
  )
}

export function TrafficCard({ ov, tz }: { ov: Overview; tz: string }) {
  const look = useLook()
  const g = ov.meta.granularity_seconds
  const data = ov.traffic.series
  return (
    <Card
      title={t('chart.traffic')}
      note={`${t('chart.trafficNote')} · ${ov.traffic.source} · покрытие ${formatPct(ov.traffic.coverage_pct)}`}
      right={<Legend items={[{ color: C.cyan, label: `↓ ${t('kpi.down')}` }, { color: C.amber, label: `↑ ${t('kpi.up')}` }]} />}
      className="h-full"
    >
      <div className="h-[200px]" role="img" aria-label={t('chart.traffic')}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="tr-down" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.cyan} stopOpacity={0.45} /><stop offset="100%" stopColor={C.cyan} stopOpacity={0.05} /></linearGradient>
              <linearGradient id="tr-up" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.amber} stopOpacity={0.45} /><stop offset="100%" stopColor={C.amber} stopOpacity={0.05} /></linearGradient>
            </defs>
            <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" {...axis} tickCount={7} tickFormatter={(v: number) => formatAxisTime(v, tz, g)} />
            <YAxis {...axis} width={58} tickFormatter={(v: number) => formatBytes(v)} />
            <Tooltip cursor={{ stroke: C.muted, strokeOpacity: 0.4 }} content={<Tip tz={tz} source={ov.traffic.source} fmt={formatBytes} names={{ down: t('kpi.down'), up: t('kpi.up') }} />} />
            <Area {...look(data.length)} dataKey="down" stroke={C.cyan} strokeWidth={1.5} fill="url(#tr-down)" isAnimationActive={false} />
            <Area {...look(data.length)} dataKey="up" stroke={C.amber} strokeWidth={1.5} fill="url(#tr-up)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

/** Real panels: one counter, no up/down split, so one honest line. */
export function TrafficTotalCard({ ov, tz }: { ov: Overview; tz: string }) {
  const look = useLook()
  const g = ov.meta.granularity_seconds
  const data = ov.traffic.total_series ?? []
  return (
    <Card
      title={t('chart.traffic')}
      note={`${t('chart.trafficTotalNote')} · ${ov.traffic.source}${ov.traffic.counter_resets ? ` · ${t('tr.resets')}: ${ov.traffic.counter_resets}` : ''}`}
      className="h-full"
    >
      <div className="h-[200px]" role="img" aria-label={t('chart.traffic')}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="tr-total" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.green} stopOpacity={0.45} /><stop offset="100%" stopColor={C.green} stopOpacity={0.05} /></linearGradient>
            </defs>
            <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" {...axis} tickCount={7} tickFormatter={(v: number) => formatAxisTime(v, tz, g)} />
            <YAxis {...axis} width={58} tickFormatter={(v: number) => formatBytes(v)} />
            <Tooltip cursor={{ stroke: C.muted, strokeOpacity: 0.4 }} content={<Tip tz={tz} source={ov.traffic.source} fmt={formatBytes} names={{ bytes: t('tr.bytes') }} />} />
            <Area {...look(data.length)} dataKey="bytes" stroke={C.green} strokeWidth={1.5} fill="url(#tr-total)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

export function UsersDonut({ ov, multiPanel, onSelectPanel }: { ov: Overview; multiPanel: boolean; onSelectPanel: (panelId: string) => void }) {
  const rows: Row[] = ov.users
  const total = ov.connections.total
  const name = (r: Row) => (multiPanel && r.panel_name ? `${r.label}${r.note ? ` (${r.note})` : ''} · ${r.panel_name}` : `${r.label}${r.note ? ` (${r.note})` : ''}`)
  return (
    <Card title={t('chart.users')} note="connection_count" className="h-full">
      <div className="flex flex-col items-center gap-4 2xl:flex-row">
        <div className="relative h-[190px] w-[190px] shrink-0">
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <PieChart>
              <Pie data={rows} dataKey="count" nameKey="label" innerRadius={62} outerRadius={90} stroke={C.surface} strokeWidth={2} isAnimationActive={false} onClick={(d) => d.payload?.panel_id && onSelectPanel(d.payload.panel_id)}>
                {rows.map((r, i) => <Cell key={r.key} fill={SERIES[i % SERIES.length]} style={{ cursor: 'pointer' }} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="tnum text-xl font-semibold text-fg">{formatInt(total)}</span>
            <span className="text-xs text-muted">{t('chart.connections')}</span>
          </div>
        </div>
        <ul className="w-full min-w-0 flex-1 space-y-1.5">
          {rows.map((r, i) => (
            <li key={r.key}>
              <button type="button" onClick={() => r.panel_id && onSelectPanel(r.panel_id)} className="tnum flex w-full items-center gap-2 rounded-md px-1.5 py-1 text-left text-[13px] hover:bg-elevated">
                <i className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: SERIES[i % SERIES.length] }} aria-hidden />
                <span className="min-w-0 flex-1 truncate text-fg">{name(r)}</span>
                <span className="text-muted">{formatInt(r.count)}</span>
                <span className="w-12 text-right text-muted">{formatPct(r.share)}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </Card>
  )
}
