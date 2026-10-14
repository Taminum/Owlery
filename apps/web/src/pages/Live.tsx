import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t } from '../i18n'
import { api } from '../lib/api'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { useApp } from '../lib/context'
import { formatInt, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { LiveAgent, LiveResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

const clock = (ms: number, tz: string) =>
  new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: tz === 'local' ? undefined : tz }).format(new Date(ms))

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-card border border-line bg-surface px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`tnum mt-1 text-[30px] font-bold leading-9 tracking-tight ${tone ?? ''}`}>{value}</div>
    </div>
  )
}

function AgentView({ a, tz }: { a: LiveAgent; tz: string }) {
  const look = useLook()
  // Bytes per second to bits per second for the chart; the table and cards print the same unit.
  const data = a.series.map((p) => ({ ts: p.ts, down: p.down_bps * 8, up: p.up_bps * 8 }))
  const all = a.devices.reduce((n, d) => n + d.up_bps + d.down_bps, 0)
  const shares = a.devices.map((d) => (all ? ((d.up_bps + d.down_bps) / all) * 100 : 0))
  const maxShare = Math.max(0, ...shares)
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">{a.name || t('live.router')}</h2>
        <span className="text-[13px] text-muted">{a.panel_name}</span>
        {a.live ? <Chip tone="green">{t('live.live')}</Chip> : <Chip tone="amber">{t('live.quiet', { s: Math.round(a.age_ms / 1000) })}</Chip>}
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <Stat label={`↓ ${t('live.down')}`} value={a.live ? formatRate(a.down_bps) : '—'} tone="text-cyan" />
        <Stat label={`↑ ${t('live.up')}`} value={a.live ? formatRate(a.up_bps) : '—'} tone="text-amber" />
        <Stat label={t('live.conns')} value={a.live ? formatInt(a.connections) : '—'} />
      </div>
      <Card title={t('live.chart')} note={t('live.chartNote')}>
        <div className="h-[220px]" role="img" aria-label={t('live.chart')}>
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
              <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => clock(v, tz)} />
              <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={72} tickFormatter={(v: number) => formatRate(v / 8)} />
              <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => clock(Number(v), tz)} formatter={(v) => formatRate(Number(v) / 8)} />
              <Area {...look(data.length)} dataKey="down" name={t('live.down')} stroke={C.cyan} fill={C.cyan} fillOpacity={0.25} isAnimationActive={false} />
              <Area {...look(data.length)} dataKey="up" name={t('live.up')} stroke={C.amber} fill={C.amber} fillOpacity={0.25} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Card>
      <Card title={t('live.devices')} note={t('live.devicesNote')}>
        {a.devices.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{a.live ? t('live.noDevices') : t('live.noDevicesStale')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('live.devices')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('dev.device')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">↓ {t('live.down')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">↑ {t('live.up')}</th>
                <th scope="col" className="w-[160px] px-2 py-2 font-medium" title={t('live.shareHint')}>{t('live.load')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
              </tr></thead>
              <tbody>
                {a.devices.map((d, i) => (
                  <tr key={d.ip} className="border-t border-line/60">
                    <td className="px-2 py-2"><span className="font-medium">{d.name || d.ip}</span>{d.name && <div className="tnum text-xs text-muted">{d.ip}</div>}</td>
                    <td className="tnum px-2 py-2 text-right">{formatRate(d.down_bps)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatRate(d.up_bps)}</td>
                    <td className="px-2 py-2"><ShareBar share={shares[i]} max={maxShare} /></td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatInt(d.connections)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

export default function Live() {
  const { filters } = useApp()
  const q = filters.panels.length ? `?panel_ids=${filters.panels.join(',')}` : ''
  const { data, error } = useLoad((s) => api.get<LiveResponse>(`/api/v1/live${q}`, s), [q], 2000)
  return (
    <div className="space-y-4">
      <PageHead title={t('live.title')} subtitle={t('live.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && data.agents.length === 0 && (
        <div role="status" className="rounded-card border border-line bg-surface px-6 py-12 text-center">
          <h2 className="text-lg font-semibold">{data.has_router ? t('live.waiting') : t('live.noRouter')}</h2>
          <p className="mx-auto mt-1.5 max-w-md text-[13px] leading-5 text-muted">{data.has_router ? t('live.waitingText') : t('live.noRouterText')}</p>
        </div>
      )}
      {data?.agents.map((a) => <AgentView key={a.agent_id} a={a} tz={filters.tz} />)}
    </div>
  )
}
