import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t } from '../i18n'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { useApp } from '../lib/context'
import { formatAxisTime, formatBytes, formatDateTime, formatInt } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { TrafficResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-card border border-line bg-surface px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className="tnum mt-1 text-[30px] font-bold leading-9 tracking-tight">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  )
}

export default function Traffic() {
  const look = useLook()
  const { filters } = useApp()
  const { data, error } = useAnalytics<TrafficResponse>('traffic', filters)
  const tz = filters.tz
  const nodeMax = data ? Math.max(0, ...data.nodes.map((n) => n.share)) : 0
  const userMax = data ? Math.max(0, ...data.users.map((u) => u.share)) : 0

  return (
    <div className="space-y-4">
      <PageHead title={t('tr.title')} subtitle={t('tr.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {data && data.meta.state === 'ok' && (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
            <span className="tnum">{formatDateTime(data.meta.from, tz)} → {formatDateTime(data.meta.to, tz)}</span>
            <Chip tone="muted">{data.meta.source}</Chip>
            {data.last_sample && <span className="tnum">{t('tr.lastSample')}: {formatDateTime(data.last_sample, tz)}</span>}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Stat label={t('tr.total')} value={formatBytes(data.total_bytes)} hint={t('tr.totalHint')} />
            <Stat label={t('tr.totalUsers')} value={formatBytes(data.users_total_bytes)} hint={data.counter_resets > 0 ? `${t('tr.resets')}: ${data.counter_resets}` : t('tr.totalHint')} />
          </div>
          <Card title={t('tr.timeline')}>
            <div className="h-[220px]" role="img" aria-label={t('tr.timeline')}>
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <AreaChart data={data.timeline} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
                  <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
                  <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => formatAxisTime(v, tz, data.meta.granularity_seconds)} />
                  <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={60} tickFormatter={(v: number) => formatBytes(v)} />
                  <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v), tz)} formatter={(v) => formatBytes(Number(v))} />
                  <Area {...look(data.timeline.length)} dataKey="bytes" name={t('tr.bytes')} stroke={C.green} fill={C.green} fillOpacity={0.25} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title={t('tr.nodes')}>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <caption className="sr-only">{t('tr.nodes')}</caption>
                <thead><tr className="text-left text-xs text-muted">
                  <th scope="col" className="px-2 py-2 font-medium">{t('tr.node')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('tr.bytes')}</th>
                  <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('tr.resets')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('tr.lastSample')}</th>
                </tr></thead>
                <tbody>
                  {data.nodes.map((n) => (
                    <tr key={n.node_id} className="border-t border-line/60">
                      <td className="px-2 py-2 font-medium">{n.name}</td>
                      <td className="tnum px-2 py-2 text-right">{n.samples === 0 ? '—' : formatBytes(n.bytes)}</td>
                      <td className="px-2 py-2"><ShareBar share={n.share} max={nodeMax} /></td>
                      <td className="tnum px-2 py-2 text-right text-muted">{formatInt(n.counter_resets)}</td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{n.last_sample ? formatDateTime(n.last_sample, tz) : t('tr.noSamples')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title={t('tr.users')} note={t('tr.usersNote')}>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <caption className="sr-only">{t('tr.users')}</caption>
                <thead><tr className="text-left text-xs text-muted">
                  <th scope="col" className="px-2 py-2 font-medium">{t('an.users.user')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('an.users.panel')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('tr.bytes')}</th>
                  <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('tr.counter')}</th>
                </tr></thead>
                <tbody>
                  {data.users.map((u) => (
                    <tr key={`${u.panel_id}:${u.label}`} className="border-t border-line/60">
                      <td className="px-2 py-2 font-medium">{u.label}{u.note ? <span className="ml-2 text-xs text-muted">{u.note}</span> : null}</td>
                      <td className="px-2 py-2 text-muted">{u.panel_name}</td>
                      <td className="tnum px-2 py-2 text-right">{formatBytes(u.bytes)}</td>
                      <td className="px-2 py-2"><ShareBar share={u.share} max={userMax} /></td>
                      <td className="px-2 py-2 text-xs text-muted">{t(u.counter === 'lifetime' ? 'tr.counter.lifetime' : 'tr.counter.period')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <p className="text-xs leading-5 text-muted">{t('tr.note')}</p>
        </>
      )}
    </div>
  )
}
