import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t } from '../i18n'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { useApp } from '../lib/context'
import { formatAxisTime, formatBytes, formatDateTime, formatInt, formatPct } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { DeviceDetailResponse, DevicesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { Drawer } from '../components/Drawer'
import { NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

function Detail({ k }: { k: string }) {
  const look = useLook()
  const { filters } = useApp()
  const { data, error } = useAnalytics<DeviceDetailResponse>('devices/detail', filters, { key: k })
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.meta.state === 'no_data') return <NoDataPanel meta={data.meta} />
  const max = Math.max(0, ...data.hosts.map((h) => h.share))
  const gran = data.meta.granularity_seconds
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 className="text-lg font-semibold">{data.name || data.ip}</h3>
        <span className="tnum text-[13px] text-muted">{data.ip} · {data.panel_name}</span>
        <span className="tnum text-[13px] text-muted">↓ {formatBytes(data.down_bytes)} · ↑ {formatBytes(data.up_bytes)}</span>
      </div>
      <div className="h-[170px]" role="img" aria-label={t('dev.timeline')}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data.timeline.map((p) => ({ ts: p.ts, down: p.down_bytes, up: p.up_bytes }))} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => formatAxisTime(v, filters.tz, gran)} />
            <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={56} tickFormatter={(v: number) => formatBytes(v)} />
            <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v), filters.tz)} formatter={(v) => formatBytes(Number(v))} />
            <Area {...look(data.timeline.length)} dataKey="down" name={t('dev.down')} stroke={C.blue} fill={C.blue} fillOpacity={0.25} isAnimationActive={false} />
            <Area {...look(data.timeline.length)} dataKey="up" name={t('dev.up')} stroke={C.green} fill={C.green} fillOpacity={0.3} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div>
        <h3 className="mb-2 text-[13px] font-medium">{t('dev.detail')}</h3>
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('dev.detail')}</caption>
          <thead><tr className="text-left text-xs text-muted">
            <th scope="col" className="px-2 py-2 font-medium">{t('dev.host')}</th>
            <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
            <th scope="col" className="px-2 py-2 text-right font-medium">{t('dev.bytes')}</th>
            <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
          </tr></thead>
          <tbody>
            {data.hosts.map((h) => (
              <tr key={h.key} className="border-t border-line/60">
                <td className="max-w-[340px] px-2 py-2"><span className="truncate font-medium" title={h.key}>{h.key}</span>{h.service && <span className="ml-2"><Chip tone="cyan">{h.service}</Chip></span>}</td>
                <td className="tnum px-2 py-2 text-right">{formatInt(h.connections)}</td>
                <td className="tnum px-2 py-2 text-right text-muted">{formatBytes(h.up_bytes + h.down_bytes)}</td>
                <td className="px-2 py-2"><ShareBar share={h.share} max={max} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function Devices() {
  const { filters } = useApp()
  const [sel, setSel] = useState<string | null>(null)
  const { data, error } = useAnalytics<DevicesResponse>('devices', filters)
  const tz = filters.tz
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0
  return (
    <div className="space-y-4">
      <PageHead title={t('dev.title')} subtitle={t('dev.subtitle')} />
      {data && data.meta.state === 'ok' && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
          <span className="tnum">{formatDateTime(data.meta.from, tz)} → {formatDateTime(data.meta.to, tz)}</span>
          <Chip tone="muted">{t('dev.source')}</Chip>
        </div>
      )}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {data && data.meta.state === 'ok' && (
        <Card title={t('dev.total', { n: formatBytes(data.total_bytes) })}>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('dev.title')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('dev.device')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('dev.down')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('dev.up')}</th>
                <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users.dests')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('dev.noDomain')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.lastSeen')}</th>
              </tr></thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.key} className={`border-t border-line/60 ${sel === r.key ? 'bg-elevated' : ''}`}>
                    <td className="px-2 py-2">
                      <button type="button" aria-pressed={sel === r.key} onClick={() => setSel(sel === r.key ? null : r.key)} className="text-left font-medium text-fg underline-offset-2 hover:text-cyan hover:underline" title={t('an.users.detail')}>
                        {r.name || r.ip}
                      </button>
                      <div className="tnum text-xs text-muted">{r.name ? `${r.ip} · ` : ''}{r.panel_name}</div>
                    </td>
                    <td className="tnum px-2 py-2 text-right text-fg">{formatBytes(r.down_bytes)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatBytes(r.up_bytes)}</td>
                    <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
                    <td className="tnum px-2 py-2 text-right">{formatInt(r.connections)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{r.destinations}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatPct(r.no_domain_share)}</td>
                    <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatDateTime(r.last_seen, tz)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {sel && <Drawer title={t('an.users.detail')} onClose={() => setSel(null)}><Detail k={sel} /></Drawer>}
    </div>
  )
}
