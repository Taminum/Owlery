import { useState } from 'react'
import { t } from '../i18n'
import { useApp } from '../lib/context'
import { formatDateTime, formatInt, formatPct } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { NamedCount, UserDetailResponse, UsersResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { formatBytes } from '../lib/format'
import { Drawer } from '../components/Drawer'
import { CoverageLine, MiniTimeline, NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

function CountList({ title, rows }: { title: string; rows: NamedCount[] }) {
  const max = Math.max(0, ...rows.map((r) => r.share))
  return (
    <div>
      <h3 className="mb-2 text-[13px] font-medium text-fg">{title}</h3>
      {rows.length === 0 ? <p className="text-[13px] text-muted">—</p> : (
        <ul className="space-y-1.5 text-[13px]">
          {rows.map((r) => (
            <li key={r.key} className="grid grid-cols-[minmax(0,1fr)_auto_150px] items-center gap-2">
              <span className="truncate" title={r.key}>{r.key}{r.service ? <span className="ml-2 text-xs text-cyan">{r.service}</span> : null}</span>
              <span className="tnum text-muted">{formatInt(r.count)}</span>
              <ShareBar share={r.share} max={max} />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Detail({ k }: { k: string }) {
  const { filters } = useApp()
  const { data, error } = useAnalytics<UserDetailResponse>('users/detail', filters, { key: k })
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.meta.state === 'no_data') return <NoDataPanel meta={data.meta} />
  const pts = (data.timeline ?? []).map((p) => ({ ts: p.ts, tcp: p.tcp, udp: p.udp }))
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 className="text-lg font-semibold">{data.label}</h3>
        <span className="text-[13px] text-muted">{data.panel_name}</span>
        <span className="tnum text-[13px] text-muted">TCP {formatInt(data.tcp)} · UDP {formatInt(data.udp)}</span>
      </div>
      {data.note && <p className="text-[13px] text-muted">{data.note === 'system' ? t('an.users.system') : data.note === 'unresolved' ? t('an.users.unresolved') : data.note}</p>}
      <MiniTimeline points={pts} granularity={data.meta.granularity_seconds} tz={filters.tz} />
      <div className="grid gap-6 lg:grid-cols-3">
        <CountList title={t('an.users.topHosts')} rows={data.hosts ?? []} />
        <CountList title={t('an.users.topPorts')} rows={data.ports ?? []} />
        <CountList title={t('an.users.byNode')} rows={data.nodes ?? []} />
      </div>
    </div>
  )
}

interface Sub { panel_id: string; panel_name: string; username: string; status: string; expire_at: string | null; traffic_limit_bytes: number | null; traffic_used_bytes: number | null }

function Subscriptions({ tz }: { tz: string }) {
  const { data } = useLoad((s) => api.get<{ users: Sub[] }>('/api/v1/subscriptions', s), [], 120_000)
  const [now] = useState(() => Date.now())
  if (!data || data.users.length === 0) return null
  return (
    <Card title={t('sub.title')} note={t('sub.note')}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('sub.title')}</caption>
          <thead><tr className="text-left text-xs text-muted">
            <th scope="col" className="px-2 py-2 font-medium">{t('sub.user')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('sub.panel')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('sub.status')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('sub.expire')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('sub.traffic')}</th>
          </tr></thead>
          <tbody>
            {data.users.map((u, i) => {
              const left = u.expire_at ? (new Date(u.expire_at).getTime() - now) / 86_400_000 : null
              const lim = u.traffic_limit_bytes ?? 0
              const pct = lim > 0 && u.traffic_used_bytes !== null ? Math.min(100, Math.round((u.traffic_used_bytes * 100) / lim)) : null
              return (
                <tr key={`${u.panel_id}:${u.username}:${i}`} className="border-t border-line/60">
                  <td className="px-2 py-2 font-medium text-fg">{u.username}</td>
                  <td className="px-2 py-2 text-muted">{u.panel_name}</td>
                  <td className="px-2 py-2"><Chip tone={u.status === 'ACTIVE' ? 'green' : 'muted'}>{u.status || '—'}</Chip></td>
                  <td className="whitespace-nowrap px-2 py-2">
                    {u.expire_at ? (
                      <>
                        <span className="tnum mr-2">{formatDateTime(u.expire_at, tz)}</span>
                        {left !== null && left < 0 ? <Chip tone="red">{t('sub.expired')}</Chip>
                          : left !== null && left <= 3 ? <Chip tone="amber">{left < 1 ? t('sub.left.today') : t('sub.left.days', { n: Math.ceil(left) })}</Chip> : null}
                      </>
                    ) : <span className="text-muted">{t('sub.noEnd')}</span>}
                  </td>
                  <td className="whitespace-nowrap px-2 py-2">
                    {pct === null ? <span className="text-muted">{lim > 0 ? '—' : t('sub.unlimited')}</span> : (
                      <span className="tnum">
                        <span className={pct >= 90 ? 'text-amber' : ''}>{formatBytes(u.traffic_used_bytes ?? 0)} / {formatBytes(lim)}</span>
                        <span className="ml-2 text-xs text-muted">{pct}%</span>
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export default function Users() {
  const { filters } = useApp()
  const [sel, setSel] = useState<string | null>(null)
  const { data, error } = useAnalytics<UsersResponse>('users', filters, { limit: '200' })
  const tz = filters.tz
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0

  return (
    <div className="space-y-4">
      <PageHead title={t('an.users.title')} subtitle={t('an.users.subtitle')} />
      <Subscriptions tz={tz} />
      {data && <CoverageLine meta={data.meta} tz={tz} />}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {data && data.meta.state === 'ok' && (
        <Card title={t('an.total', { n: formatInt(data.total_connections) })}>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('an.users.title')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('an.users.user')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.users.panel')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users.dests')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.nodes')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users.udp')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.lastSeen')}</th>
              </tr></thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.key} className={`border-t border-line/60 ${sel === r.key ? 'bg-elevated' : ''}`}>
                    <td className="px-2 py-2">
                      <button type="button" aria-pressed={sel === r.key} onClick={() => setSel(sel === r.key ? null : r.key)} className="font-medium text-fg underline-offset-2 hover:text-cyan hover:underline" title={t('an.users.detail')}>{r.label}</button>
                    </td>
                    <td className="px-2 py-2 text-muted">{r.panel_name}</td>
                    <td className="tnum px-2 py-2 text-right text-fg">{formatInt(r.connections)}</td>
                    <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
                    <td className="tnum px-2 py-2 text-right text-muted">{r.destinations}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{r.nodes}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatPct(r.udp_share)}</td>
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
