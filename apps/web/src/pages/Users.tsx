import { DataTable } from '../components/DataTable'
import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { useApp } from '../lib/context'
import { formatDateTime, formatInt, formatPct } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { NamedCount, UserDetailResponse, UsersResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { formatBytes } from '../lib/format'
import { Drawer } from '../components/Drawer'
import { AwgClients } from '../components/AwgClients'
import { SubLeaks } from '../components/SubLeaks'
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

/** Remnawave has no "never": a subscription without an end is stored with a date near the end of the century. */
const isNoEnd = (iso: string) => new Date(iso).getFullYear() >= 2090

function statusLabel(status: string): string {
  const key = `sub.st.${status}` as MsgKey
  return t(key) || status || '—'
}

const trafficPct = (u: { traffic_limit_bytes: number | null; traffic_used_bytes: number | null }): number | null => {
  const lim = u.traffic_limit_bytes ?? 0
  return lim > 0 && u.traffic_used_bytes !== null ? Math.min(100, Math.round((u.traffic_used_bytes * 100) / lim)) : null
}

function Subscriptions({ tz }: { tz: string }) {
  const { data } = useLoad((s) => api.get<{ users: Sub[] }>('/api/v1/subscriptions', s), [], 120_000)
  const [now] = useState(() => Date.now())
  if (!data || data.users.length === 0) return null
  return (
    <Card title={t('sub.title')} note={t('sub.note')}>
      <DataTable caption={t('sub.title')} rows={data.users} rowKey={(u) => `${u.panel_id}:${u.username}`} columns={[
        { key: 'user', title: t('sub.user'), sort: (u) => u.username, className: 'font-medium text-fg', cell: (u) => u.username },
        { key: 'panel', title: t('sub.panel'), sort: (u) => u.panel_name, className: 'text-muted', cell: (u) => u.panel_name },
        { key: 'status', title: t('sub.status'), sort: (u) => statusLabel(u.status), cell: (u) => <Chip tone={u.status === 'ACTIVE' ? 'green' : 'muted'}>{statusLabel(u.status)}</Chip> },
        { key: 'expire', title: t('sub.expire'), sort: (u) => (u.expire_at && !isNoEnd(u.expire_at) ? u.expire_at : null), className: 'whitespace-nowrap', cell: (u) => {
          if (!u.expire_at || isNoEnd(u.expire_at)) return <span className="text-muted">{t('sub.noEnd')}</span>
          const left = (new Date(u.expire_at).getTime() - now) / 86_400_000
          return (
            <>
              <span className="tnum mr-2">{formatDateTime(u.expire_at, tz)}</span>
              {left < 0 ? <Chip tone="red">{t('sub.expired')}</Chip>
                : left <= 3 ? <Chip tone="amber">{left < 1 ? t('sub.left.today') : t('sub.left.days', { n: Math.ceil(left) })}</Chip> : null}
            </>
          )
        } },
        { key: 'traffic', title: t('sub.traffic'), sort: (u) => trafficPct(u), descFirst: true, className: 'whitespace-nowrap', cell: (u) => {
          const lim = u.traffic_limit_bytes ?? 0
          const pct = trafficPct(u)
          if (pct === null) return <span className="text-muted">{lim > 0 ? '—' : t('sub.unlimited')}</span>
          return (
            <span className="tnum">
              <span className={pct >= 90 ? 'text-amber' : ''}>{formatBytes(u.traffic_used_bytes ?? 0)} / {formatBytes(lim)}</span>
              <span className="ml-2 text-xs text-muted">{pct}%</span>
            </span>
          )
        } },
      ]} />
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
      <SubLeaks tz={tz} />
      <AwgClients range={filters.range} tz={tz} />
      {data && <CoverageLine meta={data.meta} tz={tz} />}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {data && data.meta.state === 'ok' && (
        <Card title={t('an.total', { n: formatInt(data.total_connections) })}>
          <DataTable caption={t('an.users.title')} rows={data.rows} rowKey={(r) => r.key} rowClass={(r) => (sel === r.key ? 'bg-elevated' : '')} columns={[
            { key: 'user', title: t('an.users.user'), sort: (r) => r.label, cell: (r) => (
              <button type="button" aria-pressed={sel === r.key} onClick={() => setSel(sel === r.key ? null : r.key)} className="font-medium text-fg underline-offset-2 hover:text-cyan hover:underline" title={t('an.users.detail')}>{r.label}</button>) },
            { key: 'panel', title: t('an.users.panel'), sort: (r) => r.panel_name, className: 'text-muted', cell: (r) => r.panel_name },
            { key: 'conn', title: t('an.connections'), sort: (r) => r.connections, descFirst: true, align: 'right', className: 'text-fg', cell: (r) => formatInt(r.connections) },
            { key: 'share', title: t('an.share'), className: 'w-[150px]', cell: (r) => <ShareBar share={r.share} max={max} /> },
            { key: 'dests', title: t('an.users.dests'), sort: (r) => r.destinations, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => r.destinations },
            { key: 'nodes', title: t('an.nodes'), sort: (r) => r.nodes, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => r.nodes },
            { key: 'udp', title: t('an.users.udp'), sort: (r) => r.udp_share, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => formatPct(r.udp_share) },
            { key: 'last', title: t('an.lastSeen'), sort: (r) => r.last_seen, descFirst: true, className: 'whitespace-nowrap text-muted', cell: (r) => formatDateTime(r.last_seen, tz) },
          ]} />
        </Card>
      )}
      {sel && <Drawer title={t('an.users.detail')} onClose={() => setSel(null)}><Detail k={sel} /></Drawer>}
    </div>
  )
}
