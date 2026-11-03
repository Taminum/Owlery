import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Bell, CircleCheck, DoorOpen, KeyRound, Lock, OctagonAlert, Server as ServerIcon, ShieldAlert, TriangleAlert } from 'lucide-react'
import { ru, type MsgKey } from '../i18n/ru'
import { t } from '../i18n'
import { api } from '../lib/api'
import { C } from '../lib/colors'
import { useApp } from '../lib/context'
import { formatClock, formatDateTime, formatInt, formatRate, plural } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { Kpi } from '../components/Kpi'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { StatusChip, type Server } from '../components/ServerParts'
import { tone, uptimeText } from '../components/HostView'
import type { AlertsResponse, FleetSummary, Series } from '../lib/types'

const RANK = { bad: 0, warn: 1, unknown: 2, ok: 3 } as const
const th = 'px-2 py-1.5 text-left text-xs font-normal text-muted'
const BAR = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' } as const

/** A tile of the front page: the KPI card of the traffic overview, as a link to where the numbers come from. */
function Tile({ to, ...kpi }: { to: string } & Parameters<typeof Kpi>[0]) {
  return <Link to={to} className="block rounded-card focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan [&>section]:h-full [&>section]:transition-colors [&>section:hover]:border-cyan/50"><Kpi {...kpi} /></Link>
}

function series(sum: FleetSummary, pick: (h: FleetSummary['hourly'][number]) => number): Series {
  return { ts: sum.hourly.map((h) => Math.floor(new Date(h.at).getTime() / 1000)), v: sum.hourly.map(pick) }
}

function daysLeft(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

/** What a fail2ban jail protects, in words; an unknown jail keeps its own name. */
function jailName(name: string): string {
  const key = `home.jail.${name}`
  return key in ru ? t(key as MsgKey) : name || '—'
}

function eventName(type: string): string {
  const key = `home.ev.${type}`
  return key in ru ? t(key as MsgKey) : type
}

function ShareBar({ v, max, color }: { v: number; max: number; color: string }) {
  return <div className="h-1.5 w-full min-w-[60px] overflow-hidden rounded-full bg-elevated"><div className="h-full rounded-full" style={{ width: `${max > 0 ? (v / max) * 100 : 0}%`, background: color }} /></div>
}

function HourTip({ active, payload, label, tz }: { active?: boolean; payload?: { dataKey: string; value: number; color: string }[]; label?: number; tz: string }) {
  if (!active || !payload?.length || label === undefined) return null
  const names: Record<string, string> = { bans: t('home.chart.bans'), changes: t('home.chart.changes'), alerts: t('home.chart.alerts') }
  return (
    <div className="rounded-control border border-line bg-elevated px-3 py-2 text-xs shadow-lg">
      <div className="tnum mb-1 font-medium text-fg">{formatDateTime(label, tz)}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="tnum flex items-center justify-between gap-4 text-muted">
          <span className="flex items-center gap-1.5"><i className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color }} />{names[p.dataKey] ?? p.dataKey}</span>
          <span className="text-fg">{formatInt(p.value)}</span>
        </div>
      ))}
    </div>
  )
}

function HoursCard({ sum, tz }: { sum: FleetSummary; tz: string }) {
  const data = sum.hourly.map((h) => ({ ts: Math.floor(new Date(h.at).getTime() / 1000), bans: h.bans, changes: h.changes, alerts: h.alerts }))
  const nothing = data.every((d) => d.bans + d.changes + d.alerts === 0)
  return (
    <Card title={t('home.chart.title')} note={t('home.chart.note')} className="h-full"
      right={<ul className="flex items-center gap-3 text-xs text-muted">{[[C.red, 'home.chart.bans'], [C.amber, 'home.chart.changes'], [C.blue, 'home.chart.alerts']].map(([c, k]) => (
        <li key={k} className="flex items-center gap-1.5"><i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: c }} aria-hidden />{t(k as MsgKey)}</li>))}</ul>}>
      {nothing ? <p className="py-10 text-center text-[13px] text-muted">{t('home.chart.none')}</p> : (
        <div className="h-[220px]" role="img" aria-label={t('home.chart.title')}>
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <BarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: 0 }}>
              <CartesianGrid stroke={C.line} strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="ts" tickFormatter={(v: number) => formatClock(v, tz)} stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} minTickGap={32} />
              <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={34} allowDecimals={false} />
              <Tooltip content={<HourTip tz={tz} />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="bans" stackId="a" fill={C.red} fillOpacity={0.8} isAnimationActive={false} />
              <Bar dataKey="changes" stackId="a" fill={C.amber} isAnimationActive={false} />
              <Bar dataKey="alerts" stackId="a" fill={C.blue} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}

function ByServerCard({ sum }: { sum: FleetSummary }) {
  const rows = sum.bans.servers
  const shown = rows.reduce((a, r) => a + r.count, 0)
  const all = shown < sum.bans.total ? [...rows, { name: t('home.others'), count: sum.bans.total - shown }] : rows
  const max = Math.max(1, ...all.map((r) => r.count))
  return (
    <Card title={t('home.byServer')} note={t('home.byServerNote')} className="h-full">
      {all.length === 0 ? <p className="py-6 text-center text-[13px] text-muted">{t('home.sum.bansNone', { h: 24 })}</p> : (
        <ul className="space-y-3">
          {all.map((r, i) => (
            <li key={r.name}>
              <div className="mb-1 flex justify-between text-[13px]"><span className={i === all.length - 1 && shown < sum.bans.total ? 'text-muted' : ''}>{r.name}</span><span className="tnum text-muted">{formatInt(r.count)}</span></div>
              <ShareBar v={r.count} max={max} color={i === 0 ? C.red : i === 1 ? C.amber : C.blue} />
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function Empty({ children }: { children: string }) {
  return <p className="py-6 text-center text-[13px] text-muted">{children}</p>
}

function TopIPs({ sum }: { sum: FleetSummary }) {
  return (
    <Card title={t('home.topIps')} note={t('home.topIpsNote')} className="h-full">
      {sum.top_ips.length === 0 ? <Empty>{t('home.sum.bansNone', { h: 24 })}</Empty> : (
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('home.topIps')}</caption>
          <thead><tr><th scope="col" className={th}>IP</th><th scope="col" className={th}>{t('home.country')}</th><th scope="col" className={`${th} text-right`}>{t('home.bansShort')}</th></tr></thead>
          <tbody>
            {sum.top_ips.map((r) => (
              <tr key={r.ip} className="border-t border-line/60">
                <td className="tnum px-2 py-2">{r.ip}</td>
                <td className="px-2 py-2 text-muted">{r.country_name || '—'}</td>
                <td className="tnum px-2 py-2 text-right">{formatInt(r.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

function Jails({ sum }: { sum: FleetSummary }) {
  const max = Math.max(1, ...sum.jails.map((j) => j.count))
  return (
    <Card title={t('home.jails')} note={t('home.jailsNote')} className="h-full">
      {sum.jails.length === 0 ? <Empty>{t('home.sum.bansNone', { h: 24 })}</Empty> : (
        <ul className="space-y-3">
          {sum.jails.map((j) => (
            <li key={j.name} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 text-[13px]">
              <span className="truncate" title={j.name}>{jailName(j.name)}</span><span className="tnum text-muted">{formatInt(j.count)}</span>
              <div className="col-span-2"><ShareBar v={j.count} max={max} color={C.red} /></div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function Recent({ sum, tz }: { sum: FleetSummary; tz: string }) {
  return (
    <Card title={t('home.recent')} note={t('home.recentNote')} className="h-full">
      {sum.recent.length === 0 ? <Empty>{t('home.recentNone')}</Empty> : (
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('home.recent')}</caption>
          <tbody>
            {sum.recent.map((e, i) => (
              <tr key={`${e.at}${e.server}${e.type}${i}`} className="border-t border-line/60 first:border-t-0">
                <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatClock(e.at, tz)}</td>
                <td className="px-2 py-2 font-medium">{e.server}</td>
                <td className={`px-2 py-2 ${e.severity === 'critical' ? 'text-red' : e.severity === 'warning' ? 'text-amber' : 'text-muted'}`}>{eventName(e.type)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

function Mini({ pct }: { pct: number | null }) {
  const v = pct === null ? 0 : Math.max(0, Math.min(100, pct))
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-elevated" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)}><div className={`h-full rounded-full ${BAR[tone(v)]}`} style={{ width: `${v}%` }} /></div>
      <span className="tnum w-9 text-right text-xs text-muted">{pct === null ? '—' : `${Math.round(pct)}%`}</span>
    </div>
  )
}

function Machines({ list }: { list: Server[] }) {
  const load = (s: Server) => {
    const h = s.host
    if (!h?.has_data) return -1
    const root = h.disks.find((d) => d.m === '/' || d.m === 'C:') ?? h.disks[0]
    return Math.max(h.cpu ?? 0, h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : 0, root && root.t > 0 ? (root.u * 100) / root.t : 0)
  }
  const sorted = [...list].sort((a, b) => RANK[a.status] - RANK[b.status] || load(b) - load(a) || a.name.localeCompare(b.name, 'ru'))
  return (
    <Card title={t('home.machines')} note={t('home.machinesNote')} right={<Link to="/servers" className="text-xs text-cyan underline">{t('home.allServers')}</Link>}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('home.machines')}</caption>
          <thead><tr><th scope="col" className={th}>{t('home.col.machine')}</th><th scope="col" className={th}>{t('home.col.status')}</th><th scope="col" className={th}>{t('host.cpu')}</th><th scope="col" className={th}>{t('host.mem')}</th><th scope="col" className={th}>{t('host.disk')}</th><th scope="col" className={`${th} text-right`}>{t('home.col.net')}</th></tr></thead>
          <tbody>
            {sorted.map((s) => {
              const h = s.host?.has_data ? s.host : null
              const root = h?.disks.find((d) => d.m === '/' || d.m === 'C:') ?? h?.disks[0]
              return (
                <tr key={s.id} className="border-t border-line/60">
                  <td className="px-2 py-2"><Link to={`/servers/${s.id}`} className="font-medium hover:text-cyan">{s.name}</Link></td>
                  <td className="px-2 py-2"><StatusChip s={s} /></td>
                  {h ? (
                    <>
                      <td className="px-2 py-2"><Mini pct={h.cpu} /></td>
                      <td className="px-2 py-2"><Mini pct={h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null} /></td>
                      <td className="px-2 py-2"><Mini pct={root && root.t > 0 ? (root.u * 100) / root.t : null} /></td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-right text-xs text-muted">↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {uptimeText(h.uptime)}</td>
                    </>
                  ) : <td colSpan={4} className="px-2 py-2 text-xs text-muted">{t('srv.reason.no_agent_short')}</td>}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export default function Home() {
  const { filters } = useApp()
  const tz = filters.tz
  const servers = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 30_000)
  const alerts = useLoad((sig) => api.get<AlertsResponse>('/api/v1/alerts', sig), [], 60_000)
  const summary = useLoad((sig) => api.get<FleetSummary>('/api/v1/summary?hours=24', sig), [], 120_000)
  const list = servers.data?.servers ?? []
  const sum = summary.data
  const open = (alerts.data?.alerts ?? []).filter((a) => !a.resolved_at).length
  const bad = list.filter((s) => s.status === 'bad').length
  const warn = list.filter((s) => s.status === 'warn').length
  const ok = list.filter((s) => s.status === 'ok').length
  const noAgent = list.filter((s) => s.status === 'unknown').length
  const offline = list.filter((s) => s.reason === 'offline').length
  const state = bad > 0 ? 'bad' : warn > 0 ? 'warn' : 'ok'
  const nearest = sum?.tls.nearest_end ? daysLeft(sum.tls.nearest_end) : null
  const o = sum?.owlery
  return (
    <div className="space-y-4">
      <PageHead title={t('home.title')} subtitle={t('home.subtitle')} />
      {servers.error && <p role="alert" className="text-[13px] text-red">{servers.error}</p>}
      {!servers.data && !servers.error && <TableSkeleton />}
      {servers.data && list.length === 0 && (
        <p className="py-10 text-center text-[13px] text-muted">{t('home.empty')} <Link to="/servers" className="text-cyan underline">{t('home.emptyLink')}</Link></p>
      )}
      {list.length > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
            {state === 'ok' ? <Chip icon={CircleCheck} tone="green">{t('home.hero.ok')}</Chip>
              : state === 'warn' ? <Chip icon={TriangleAlert} tone="amber">{t('home.hero.warn')}</Chip>
              : <Chip icon={OctagonAlert} tone="red">{t('home.hero.bad')}</Chip>}
            {sum && <span className="tnum">{formatDateTime(sum.from, tz)} → {formatDateTime(sum.to, tz)}</span>}
            {offline > 0 && <span>{t('home.hero.offline', { n: offline })}</span>}
            {noAgent > 0 && <span>{t('home.hero.noAgent', { n: noAgent })}</span>}
          </div>

          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Tile to="/servers" id="srv" icon={ServerIcon} color={C.blue} label={t('home.kpi.machines')} value={`${ok} / ${list.length}`}
              sub={warn + bad > 0 ? t('home.hero.asking', { n: warn + bad }) : t('home.kpi.machinesOk')} />
            <Tile to="/security" id="bans" icon={ShieldAlert} color={C.red} label={t('home.sum.bans')} value={sum ? formatInt(sum.bans.total) : '—'}
              sub={sum && sum.bans.total > 0 ? t('home.kpi.bansSub', { n: sum.bans.servers.length }) : t('home.kpi.none')} series={sum ? series(sum, (h) => h.bans) : undefined} />
            <Tile to="/alerts" id="alerts" icon={Bell} color={C.amber} label={t('home.kpi.alerts')} value={formatInt(open)}
              sub={open === 0 ? t('home.kpi.none') : t('home.kpi.alertsSub')} series={sum && o ? series(sum, (h) => h.alerts) : undefined} />
            <Tile to="/security" id="changes" icon={DoorOpen} color={C.amber} label={t('home.sum.changes')} value={sum ? formatInt(sum.changes.total) : '—'}
              sub={sum && sum.changes.total > 0 ? t('home.kpi.changesSub') : t('home.kpi.none')} series={sum ? series(sum, (h) => h.changes) : undefined} />
            {o && sum && (
              <Tile to="/settings" id="access" icon={KeyRound} color="#9b8cf5" label={t('home.kpi.access')} value={formatInt(o.terminals + o.screens + o.desktops)}
                sub={`${t('home.kpi.logins', { n: o.logins })}${o.failed_logins > 0 ? ` · ${t('home.sum.failedLogins', { n: o.failed_logins })}` : ''}`} series={series(sum, (h) => h.access)} />
            )}
            <Tile to="/security" id="tls" icon={Lock} color={C.green} label={t('home.sum.tls')} value={nearest === null ? '—' : `${nearest} ${plural(nearest, 'день', 'дня', 'дней')}`}
              sub={sum && sum.tls.problems > 0 ? t('home.sum.tlsProblems', { n: sum.tls.problems }) : sum?.tls.nearest_host || t('home.sum.tlsNone')} />
          </div>

          {summary.error && <p role="alert" className="text-[13px] text-red">{summary.error}</p>}
          {sum && (
            <>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 [&>*]:min-w-0">
                <div className="lg:col-span-8"><HoursCard sum={sum} tz={tz} /></div>
                <div className="lg:col-span-4"><ByServerCard sum={sum} /></div>
              </div>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 [&>*]:min-w-0">
                <TopIPs sum={sum} />
                <Jails sum={sum} />
                <Recent sum={sum} tz={tz} />
              </div>
            </>
          )}
          <Machines list={list} />
        </>
      )}
    </div>
  )
}
