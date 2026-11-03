import { Link } from 'react-router-dom'
import { CircleCheck, OctagonAlert, TriangleAlert, type LucideIcon } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { RoleChips, StatusChip, StatusDot, type Server } from '../components/ServerParts'
import { Spark, tone, uptimeText } from '../components/HostView'
import { useModulesOff } from '../lib/modules'
import type { AlertsResponse } from '../lib/types'

const TEXT = { green: 'text-green', amber: 'text-amber', red: 'text-red' } as const
const RANK = { bad: 0, warn: 1, unknown: 2, ok: 3 } as const
const EDGE = { bad: 'border-t-red', warn: 'border-t-amber', unknown: 'border-t-muted/40', ok: 'border-t-green' } as const

function Stat({ label, value, hint, accent }: { label: string; value: number; hint?: string; accent?: 'amber' | 'red' | 'green' }) {
  return (
    <div className="rounded-control border border-line bg-bg/40 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
      <div className={`tnum text-[24px] font-semibold leading-8 ${accent && value > 0 ? TEXT[accent] : ''}`}>{value}</div>
      {hint && <div className="text-[11px] text-muted">{hint}</div>}
    </div>
  )
}

/** The one sentence the whole page is about: is the farm all right. */
function Hero({ list, alerts }: { list: Server[]; alerts: number }) {
  const bad = list.filter((s) => s.status === 'bad').length
  const warn = list.filter((s) => s.status === 'warn').length
  const ok = list.filter((s) => s.status === 'ok').length
  const offline = list.filter((s) => s.reason === 'offline').length
  const noAgent = list.filter((s) => s.status === 'unknown').length
  const state: 'ok' | 'warn' | 'bad' = bad > 0 ? 'bad' : warn > 0 ? 'warn' : 'ok'
  const Icon: LucideIcon = { ok: CircleCheck, warn: TriangleAlert, bad: OctagonAlert }[state]
  const look = {
    ok: 'border-green/40 bg-gradient-to-br from-green/15 via-surface to-surface text-green',
    warn: 'border-amber/40 bg-gradient-to-br from-amber/15 via-surface to-surface text-amber',
    bad: 'border-red/40 bg-gradient-to-br from-red/15 via-surface to-surface text-red',
  }[state]
  const withData = list.filter((s) => s.host?.has_data)
  const rx = withData.reduce((a, s) => a + (s.host?.rx_bps ?? 0), 0)
  const tx = withData.reduce((a, s) => a + (s.host?.tx_bps ?? 0), 0)
  return (
    <section aria-label={t(`home.hero.${state}` as never)} className={`rounded-card border p-5 ${look}`}>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
        <Icon size={44} strokeWidth={1.6} aria-hidden />
        <div className="min-w-0 flex-1">
          <h2 className="text-[22px] font-semibold leading-7 text-fg">{t(`home.hero.${state}` as never)}</h2>
          <p className="mt-0.5 text-[13px] text-muted">
            {t('home.hero.sub', { ok, total: list.length })}
            {withData.length > 0 && <> · <span className="tnum">↓ {formatRate(rx)} · ↑ {formatRate(tx)}</span> {t('home.hero.now')}</>}
          </p>
        </div>
        <div className="grid w-full grid-cols-2 gap-2 text-fg sm:w-auto sm:grid-cols-4">
          <Stat label={t('home.stat.total')} value={list.length} />
          <Stat label={t('home.stat.ok')} value={ok} accent="green" />
          <Stat label={t('home.stat.warn')} value={warn} accent="amber" hint={alerts > 0 ? t('home.stat.alertsHint', { n: alerts }) : undefined} />
          <Stat label={t('home.stat.bad')} value={bad} accent="red" hint={t('home.stat.badHint', { n: offline })} />
        </div>
      </div>
      {noAgent > 0 && <p className="mt-3 text-xs text-muted">{t('home.hero.noAgent', { n: noAgent })}</p>}
    </section>
  )
}

function Mini({ label, v }: { label: string; v: number | null }) {
  const pct = v === null ? 0 : Math.max(0, Math.min(100, v))
  const color = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' }[tone(pct)]
  return (
    <div className="min-w-0 flex-1">
      <div className="flex justify-between text-[11px] text-muted"><span>{label}</span><span className={`tnum ${v === null ? '' : TEXT[tone(pct)]}`}>{v === null ? '—' : `${Math.round(v)}%`}</span></div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-elevated"><div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} /></div>
    </div>
  )
}

function MachineCard({ s }: { s: Server }) {
  const h = s.host?.has_data ? s.host : null
  const root = h?.disks.find((d) => d.m === '/' || d.m === 'C:') ?? h?.disks[0]
  const mem = h && h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  return (
    <li>
      <Link to={`/servers/${s.id}`}
        className={`block rounded-card border border-t-2 border-line bg-surface p-3.5 transition-colors hover:border-cyan/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan ${EDGE[s.status]}`}>
        <div className="flex items-center gap-2">
          <StatusDot s={s} />
          <span className="min-w-0 flex-1 truncate text-[14px] font-semibold">{s.name}</span>
          {h && <Spark values={h.cpu_spark} />}
        </div>
        <div className="mt-1.5 min-h-5"><RoleChips roles={s.roles} /></div>
        {h ? (
          <>
            <div className="mt-2.5 flex gap-3">
              <Mini label={t('host.cpu')} v={h.cpu} />
              <Mini label={t('host.mem')} v={mem} />
              <Mini label={t('host.disk')} v={root && root.t > 0 ? (root.u * 100) / root.t : null} />
            </div>
            <p className="tnum mt-2 text-[11px] text-muted">↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {t('host.up')} {uptimeText(h.uptime)}</p>
          </>
        ) : <p className="mt-2.5 text-xs text-muted">{t('srv.reason.no_agent_short')}</p>}
      </Link>
    </li>
  )
}

function ago(iso: string): string {
  const min = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60_000))
  if (min < 1) return t('home.justNow')
  if (min < 60) return t('home.minAgo', { n: min })
  if (min < 24 * 60) return t('home.hourAgo', { n: Math.round(min / 60) })
  return t('home.dayAgo', { n: Math.round(min / (24 * 60)) })
}

export default function Home() {
  const servers = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 30_000)
  const alerts = useLoad((sig) => api.get<AlertsResponse>('/api/v1/alerts', sig), [], 60_000)
  const off = useModulesOff()
  const list = servers.data?.servers ?? []
  const byTrouble = (a: Server, b: Server) => RANK[a.status] - RANK[b.status] || a.name.localeCompare(b.name, 'ru')
  const trouble = list.filter((s) => s.status === 'bad' || s.status === 'warn').sort(byTrouble)
  const open = (alerts.data?.alerts ?? []).filter((a) => !a.resolved_at)
  const sorted = [...list].sort(byTrouble)
  return (
    <div className="space-y-5">
      <PageHead title={t('home.title')} subtitle={t('home.subtitle')} />
      {servers.error && <p role="alert" className="text-[13px] text-red">{servers.error}</p>}
      {!servers.data && !servers.error && <TableSkeleton />}
      {servers.data && list.length === 0 && (
        <p className="py-10 text-center text-[13px] text-muted">{t('home.empty')} <Link to="/servers" className="text-cyan underline">{t('home.emptyLink')}</Link></p>
      )}
      {list.length > 0 && (
        <>
          <Hero list={list} alerts={open.length} />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 [&>*]:min-w-0">
            <Card title={t('home.attention')} note={trouble.length ? undefined : t('home.attentionOk')}>
              {trouble.length > 0 && (
                <ul className="divide-y divide-line">
                  {trouble.map((s) => (
                    <li key={s.id}>
                      <Link to={`/servers/${s.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-2 text-[13px] hover:bg-elevated">
                        <span className="font-medium">{s.name}</span>
                        <StatusChip s={s} />
                        <span className="text-xs text-muted">{s.reason ? t(`srv.reason.${s.reason}` as never) : ''}</span>
                        {s.alerts_open > 0 && <span className={`ml-auto text-xs ${s.alerts_critical > 0 ? 'text-red' : 'text-amber'}`}>{t('srv.alerts', { n: s.alerts_open })}</span>}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title={t('home.alerts')} right={<Link to="/alerts" className="text-xs text-cyan underline">{t('home.allAlerts')}</Link>}
              note={open.length ? undefined : t('home.alertsNone')}>
              {open.length > 0 && (
                <ul className="divide-y divide-line">
                  {open.slice(0, 6).map((a) => (
                    <li key={a.id} className="px-2 py-2 text-[13px]">
                      <div className="flex flex-wrap items-baseline gap-x-3">
                        <span className="font-medium">{a.label}</span>
                        <span className="ml-auto text-xs text-muted">{ago(a.opened_at)}</span>
                      </div>
                      {a.detail && <div className="mt-0.5 line-clamp-2 text-xs text-muted">{a.detail}</div>}
                    </li>
                  ))}
                  {open.length > 6 && <li className="px-2 py-2 text-xs text-muted">{t('home.moreAlerts', { n: open.length - 6 })}</li>}
                </ul>
              )}
            </Card>
          </div>

          <section aria-label={t('home.fleet')} className="space-y-3">
            <div className="flex items-baseline justify-between">
              <h2 className="text-[13px] font-semibold uppercase tracking-wide text-muted">{t('home.fleet')}</h2>
              <Link to="/servers" className="text-xs text-cyan underline">{t('home.allServers')}</Link>
            </div>
            <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">{sorted.map((s) => <MachineCard key={s.id} s={s} />)}</ul>
          </section>

          {!off.has('remnawave') && (
            <p className="text-[13px] text-muted">{t('home.vpn')} <Link to="/vpn" className="text-cyan underline">{t('home.vpnLink')}</Link></p>
          )}
        </>
      )}
    </div>
  )
}
