import { Link } from 'react-router-dom'
import { CircleCheck, DoorOpen, KeyRound, Lock, OctagonAlert, ShieldAlert, TriangleAlert, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatInt, plural } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { StatusChip, type Server } from '../components/ServerParts'
import { useModulesOff } from '../lib/modules'
import type { AlertsResponse, FleetSummary } from '../lib/types'

const RANK = { bad: 0, warn: 1, unknown: 2, ok: 3 } as const

/** The one sentence the whole page is about: is the farm all right. */
function Hero({ list, alerts, offline }: { list: Server[]; alerts: number; offline: number }) {
  const bad = list.filter((s) => s.status === 'bad').length
  const warn = list.filter((s) => s.status === 'warn').length
  const state: 'ok' | 'warn' | 'bad' = bad > 0 ? 'bad' : warn > 0 ? 'warn' : 'ok'
  const Icon: LucideIcon = { ok: CircleCheck, warn: TriangleAlert, bad: OctagonAlert }[state]
  const look = {
    ok: 'border-green/40 bg-gradient-to-br from-green/15 via-surface to-surface text-green',
    warn: 'border-amber/40 bg-gradient-to-br from-amber/15 via-surface to-surface text-amber',
    bad: 'border-red/40 bg-gradient-to-br from-red/15 via-surface to-surface text-red',
  }[state]
  const asking = bad + warn
  const noAgent = list.filter((s) => s.status === 'unknown').length
  return (
    <section aria-label={t(`home.hero.${state}` as never)} className={`rounded-card border p-5 ${look}`}>
      <div className="flex items-center gap-5">
        <Icon size={44} strokeWidth={1.6} aria-hidden className="shrink-0" />
        <div className="min-w-0">
          <h2 className="text-[22px] font-semibold leading-7 text-fg">{t(`home.hero.${state}` as never)}</h2>
          <p className="mt-0.5 text-[13px] text-muted">
            {t('home.hero.sub', { n: list.length })}
            {asking > 0 && <> · {t('home.hero.asking', { n: asking })}</>}
            {offline > 0 && <> · {t('home.hero.offline', { n: offline })}</>}
            {alerts > 0 && <> · {t('home.hero.alerts', { n: alerts })}</>}
          </p>
        </div>
      </div>
      {noAgent > 0 && <p className="mt-3 text-xs text-muted">{t('home.hero.noAgent', { n: noAgent })}</p>}
    </section>
  )
}

function Tile({ icon: Icon, label, value, sub, tone, to }: { icon: LucideIcon; label: string; value: ReactNode; sub?: ReactNode; tone?: 'amber' | 'red'; to?: string }) {
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-xs text-muted"><Icon size={14} aria-hidden />{label}</div>
      <div className={`tnum mt-1 text-[26px] font-semibold leading-8 ${tone === 'red' ? 'text-red' : tone === 'amber' ? 'text-amber' : ''}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </>
  )
  const cls = 'block rounded-card border border-line bg-surface p-3.5'
  return to
    ? <Link to={to} className={`${cls} transition-colors hover:border-cyan/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan`}>{body}</Link>
    : <section className={cls}>{body}</section>
}

function daysLeft(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

/** The same change on the same machine, repeated, reads as one line with a count. */
function changeLines(items: FleetSummary['changes']['items']): string {
  const seen = new Map<string, number>()
  for (const c of items) {
    const k = `${c.server}: ${t(`home.change.${c.type}` as never)}`
    seen.set(k, (seen.get(k) ?? 0) + 1)
  }
  return [...seen].slice(0, 2).map(([k, n]) => (n > 1 ? `${k} ×${n}` : k)).join('; ')
}

function Summary({ sum, hours }: { sum: FleetSummary; hours: number }) {
  const top = sum.bans.servers[0]
  const nearest = sum.tls.nearest_end ? daysLeft(sum.tls.nearest_end) : null
  const o = sum.owlery
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Tile icon={ShieldAlert} label={t('home.sum.bans')} value={formatInt(sum.bans.total)} to="/security"
        sub={sum.bans.total === 0 ? t('home.sum.bansNone', { h: hours }) : t('home.sum.bansSub', { n: sum.bans.servers.length, name: top?.name ?? '' })} />
      <Tile icon={DoorOpen} label={t('home.sum.changes')} value={formatInt(sum.changes.total)} tone={sum.changes.total > 0 ? 'amber' : undefined} to="/security"
        sub={sum.changes.total === 0 ? t('home.sum.changesNone') : changeLines(sum.changes.items)} />
      {o && (
        <Tile icon={KeyRound} label={t('home.sum.owlery')} value={formatInt(o.logins)} tone={o.failed_logins > 0 ? 'amber' : undefined} to="/settings"
          sub={`${o.failed_logins > 0 ? `${t('home.sum.failedLogins', { n: o.failed_logins })} · ` : ''}${t('home.sum.sessions', { n: o.terminals + o.screens + o.desktops })}`} />
      )}
      <Tile icon={Lock} label={t('home.sum.tls')} value={nearest === null ? '—' : `${nearest} ${plural(nearest, 'день', 'дня', 'дней')}`}
        tone={sum.tls.problems > 0 || (nearest !== null && nearest < 14) ? 'red' : nearest !== null && nearest < 30 ? 'amber' : undefined} to="/security"
        sub={sum.tls.problems > 0 ? t('home.sum.tlsProblems', { n: sum.tls.problems }) : nearest === null ? t('home.sum.tlsNone') : sum.tls.nearest_host} />
    </div>
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
  const summary = useLoad((sig) => api.get<FleetSummary>('/api/v1/summary?hours=24', sig), [], 120_000)
  const off = useModulesOff()
  const list = servers.data?.servers ?? []
  const byTrouble = (a: Server, b: Server) => RANK[a.status] - RANK[b.status] || a.name.localeCompare(b.name, 'ru')
  const trouble = list.filter((s) => s.status === 'bad' || s.status === 'warn').sort(byTrouble)
  const open = (alerts.data?.alerts ?? []).filter((a) => !a.resolved_at)
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
          <Hero list={list} alerts={open.length} offline={list.filter((s) => s.reason === 'offline').length} />
          {summary.data && <Summary sum={summary.data} hours={24} />}

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

          <p className="text-[13px] text-muted">
            <Link to="/servers" className="text-cyan underline">{t('home.allServers')}</Link>
            {!off.has('remnawave') && <> · {t('home.vpn')} <Link to="/vpn" className="text-cyan underline">{t('home.vpnLink')}</Link></>}
          </p>
        </>
      )}
    </div>
  )
}
