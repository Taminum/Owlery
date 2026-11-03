import { Link } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { Card } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { RoleChips, StatusChip, StatusDot, type Server } from '../components/ServerParts'
import { tone } from '../components/HostView'
import { useModulesOff } from '../lib/modules'
import type { AlertsResponse } from '../lib/types'

const TEXT = { green: 'text-green', amber: 'text-amber', red: 'text-red' } as const

function Stat({ label, value, hint, accent }: { label: string; value: number; hint?: string; accent?: 'amber' | 'red' | 'green' }) {
  return (
    <div className="rounded-card border border-line bg-surface p-4">
      <div className="text-xs text-muted">{label}</div>
      <div className={`tnum mt-1 text-[28px] font-semibold leading-9 ${accent && value > 0 ? TEXT[accent] : ''}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  )
}

function Percent({ label, v }: { label: string; v: number | null }) {
  if (v === null) return <span className="text-muted">{label} —</span>
  return <span className="text-muted">{label} <span className={`tnum ${TEXT[tone(v)]}`}>{Math.round(v)}%</span></span>
}

function ServerRow({ s }: { s: Server }) {
  const h = s.host?.has_data ? s.host : null
  const root = h?.disks.find((d) => d.m === '/' || d.m === 'C:') ?? h?.disks[0]
  const mem = h && h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
  return (
    <li>
      <Link to={`/servers/${s.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-control px-2 py-2 text-[13px] hover:bg-elevated focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan">
        <StatusDot s={s} />
        <span className="min-w-[8rem] font-medium">{s.name}</span>
        <RoleChips roles={s.roles} />
        <span className="ml-auto flex flex-wrap gap-x-4 gap-y-0.5 text-xs">
          {h ? (
            <>
              <Percent label={t('host.cpu')} v={h.cpu} />
              <Percent label={t('host.mem')} v={mem} />
              <Percent label={t('host.disk')} v={root && root.t > 0 ? (root.u * 100) / root.t : null} />
            </>
          ) : <span className="text-muted">{t('srv.reason.no_agent_short')}</span>}
        </span>
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

const RANK = { bad: 0, warn: 1, unknown: 2, ok: 3 } as const

export default function Home() {
  const servers = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 30_000)
  const alerts = useLoad((sig) => api.get<AlertsResponse>('/api/v1/alerts', sig), [], 60_000)
  const off = useModulesOff()
  const list = servers.data?.servers ?? []
  const count = (f: (s: Server) => boolean) => list.filter(f).length
  const trouble = list.filter((s) => s.status === 'bad' || s.status === 'warn').sort((a, b) => RANK[a.status] - RANK[b.status] || a.name.localeCompare(b.name, 'ru'))
  const open = (alerts.data?.alerts ?? []).filter((a) => !a.resolved_at)
  const sorted = [...list].sort((a, b) => RANK[a.status] - RANK[b.status] || a.name.localeCompare(b.name, 'ru'))
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
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Stat label={t('home.stat.total')} value={list.length} />
            <Stat label={t('home.stat.ok')} value={count((s) => s.status === 'ok')} accent="green" />
            <Stat label={t('home.stat.warn')} value={count((s) => s.status === 'warn')} accent="amber" />
            <Stat label={t('home.stat.bad')} value={count((s) => s.status === 'bad')} accent="red" hint={t('home.stat.badHint', { n: count((s) => s.reason === 'offline') })} />
            <Stat label={t('home.stat.noAgent')} value={count((s) => s.status === 'unknown')} />
          </div>

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
                  {open.slice(0, 8).map((a) => (
                    <li key={a.id} className="px-2 py-2 text-[13px]">
                      <div className="flex flex-wrap items-baseline gap-x-3">
                        <span className="font-medium">{a.label}</span>
                        <span className="ml-auto text-xs text-muted">{ago(a.opened_at)}</span>
                      </div>
                      {a.detail && <div className="mt-0.5 text-xs text-muted">{a.detail}</div>}
                    </li>
                  ))}
                  {open.length > 8 && <li className="px-2 py-2 text-xs text-muted">{t('home.moreAlerts', { n: open.length - 8 })}</li>}
                </ul>
              )}
            </Card>
          </div>

          <Card title={t('home.fleet')} right={<Link to="/servers" className="text-xs text-cyan underline">{t('home.allServers')}</Link>}>
            <ul className="divide-y divide-line">{sorted.map((s) => <ServerRow key={s.id} s={s} />)}</ul>
          </Card>

          {!off.has('remnawave') && (
            <p className="text-[13px] text-muted">{t('home.vpn')} <Link to="/vpn" className="text-cyan underline">{t('home.vpnLink')}</Link></p>
          )}
        </>
      )}
    </div>
  )
}
