import { AlertTriangle, CheckCircle2, FileWarning, Network, Radar, ServerOff, ShieldAlert, Waypoints } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useApp } from '../lib/context'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { AlertsResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'

const ICON = { agent_silent: ServerOff, panel_sync: Waypoints, sec_agent_silent: ShieldAlert, sec_tls: FileWarning, sec_port: Network, dns_check_failed: Radar, dns_change: Radar } as const

export default function Alerts() {
  const { filters } = useApp()
  const q = filters.panels.length ? `&panel_ids=${filters.panels.join(',')}` : ''
  const { data, error } = useLoad((s) => api.get<AlertsResponse>(`/api/v1/alerts?state=all${q}`, s), [q], 30_000)
  const tz = filters.tz
  const open = data?.alerts.filter((a) => !a.resolved_at) ?? []
  const closed = data?.alerts.filter((a) => a.resolved_at) ?? []

  return (
    <div className="space-y-4">
      <PageHead title={t('al.title')} subtitle={t('al.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && (
        <>
          {open.length === 0 ? (
            <div role="status" className="flex items-center gap-3 rounded-card border border-green/30 bg-green/10 px-4 py-4 text-[14px]">
              <CheckCircle2 size={20} aria-hidden className="text-green" />
              <span>{t('al.allGood')}</span>
            </div>
          ) : (
            <div className="space-y-3" aria-label={t('al.open')}>
              {open.map((a) => {
                const Icon = ICON[a.kind as keyof typeof ICON] ?? AlertTriangle
                return (
                  <div key={a.id} role="alert" className="flex gap-3 rounded-card border border-amber/40 bg-amber/10 px-4 py-3">
                    <Icon size={20} aria-hidden className="mt-0.5 shrink-0 text-amber" />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="font-semibold">{a.label}</span>
                        <span className="text-xs text-muted">{a.panel_name}</span>
                      </div>
                      <p className="mt-0.5 text-[13px] text-fg/90">{a.detail}</p>
                      <p className="tnum mt-1 text-xs text-muted">{t('al.since')} {formatDateTime(a.opened_at, tz)}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
          <Card title={t('al.history')} note={t('al.historyNote')}>
            {closed.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{t('al.noHistory')}</p> : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-[13px]">
                  <caption className="sr-only">{t('al.history')}</caption>
                  <thead><tr className="text-left text-xs text-muted">
                    <th scope="col" className="px-2 py-2 font-medium">{t('al.what')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('al.detail')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('al.opened')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('al.closed')}</th>
                  </tr></thead>
                  <tbody>
                    {closed.map((a) => (
                      <tr key={a.id} className="border-t border-line/60">
                        <td className="px-2 py-2"><span className="font-medium">{a.label}</span> <Chip tone="muted">{a.panel_name}</Chip></td>
                        <td className="px-2 py-2 text-muted">{a.detail}</td>
                        <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatDateTime(a.opened_at, tz)}</td>
                        <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{a.resolved_at ? formatDateTime(a.resolved_at, tz) : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  )
}
