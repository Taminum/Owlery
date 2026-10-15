import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { useApp } from '../lib/context'
import { formatBytes, formatDateTime, formatInt } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { DigestResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'

const SEV_TONE = { info: 'muted', warning: 'amber', critical: 'red' } as const

function Empty({ children }: { children: string }) {
  return <p className="text-[13px] text-muted">{children}</p>
}

export default function Digest() {
  const { filters } = useApp()
  const { data, error } = useAnalytics<DigestResponse>('digest', filters)
  const tz = filters.tz
  return (
    <div className="space-y-4">
      <PageHead title={t('dg.title')} subtitle={t('dg.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && (
        <>
          <p className="tnum text-[13px] text-muted">{t('dg.range', { from: formatDateTime(data.from, tz), to: formatDateTime(data.to, tz) })}</p>

          <div role="status" className={`flex flex-wrap items-center gap-3 rounded-card border px-4 py-3 text-[14px] ${data.open_alerts === 0 ? 'border-green/30 bg-green/10' : 'border-amber/40 bg-amber/10'}`}>
            <span>{data.open_alerts === 0 ? t('dg.open.none') : t('dg.open.some', { n: data.open_alerts })}</span>
            {data.open_alerts > 0 && <Link to="/alerts" className="text-cyan hover:underline">{t('dg.open.go')}</Link>}
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={t('dg.sites')} note={t('dg.sites.hint')}>
              {data.new_sites.length === 0 ? <Empty>{t('dg.sites.none')}</Empty> : (
                <ul className="divide-y divide-line text-[13px]">
                  {data.new_sites.map((s) => (
                    <li key={s.site} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
                      <span><Link to={`/sites?q=${encodeURIComponent(s.site)}`} className="font-medium hover:text-cyan hover:underline">{s.site}</Link>
                        {s.category && <span className="ml-2 text-xs text-muted">{s.category}</span>}</span>
                      <span className="tnum text-xs text-muted">{t('dg.sites.conns', { n: formatInt(s.connections) })} · {t('dg.sites.users', { n: s.users })}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title={t('dg.newDevices')}>
              {data.new_devices_note === 'window_too_long' && <Empty>{t('dg.newDevices.long')}</Empty>}
              {data.new_devices_note !== 'window_too_long' && data.new_devices.length === 0 && <Empty>{t('dg.newDevices.none')}</Empty>}
              <ul className="divide-y divide-line text-[13px]">
                {data.new_devices.map((d) => (
                  <li key={`${d.panel_id}|${d.ip}`} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
                    <span><span className="font-medium">{d.name || d.ip}</span> <span className="text-xs text-muted">{d.name ? d.ip : ''} · {d.panel_name}</span></span>
                    <span className="tnum text-xs text-muted">{d.first_seen ? t('dg.newDevices.first', { at: formatDateTime(d.first_seen, tz) }) : ''}</span>
                  </li>
                ))}
              </ul>
            </Card>

            <Card title={t('dg.devices')}>
              {data.top_devices.length === 0 ? <Empty>{t('dg.devices.none')}</Empty> : (
                <ul className="divide-y divide-line text-[13px]">
                  {data.top_devices.map((d) => (
                    <li key={`${d.panel_id}|${d.ip}`} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
                      <span className="font-medium">{d.name || d.ip}</span>
                      <span className="tnum text-xs text-muted">↓ {formatBytes(d.down_bytes)} · ↑ {formatBytes(d.up_bytes)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title={t('dg.dns')}>
              {!data.dns || (data.dns.total === 0 && data.dns.failed_checks === 0) ? <Empty>{t('dg.dns.none')}</Empty> : (
                <ul className="space-y-1 text-[13px]">
                  <li>{t('dg.dns.changes', { n: data.dns.total })}{data.dns.volatile > 0 && <span className="text-muted"> · {t('dg.dns.volatile', { n: data.dns.volatile })}</span>}</li>
                  {data.dns.failed_checks > 0 && <li className="text-amber">{t('dg.dns.failed', { n: data.dns.failed_checks })}</li>}
                </ul>
              )}
            </Card>
          </div>

          <Card title={t('dg.security')}>
            {data.security_events.length === 0 ? <Empty>{t('dg.security.none')}</Empty> : (
              <ul className="divide-y divide-line text-[13px]">
                {data.security_events.map((e) => {
                  const key = `dg.ev.${e.type}` as MsgKey
                  const label = t(key) ?? e.type
                  return (
                    <li key={e.type} className="flex items-center justify-between gap-3 py-2">
                      <span><Chip tone={SEV_TONE[e.severity]}>{e.severity}</Chip> <span className="ml-2">{label}</span></span>
                      <span className="tnum font-medium">{formatInt(e.count)}</span>
                    </li>
                  )
                })}
              </ul>
            )}
            <p className="mt-3 text-[13px]"><Link to="/security" className="text-cyan hover:underline">{t('dg.security.more')}</Link></p>
          </Card>
        </>
      )}
    </div>
  )
}
