import { t } from '../i18n'
import { useApp } from '../lib/context'
import { formatBytes, formatInt } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { CountriesResponse } from '../lib/types'
import { Card } from './ui'
import { ShareBar } from './Analyzer'

/** A flag from the two-letter code (a pair of regional-indicator letters). Where the system has no
 *  flag glyphs the code itself is shown, so the code is always printed next to it. */
export const flag = (code: string) =>
  /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : ''

/** Where the traffic goes, by the country of the destination IP. */
export function CountriesCard({ subject = '', limit = 12, compact = false }: { subject?: string; limit?: number; compact?: boolean }) {
  const { filters } = useApp()
  const { data, error } = useAnalytics<CountriesResponse>('countries', filters, { subject, limit: String(limit) })
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0
  const body = () => {
    if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
    if (!data) return <p className="py-6 text-center text-[13px] text-muted">{t('state.loading')}</p>
    if (data.meta.state === 'no_data' || data.rows.length === 0) return <p className="py-6 text-center text-[13px] text-muted">{t('geo.none')}</p>
    return (
      <>
        <ul className="space-y-2" aria-label={t('geo.title')}>
          {data.rows.map((r) => (
            <li key={r.code} className="grid grid-cols-[minmax(0,1fr)_auto_140px] items-center gap-2 text-[13px]">
              <span className="truncate" title={r.name}><span aria-hidden className="mr-2">{flag(r.code)}</span><span className="font-medium">{r.name}</span> <span className="text-xs text-muted">{r.code}</span></span>
              <span className="tnum text-muted" title={r.bytes == null ? undefined : formatBytes(r.bytes)}>{formatInt(r.connections)}</span>
              <ShareBar share={r.share} max={max} />
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs leading-5 text-muted">
          {t('geo.coverage', { placed: formatInt(data.located), total: formatInt(data.total_connections) })}
          {compact ? '' : ` ${t('geo.coverageNote')}`}
        </p>
      </>
    )
  }
  return (
    <Card title={t('geo.title')} note={t('geo.note')} className="h-full">
      {body()}
      <p className="mt-2 text-[11px] text-muted/80">{t('geo.credit')}</p>
    </Card>
  )
}
