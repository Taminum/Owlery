import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatBytes, formatClock, formatDateTime, formatInt } from '../lib/format'
import { useApp } from '../lib/context'
import { analyticsURL, useAnalytics } from '../hooks/useAnalytics'
import type { TimelineResponse } from '../lib/types'
import { Card, Chip, Segmented } from './ui'
import { CoverageLine, NoDataPanel, TableSkeleton } from './Analyzer'
import { controlCls } from './Popover'

const PAGE = 100

/** The calendar day of a moment in the viewer's zone, as YYYY-MM-DD (it only groups, and sorts as text). */
function dayKey(iso: string, tz: string): string {
  return new Intl.DateTimeFormat('en-CA', { timeZone: tz === 'local' ? undefined : tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(iso))
}

function dayTitle(iso: string, tz: string): string {
  const zone = tz === 'local' ? undefined : tz
  const d = new Date(iso)
  const same = (a: Date, b: Date) => dayKey(a.toISOString(), tz) === dayKey(b.toISOString(), tz)
  const now = new Date()
  const full = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', weekday: 'short', timeZone: zone }).format(d)
  if (same(d, now)) return `Сегодня, ${full}`
  if (same(d, new Date(now.getTime() - 86_400_000))) return `Вчера, ${full}`
  return full
}

const SRC_OPTIONS = [['', 'tl.src.all'], ['node', 'src.node'], ['router', 'src.router'], ['awg', 'src.awg']] as const

/**
 * What was opened at the sites that match the search, newest first, a visit per line: the connections of one person to one
 * site with no pause longer than half an hour. It knows domains only.
 */
export function Timeline({ q, subject }: { q: string; subject: string }) {
  const { filters } = useApp()
  const tz = filters.tz
  const [raw, setRaw] = useState(false)
  const [src, setSrc] = useState('')
  const base = { q, subject, src, ...(raw ? { raw: '1' } : {}), limit: String(PAGE) }
  const { data, error, url } = useAnalytics<TimelineResponse>('timeline', filters, base, q !== '')
  const [more, setMore] = useState<{ url: string; rows: TimelineResponse['rows']; more: boolean } | null>(null)
  const [moreError, setMoreError] = useState('')
  const [busy, setBusy] = useState(false)
  const extra = more && more.url === url ? more : null
  const rows = data ? [...data.rows, ...(extra?.rows ?? [])] : []
  const hasMore = extra ? extra.more : !!data?.more

  async function loadMore() {
    if (!rows.length || busy) return
    setBusy(true)
    setMoreError('')
    try {
      const next = await api.get<TimelineResponse>(analyticsURL('timeline', filters, { ...base, before: rows[rows.length - 1].start }))
      setMore({ url, rows: [...(extra?.rows ?? []), ...next.rows], more: next.more })
    } catch (e) {
      setMoreError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  const days: { key: string; title: string; items: typeof rows }[] = []
  for (const r of rows) {
    const k = dayKey(r.start, tz)
    const last = days[days.length - 1]
    if (last && last.key === k) last.items.push(r)
    else days.push({ key: k, title: dayTitle(r.start, tz), items: [r] })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented label={t('tl.mode')} value={raw ? 'raw' : 'visits'} onChange={(v) => setRaw(v === 'raw')} options={[{ value: 'visits', label: t('tl.mode.visits') }, { value: 'raw', label: t('tl.mode.raw') }]} />
        <label className="sr-only" htmlFor="tl-src">{t('tl.src')}</label>
        <select id="tl-src" value={src} onChange={(e) => setSrc(e.target.value)} className={controlCls}>
          {SRC_OPTIONS.map(([v, k]) => <option key={v} value={v}>{t(k)}</option>)}
        </select>
      </div>
      {q === '' && <p className="rounded-card border border-line bg-surface px-4 py-6 text-center text-[13px] text-muted">{t('tl.empty')}</p>}
      {q !== '' && error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {q !== '' && !data && !error && <TableSkeleton />}
      {q !== '' && data && <CoverageLine meta={data.meta} tz={tz} />}
      {q !== '' && data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {q !== '' && data?.meta.state === 'ok' && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('tl.visits')}</div><div className="tnum text-xl font-semibold">{formatInt(data.totals.visits)}</div></div>
            <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('tl.sites')}</div><div className="tnum text-xl font-semibold">{formatInt(data.totals.sites)}</div></div>
            <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('tl.last')}</div><div className="tnum text-xl font-semibold">{data.totals.last ? formatDateTime(data.totals.last, tz) : '—'}</div></div>
          </div>
          {rows.length === 0 && <p className="py-6 text-center text-[13px] text-muted">{t('tl.none')}</p>}
          {days.map((d) => (
            <Card key={d.key} title={d.title}>
              <ul className="divide-y divide-line/60">
                {d.items.map((r, i) => (
                  <li key={`${r.start}|${r.site}|${r.label}|${i}`} className="grid grid-cols-[3.2rem_minmax(0,1fr)_auto] items-center gap-3 py-2.5 text-[13px]">
                    <span className="tnum text-muted">{formatClock(r.start, tz)}</span>
                    <span className="min-w-0">
                      <span className="font-medium" title={r.host}>{r.site}</span>
                      {r.service && <span className="ml-2 text-xs text-cyan">{r.service}</span>}
                      <span className="ml-2 text-xs text-muted">
                        {raw ? r.host : `${r.start === r.end ? '' : `${formatClock(r.start, tz)}–${formatClock(r.end, tz)}, `}${t('tl.connN', { n: formatInt(r.connections) })}${r.hosts > 1 ? `, ${t('tl.hostsN', { n: r.hosts })}` : ''}`}
                        {r.bytes != null ? `, ${formatBytes(r.bytes)}` : ''}
                      </span>
                      <span className="block truncate text-xs text-muted">{r.label}{r.note ? ` · ${r.note}` : ''}</span>
                    </span>
                    <Chip tone={r.src === 'router' ? 'green' : 'cyan'}>{r.src === 'router' ? t('tl.router') : r.src === 'awg' ? t('tl.awg') : r.node ? t('tl.vpn', { node: r.node }) : t('src.node')}</Chip>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
          {moreError && <p role="alert" className="text-[13px] text-red">{moreError}</p>}
          <div className="flex items-center justify-between gap-3 text-xs text-muted">
            <span>{t('tl.note')}</span>
            {hasMore && <button type="button" onClick={() => void loadMore()} disabled={busy} className={`${controlCls} disabled:opacity-40`}>{t('tl.more')}</button>}
          </div>
        </>
      )}
    </div>
  )
}
