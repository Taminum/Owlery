import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Segmented } from './ui'
import { controlCls } from './Popover'
import { Drawer } from './Drawer'
import { TableSkeleton } from './Analyzer'

interface Row { panel_id: string; panel_name: string; user: string; label: string; note?: string; ips: number; requests: number; last: string; clients: string[]; level: 'leak' | 'check' }
interface Leaks { asked: number; leaks: number; new: number; rows: Row[] }
interface IPRow { ip: string; country?: string; org?: string; hosting: boolean; requests: number; last: string; client?: string }

const DAYS = ['1', '7', '30'] as const
const MINS = [3, 5, 8, 10]

function Where({ row, days, tz }: { row: Row; days: number; tz: string }) {
  const { data, error } = useLoad((s) => api.get<{ ips: IPRow[] }>(`/api/v1/subscriptions/leaks/ips?panel_id=${encodeURIComponent(row.panel_id)}&user=${encodeURIComponent(row.user)}&days=${days}`, s), [row.panel_id, row.user, days])
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  return (
    <div className="space-y-3 text-[13px]">
      <ul className="divide-y divide-line/60">
        {data.ips.map((x) => (
          <li key={x.ip} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 py-2">
            <span className="min-w-0">
              <span className="tnum font-medium">{x.ip}</span>
              {x.hosting && <span className="ml-2"><Chip tone="amber">{t('sl.hosting')}</Chip></span>}
              <span className="block truncate text-xs text-muted">{[x.country, x.org].filter(Boolean).join(', ') || '—'}{x.client ? ` · ${x.client}` : ''}</span>
            </span>
            <span className="text-right text-xs text-muted"><span className="tnum">{t('sl.times')}: {formatInt(x.requests)}</span><span className="block">{formatDateTime(x.last, tz)}</span></span>
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted">{t('sl.hint')}</p>
    </div>
  )
}

/** Subscriptions taken from many different addresses lately: a sign that the link has been passed on. Reading only. */
export function SubLeaks({ tz }: { tz: string }) {
  const [days, setDays] = useState<(typeof DAYS)[number]>('7')
  const [min, setMin] = useState(5)
  const [sel, setSel] = useState<Row | null>(null)
  const { data, error } = useLoad((s) => api.get<Leaks>(`/api/v1/subscriptions/leaks?days=${days}&min=${min}`, s), [days, min], 300_000)
  if (error && !data) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data || data.asked === 0) return null
  return (
    <Card title={t('sl.title')} note={t('sl.note')} right={
      <div className="flex flex-wrap items-center gap-2">
        <Segmented label={t('sl.days')} value={days} onChange={setDays} options={DAYS.map((d) => ({ value: d, label: `${d} дн.` }))} />
        <label className="sr-only" htmlFor="sl-min">{t('sl.min')}</label>
        <select id="sl-min" value={min} onChange={(e) => setMin(Number(e.target.value))} className={controlCls}>
          {MINS.map((n) => <option key={n} value={n}>{t('sl.minN', { n })}</option>)}
        </select>
      </div>
    }>
      <div className="mb-3 grid grid-cols-3 gap-3">
        <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('sl.asked')}</div><div className="tnum text-xl font-semibold">{formatInt(data.asked)}</div></div>
        <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('sl.leaks')}</div><div className={`tnum text-xl font-semibold ${data.leaks > 0 ? 'text-red' : ''}`}>{formatInt(data.leaks)}</div></div>
        <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{t('sl.new')}</div><div className="tnum text-xl font-semibold">{formatInt(data.new)}</div></div>
      </div>
      {data.rows.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{t('sl.none', { n: min })}</p> : (
        <ul className="divide-y divide-line/60">
          {data.rows.map((r) => (
            <li key={`${r.panel_id}:${r.user}`} className="grid grid-cols-[minmax(0,1.4fr)_auto_auto] items-center gap-3 py-2.5 text-[13px] sm:grid-cols-[minmax(0,1.4fr)_70px_80px_minmax(0,1.2fr)_120px]">
              <span className="min-w-0">
                <button type="button" onClick={() => setSel(r)} title={t('sl.open')} className="font-medium text-fg underline-offset-2 hover:text-cyan hover:underline">{r.label}</button>
                <span className="ml-2"><Chip tone={r.level === 'leak' ? 'red' : 'amber'}>{r.level === 'leak' ? t('sl.leak') : t('sl.check')}</Chip></span>
                <span className="block truncate text-xs text-muted">{r.panel_name}{r.note ? ` · ${r.note}` : ''}</span>
              </span>
              <span className={`tnum font-medium ${r.level === 'leak' ? 'text-red' : 'text-amber'}`} title={t('sl.ips')}>{r.ips} IP</span>
              <span className="tnum text-muted" title={t('sl.requests')}>{formatInt(r.requests)}</span>
              <span className="hidden truncate text-xs text-muted sm:block" title={t('sl.clients')}>{r.clients.join(', ') || '—'}</span>
              <span className="hidden whitespace-nowrap text-xs text-muted sm:block" title={t('sl.last')}>{formatDateTime(r.last, tz)}</span>
            </li>
          ))}
        </ul>
      )}
      {sel && <Drawer title={t('sl.detail', { name: sel.label, days })} onClose={() => setSel(null)}><Where row={sel} days={Number(days)} tz={tz} /></Drawer>}
    </Card>
  )
}
