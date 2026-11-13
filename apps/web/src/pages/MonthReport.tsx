import { useState } from 'react'
import { ChevronLeft, ChevronRight, Send } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { ApiError, api } from '../lib/api'
import { formatBytes, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Skeleton } from '../components/ui'
import { GhostButton } from '../components/Modal'
import { PageHead } from '../components/Analyzer'

interface Month {
  month: string
  availability: number | null
  worst: { name: string; down_mins: number }[]
  alerts: number
  noisy: { label: string; count: number } | null
  longest: { label: string; mins: number } | null
  events: { type: string; severity: string; count: number }[]
  event_total: number
  net_downs: number
  net_down_mins: number
  net_worst?: string
  new_devices: number
  traffic_bytes: number | null
  paid: { currency: string; amount: number }[]
}
interface Report { cur: Month; prev: Month; upcoming: { name: string; due: string; amount: number; currency: string }[] }

const ym = (d: Date) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`
const shift = (m: string, by: number) => { const [y, mo] = m.split('-').map(Number); return ym(new Date(Date.UTC(y, mo - 1 + by, 1))) }
const MONTHS = ['январь', 'февраль', 'март', 'апрель', 'май', 'июнь', 'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь']
const title = (m: string) => { const [y, mo] = m.split('-').map(Number); return `${MONTHS[mo - 1]} ${y}`.replace(/^./, (c) => c.toUpperCase()) }
const mins = (m: number) => (m >= 60 ? `${Math.floor(m / 60)} ч${m % 60 ? ` ${m % 60} мин` : ''}` : `${m} мин`)
const num = (n: number, d = 2) => n.toFixed(d).replace('.', ',')

type Tone = 'good' | 'bad' | 'flat'
function Tile({ label, value, note, tone = 'flat' }: { label: string; value: string; note?: string; tone?: Tone }) {
  const color = tone === 'good' ? 'text-green' : tone === 'bad' ? 'text-amber' : 'text-muted'
  return (
    <div className="rounded-control border border-line bg-elevated px-3 py-2.5">
      <div className="text-xs text-muted">{label}</div>
      <div className="tnum mt-0.5 text-[22px] font-medium">{value}</div>
      {note && <div className={`text-xs ${color}`}>{note}</div>}
    </div>
  )
}

/** Signed difference against the month before; nothing when there is nothing to set it against. */
function diff(cur: number, prev: number | null | undefined, lowerIsBetter: boolean, fmt: (n: number) => string): { note?: string; tone: Tone } {
  if (prev == null) return { tone: 'flat' }
  const d = cur - prev
  if (d === 0) return { note: t('rp.same'), tone: 'flat' }
  return { note: `${d > 0 ? '+' : '−'}${fmt(Math.abs(d))}`, tone: (d < 0) === lowerIsBetter ? 'good' : 'bad' }
}

function Line({ children }: { children: string }) { return <p className="py-0.5 text-[13px]">{children}</p> }

export default function MonthReport() {
  const [now] = useState(() => new Date())
  const thisMonth = ym(now)
  const [month, setMonth] = useState(thisMonth)
  const q = useLoad((sig) => api.get<Report>(`/api/v1/reports/month?month=${month}`, sig), [month])
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const r = q.data
  const c = r?.cur
  const p = r?.prev

  async function send() {
    setNote('')
    setErr('')
    try {
      const res = await api.post<{ sent: number; failed: number }>(`/api/v1/reports/month/send?month=${month}`)
      setNote(`${t('rp.sent', { n: res.sent })}${res.failed ? ` ${t('rp.sendFailed', { n: res.failed })}` : ''}`)
    } catch (e) {
      setErr(e instanceof ApiError && e.code === 'no_channels' ? t('rp.noChannels') : t('rp.sendError'))
    }
  }

  const avail = c?.availability != null ? diff(c.availability, p?.availability, false, (n) => `${num(n)} п.п.`) : { tone: 'flat' as Tone }
  const al = c ? diff(c.alerts, p && p.alerts > 0 ? p.alerts : null, true, (n) => formatInt(n)) : { tone: 'flat' as Tone }
  const ev = c ? diff(c.event_total, p && p.event_total > 0 ? p.event_total : null, true, (n) => formatInt(n)) : { tone: 'flat' as Tone }
  const tr = c?.traffic_bytes != null && p?.traffic_bytes ? diff(c.traffic_bytes, p.traffic_bytes, false, formatBytes) : { tone: 'flat' as Tone }

  return (
    <div className="space-y-4">
      <PageHead title={t('rp.title')} subtitle={t('rp.subtitle')} right={<GhostButton size="m" onClick={() => void send()}><Send size={14} aria-hidden className="mr-1.5 inline" />{t('rp.send')}</GhostButton>} />
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" aria-label={t('rp.prev')} title={t('rp.prev')} onClick={() => setMonth(shift(month, -1))} className="grid h-8 w-8 place-items-center rounded-control border border-line bg-elevated text-muted hover:text-fg"><ChevronLeft size={16} aria-hidden /></button>
        <span className="text-[16px] font-medium">{title(month)}</span>
        {month < thisMonth && <button type="button" aria-label={t('rp.next')} title={t('rp.next')} onClick={() => setMonth(shift(month, 1))} className="grid h-8 w-8 place-items-center rounded-control border border-line bg-elevated text-muted hover:text-fg"><ChevronRight size={16} aria-hidden /></button>}
        <span className="text-xs text-muted">{t('rp.vs')}</span>
      </div>
      {month === thisMonth && <p className="text-xs text-amber">{t('rp.partial')}</p>}
      {note && <p role="status" className="text-[13px] text-green">{note}</p>}
      {err && <p role="alert" className="text-[13px] text-red">{err}</p>}
      {q.error && <p role="alert" className="text-[13px] text-red">{t('rp.error')}</p>}
      {!r && !q.error && <Skeleton className="h-40" />}
      {r && c && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Tile label={t('rp.availability')} value={c.availability != null ? `${num(c.availability)}%` : t('rp.noData')} note={avail.note} tone={avail.tone} />
            <Tile label={t('rp.alerts')} value={formatInt(c.alerts)} note={al.note} tone={al.tone} />
            <Tile label={t('rp.events')} value={formatInt(c.event_total)} note={ev.note} tone={ev.tone} />
            <Tile label={t('rp.traffic')} value={c.traffic_bytes != null ? formatBytes(c.traffic_bytes) : t('rp.noData')} note={tr.note} tone={tr.tone} />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={t('rp.machines')}>
              {c.worst.length === 0 && !c.noisy && !c.longest ? <p className="text-[13px] text-muted">{t('rp.noDowntime')}</p> : null}
              {c.worst.map((w) => <Line key={w.name}>{t('rp.worst', { name: w.name, time: mins(w.down_mins) })}</Line>)}
              {c.noisy && <Line>{t('rp.noisy', { label: c.noisy.label, n: c.noisy.count })}</Line>}
              {c.longest && <Line>{t('rp.longest', { label: c.longest.label, time: mins(c.longest.mins) })}</Line>}
            </Card>
            <Card title={t('rp.security')}>
              {c.events.length === 0 ? <p className="text-[13px] text-muted">{t('rp.noEvents')}</p> : (
                <ul className="divide-y divide-line/60 text-[13px]">
                  {c.events.map((e) => {
                    const key = `dg.ev.${e.type}` as MsgKey
                    const label = t(key)
                    return <li key={e.type} className="flex justify-between gap-3 py-1.5"><span>{label === key ? e.type : label}</span><span className="tnum font-medium">{formatInt(e.count)}</span></li>
                  })}
                </ul>
              )}
            </Card>
            <Card title={t('rp.network')}>
              {c.net_downs === 0 ? <Line>{t('rp.noNetDowns')}</Line> : <Line>{t('rp.netDowns', { n: c.net_downs, time: mins(c.net_down_mins), name: c.net_worst ?? '' })}</Line>}
              <Line>{t('rp.newDevices', { n: c.new_devices })}</Line>
            </Card>
            <Card title={t('rp.money')}>
              <Line>{c.paid.length === 0 ? t('rp.noPaid') : t('rp.paid', { sum: c.paid.map((m) => `${num(m.amount)} ${m.currency}`).join(' + ') })}</Line>
              {r.upcoming.map((u) => <Line key={`${u.name}${u.due}`}>{`${t('rp.upcoming')}: ${u.name}, ${u.due.slice(8, 10)}.${u.due.slice(5, 7)}, ${num(u.amount)} ${u.currency}`}</Line>)}
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
