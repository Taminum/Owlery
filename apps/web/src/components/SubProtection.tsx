import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Segmented } from './ui'
import { controlCls } from './Popover'

const DAYS = ['1', '7', '30'] as const
const MINS = [3, 5, 8, 10]

interface TorrentRow { panel_id: string; panel_name: string; user: string; label: string; note?: string; reports: number; recent: number; nodes: string[]; last: string; repeat: boolean }
interface Torrents { seen: boolean; reports: number; subs: number; nodes: number; rows: TorrentRow[] }
interface DeviceRow { panel_id: string; panel_name: string; user: string; label: string; note?: string; devices: number; ips: number; level: 'leak' | 'check' }
interface Devices { seen: boolean; days: number; rows: DeviceRow[] }

function Off({ text }: { text: string }) {
  return <p className="rounded-control border border-dashed border-line px-3 py-3 text-[13px] text-muted">{text}</p>
}

function Metric({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{label}</div><div className={`tnum text-xl font-semibold ${tone ?? ''}`}>{formatInt(value)}</div></div>
}

/** Subscriptions the torrent blocker of the panels caught lately. Reading only. */
export function SubTorrents({ tz }: { tz: string }) {
  const [days, setDays] = useState<(typeof DAYS)[number]>('7')
  const { data, error } = useLoad((s) => api.get<Torrents>(`/api/v1/subscriptions/torrents?days=${days}`, s), [days], 300_000)
  if (error && !data) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return null
  return (
    <Card title={t('tr.title')} note={t('tr.note')} right={data.seen ? <Segmented label={t('tr.days')} value={days} onChange={setDays} options={DAYS.map((d) => ({ value: d, label: `${d} дн.` }))} /> : undefined}>
      {!data.seen ? <Off text={t('tr.off')} /> : (
        <>
          <div className="mb-3 grid grid-cols-3 gap-3">
            <Metric label={t('tr.reports')} value={data.reports} />
            <Metric label={t('tr.subs')} value={data.subs} tone={data.subs > 0 ? 'text-amber' : ''} />
            <Metric label={t('tr.nodes')} value={data.nodes} />
          </div>
          {data.rows.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{t('tr.none')}</p> : (
            <ul className="divide-y divide-line/60">
              {data.rows.map((r) => (
                <li key={`${r.panel_id}:${r.user}`} className="grid grid-cols-[minmax(0,1.4fr)_auto] items-center gap-3 py-2.5 text-[13px] sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_70px_120px]">
                  <span className="min-w-0">
                    <span className="font-medium">{r.label}</span>
                    {r.repeat && <span className="ml-2"><Chip tone="red">{t('tr.repeat')}</Chip></span>}
                    <span className="block truncate text-xs text-muted">{r.panel_name}{r.note ? ` · ${r.note}` : ''}</span>
                  </span>
                  <span className="hidden truncate text-xs text-muted sm:block">{r.nodes.join(', ') || '—'}</span>
                  <span className={`tnum text-right font-medium ${r.repeat ? 'text-red' : ''}`}>{t('tr.times', { n: r.reports })}</span>
                  <span className="hidden whitespace-nowrap text-right text-xs text-muted sm:block" title={t('tr.last')}>{formatDateTime(r.last, tz)}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  )
}

/** Subscriptions with many devices registered, with the addresses they were taken from. Reading only. */
export function SubDevices() {
  const [min, setMin] = useState(5)
  const { data, error } = useLoad((s) => api.get<Devices>(`/api/v1/subscriptions/devices?min=${min}`, s), [min], 300_000)
  if (error && !data) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return null
  return (
    <Card title={t('dv.title')} note={t('dv.note')} right={data.seen ? (
      <>
        <label className="sr-only" htmlFor="dv-min">{t('dv.min')}</label>
        <select id="dv-min" value={min} onChange={(e) => setMin(Number(e.target.value))} className={controlCls}>
          {MINS.map((n) => <option key={n} value={n}>{t('dv.minN', { n })}</option>)}
        </select>
      </>
    ) : undefined}>
      {!data.seen ? <Off text={t('dv.off')} /> : data.rows.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{t('dv.none', { n: min })}</p> : (
        <ul className="divide-y divide-line/60">
          {data.rows.map((r) => (
            <li key={`${r.panel_id}:${r.user}`} className="grid grid-cols-[minmax(0,1.4fr)_auto_auto] items-center gap-3 py-2.5 text-[13px] sm:grid-cols-[minmax(0,1.4fr)_80px_110px_90px]">
              <span className="min-w-0">
                <span className="font-medium">{r.label}</span>
                <span className="block truncate text-xs text-muted">{r.panel_name}{r.note ? ` · ${r.note}` : ''}</span>
              </span>
              <span className={`tnum font-medium ${r.level === 'leak' ? 'text-red' : ''}`} title={t('dv.devices')}>{r.devices} устр.</span>
              <span className="tnum text-muted" title={t('dv.ips', { days: data.days })}>{r.ips} IP</span>
              <span className="hidden sm:block"><Chip tone={r.level === 'leak' ? 'red' : 'amber'}>{r.level === 'leak' ? t('dv.leak') : t('dv.check')}</Chip></span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
