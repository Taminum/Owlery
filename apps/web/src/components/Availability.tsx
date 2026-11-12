import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'

interface Day { day: string; minutes: number; of: number }

const pct = (d: Day) => (d.of > 0 ? (d.minutes * 100) / d.of : 0)
const color = (p: number) => (p >= 99.5 ? 'bg-green' : p >= 95 ? 'bg-amber' : 'bg-red')

/** The last thirty days of a machine as a strip of days: how much of each day its agent answered. */
export function Availability({ hostId }: { hostId: string }) {
  const { data } = useLoad((s) => api.get<{ days: Day[] }>(`/api/v1/hosts/${hostId}/availability`, s), [hostId], 5 * 60_000)
  const days = data?.days ?? []
  if (days.length === 0) return null
  const total = days.reduce((n, d) => n + d.of, 0)
  const up = days.reduce((n, d) => n + d.minutes, 0)
  const all = total > 0 ? (up * 100) / total : 0
  return (
    <div>
      <p className="mb-1 flex items-baseline justify-between text-xs text-muted">
        <span>{t('host.avail', { n: days.length })}</span>
        <span className="tnum text-fg">{all.toFixed(all >= 99.95 || all < 99 ? 1 : 2).replace('.', ',')}%</span>
      </p>
      <div className="flex h-5 items-stretch gap-[2px]" role="img" aria-label={t('host.availLabel', { p: all.toFixed(1).replace('.', ','), n: days.length })}>
        {days.map((d) => {
          const p = pct(d)
          return <span key={d.day} title={t('host.availDay', { day: d.day, p: p.toFixed(1).replace('.', ',') })} className={`min-w-[3px] flex-1 rounded-[2px] ${color(p)}`} />
        })}
      </div>
    </div>
  )
}
