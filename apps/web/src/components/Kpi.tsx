import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { Area, AreaChart, ResponsiveContainer } from 'recharts'
import type { Series } from '../lib/types'
import { useSmooth } from '../lib/chartLook'

export function Sparkline({ series, color, id }: { series: Series; color: string; id: string }) {
  const smooth = useSmooth()
  const data = (series?.v ?? []).map((v, i) => ({ i, v }))
  if (data.length < 2) return <div className="h-10" />
  return (
    <div className="h-10 w-full" aria-hidden>
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`sp-${id}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <Area type={smooth ? 'monotone' : 'linear'} dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#sp-${id})`} isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

export function Kpi({
  id,
  icon: Icon,
  color,
  label,
  value,
  sub,
  series,
  note,
}: {
  id: string
  icon: LucideIcon
  color: string
  label: string
  value: ReactNode
  sub?: ReactNode
  series?: Series
  note?: string
}) {
  return (
    <section aria-label={label} className="flex min-w-0 flex-col rounded-card border border-line bg-surface p-3.5">
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5 shrink-0" style={{ color }}>
          <Icon size={22} aria-hidden />
        </span>
        <div className="min-w-0">
          <div className="min-h-8 text-[13px] font-medium leading-4 text-fg" title={note ? `${label} — ${note}` : label}>
            {label}
          </div>
          <div className="tnum mt-0.5 text-[30px] font-bold leading-9 tracking-tight text-fg">{value}</div>
          <div className="tnum min-h-4 text-xs text-muted">{sub}</div>
        </div>
      </div>
      <div className="mt-1.5">{series ? <Sparkline series={series} color={color} id={id} /> : <div className="h-10" />}</div>
    </section>
  )
}
