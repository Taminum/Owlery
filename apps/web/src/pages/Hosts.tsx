import { Fragment, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { Drawer } from '../components/Drawer'
import { PageHead, TableSkeleton } from '../components/Analyzer'

interface Disk { m: string; fs?: string; t: number; u: number }
interface Host {
  id: string; name: string; online: boolean; has_data: boolean; updated_at: string | null
  os: string; kernel: string; arch: string; cpu_model: string; cpus: number; mem_total: number; swap_total: number
  cpu: number | null; load1: number; load5: number; load15: number; mem_used: number; swap_used: number; uptime: number
  disks: Disk[]; cpu_spark: (number | null)[]; mem_spark: number[]
}
interface Point { at: string; cpu: number | null; load1: number; mem_pct: number; disk_pct: number; rx_bps: number; tx_bps: number }

const HOURS = [1, 6, 24, 168] as const

function tone(p: number): 'green' | 'amber' | 'red' {
  return p >= 90 ? 'red' : p >= 70 ? 'amber' : 'green'
}
const BAR = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' } as const

function Meter({ label, pct, detail }: { label: string; pct: number | null; detail: string }) {
  const v = pct === null ? 0 : Math.max(0, Math.min(100, pct))
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between text-[12px]">
        <span className="text-muted">{label}</span>
        <span className="tnum">{pct === null ? '—' : `${Math.round(pct)}%`} <span className="text-muted">{detail}</span></span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-elevated" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)}>
        <div className={`h-full rounded-full ${BAR[tone(v)]}`} style={{ width: `${v}%` }} />
      </div>
    </div>
  )
}

/** A line over time with its own scale: no library, nothing to load. */
function Line({ title, points, max, format, color = 'var(--color-cyan)' }: { title: string; points: { x: number; y: number | null }[]; max: number | null; format: (v: number) => string; color?: string }) {
  const W = 320
  const H = 90
  const ys = points.map((p) => p.y).filter((v): v is number => v !== null)
  const top = max ?? Math.max(1, ...ys) * 1.15
  const xs = points.map((p) => p.x)
  const x0 = Math.min(...xs)
  const x1 = Math.max(...xs)
  const px = (x: number) => (x1 === x0 ? W / 2 : ((x - x0) / (x1 - x0)) * W)
  const py = (y: number) => H - (Math.min(y, top) / top) * H
  let d = ''
  let pen = false
  for (const p of points) {
    if (p.y === null) { pen = false; continue }
    d += `${pen ? 'L' : 'M'}${px(p.x).toFixed(1)},${py(p.y).toFixed(1)} `
    pen = true
  }
  const last = ys.length ? ys[ys.length - 1] : null
  return (
    <figure className="m-0">
      <figcaption className="mb-1 flex items-baseline justify-between text-[12px]"><span className="text-muted">{title}</span><span className="tnum">{last === null ? '—' : format(last)}</span></figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[90px] w-full rounded-control bg-elevated/50" role="img" aria-label={`${title}: ${last === null ? '—' : format(last)}`} preserveAspectRatio="none">
        <line x1="0" x2={W} y1={H / 2} y2={H / 2} stroke="var(--color-line)" strokeDasharray="3 4" />
        {d && <path d={d} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />}
      </svg>
      <div className="flex justify-between text-[10px] text-muted"><span>0</span><span>{format(top)}</span></div>
    </figure>
  )
}

function Detail({ host }: { host: Host }) {
  const [hours, setHours] = useState<(typeof HOURS)[number]>(24)
  const q = useLoad((s) => api.get<{ points: Point[] }>(`/api/v1/hosts/${host.id}/series?hours=${hours}`, s), [host.id, hours], 60_000)
  const pts = q.data?.points ?? []
  const series = (f: (p: Point) => number | null) => pts.map((p) => ({ x: new Date(p.at).getTime(), y: f(p) }))
  return (
    <div className="space-y-5">
      <div className="flex gap-2" role="group" aria-label={t('host.range')}>
        {HOURS.map((h) => (
          <button key={h} type="button" aria-pressed={hours === h} onClick={() => setHours(h)}
            className={`h-8 rounded-control border px-3 text-[12px] ${hours === h ? 'border-blue bg-blue/20 text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(`host.h.${h}` as MsgKey)}</button>
        ))}
      </div>
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {pts.length === 0 && !q.error && <p className="text-[13px] text-muted">{t('host.nodata')}</p>}
      {pts.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Line title={t('host.cpu')} points={series((p) => p.cpu)} max={100} format={(v) => `${Math.round(v)}%`} />
          <Line title={t('host.mem')} points={series((p) => p.mem_pct)} max={100} format={(v) => `${Math.round(v)}%`} color="var(--color-blue)" />
          <Line title={t('host.disk')} points={series((p) => p.disk_pct)} max={100} format={(v) => `${Math.round(v)}%`} color="var(--color-amber)" />
          <Line title={t('host.load')} points={series((p) => p.load1)} max={null} format={(v) => v.toFixed(2)} />
          <Line title={t('host.rx')} points={series((p) => p.rx_bps)} max={null} format={formatRate} />
          <Line title={t('host.tx')} points={series((p) => p.tx_bps)} max={null} format={formatRate} color="var(--color-blue)" />
        </div>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
        <dt className="text-muted">{t('host.os')}</dt><dd>{host.os || '—'}</dd>
        <dt className="text-muted">{t('host.kernel')}</dt><dd>{host.kernel || '—'} {host.arch && <span className="text-muted">({host.arch})</span>}</dd>
        <dt className="text-muted">{t('host.cpuModel')}</dt><dd>{host.cpu_model || '—'}{host.cpus > 0 && <span className="text-muted"> × {host.cpus}</span>}</dd>
        <dt className="text-muted">{t('host.memTotal')}</dt><dd>{formatBytes(host.mem_total)}{host.swap_total > 0 && <span className="text-muted"> + swap {formatBytes(host.swap_total)}</span>}</dd>
        {host.disks.map((d) => (<Fragment key={d.m}><dt className="text-muted">{d.m}</dt><dd>{formatBytes(d.u)} / {formatBytes(d.t)} <span className="text-muted">{d.fs}</span></dd></Fragment>))}
      </dl>
    </div>
  )
}

function uptimeText(sec: number): string {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  return d > 0 ? t('host.up.days', { d, h }) : t('host.up.hours', { h, m: Math.floor((sec % 3600) / 60) })
}

function Spark({ values }: { values: (number | null)[] }) {
  const ys = values.filter((v): v is number => v !== null)
  if (ys.length < 2) return <span className="text-xs text-muted">—</span>
  const W = 90
  const H = 22
  let d = ''
  values.forEach((v, i) => {
    if (v === null) return
    d += `${d ? 'L' : 'M'}${((i / (values.length - 1)) * W).toFixed(1)},${(H - (Math.min(v, 100) / 100) * H).toFixed(1)} `
  })
  return <svg viewBox={`0 0 ${W} ${H}`} className="h-[22px] w-[90px]" aria-hidden="true"><path d={d} fill="none" stroke="var(--color-cyan)" strokeWidth="1.4" /></svg>
}

export default function Hosts() {
  const q = useLoad((s) => api.get<{ hosts: Host[] }>('/api/v1/hosts', s), [], 15_000)
  const [open, setOpen] = useState<Host | null>(null)
  const hosts = q.data?.hosts ?? []
  return (
    <div className="space-y-4">
      <PageHead title={t('host.title')} subtitle={t('host.subtitle')} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && hosts.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('host.empty')}</p>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {hosts.map((h) => {
          const root = h.disks.find((d) => d.m === '/') ?? h.disks[0]
          const memPct = h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
          return (
            <Card key={h.id} title={h.name} note={[h.os, h.cpus > 0 ? `${h.cpus} ${t('host.cores')}` : '', h.mem_total > 0 ? formatBytes(h.mem_total) : ''].filter(Boolean).join(' · ') || undefined}
              right={<Chip tone={!h.has_data ? 'muted' : h.online ? 'green' : 'amber'}>{!h.has_data ? t('host.noAgent') : h.online ? t('host.online') : t('host.stale')}</Chip>}>
              {!h.has_data ? <p className="text-[13px] text-muted">{t('host.noAgent.hint')}</p> : (
                <div className="space-y-3">
                  <Meter label={t('host.cpu')} pct={h.cpu} detail={t('host.loadAvg', { n: h.load1.toFixed(2) })} />
                  <Meter label={t('host.mem')} pct={memPct} detail={`${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}`} />
                  <Meter label={root ? `${t('host.disk')} ${root.m}` : t('host.disk')} pct={root && root.t > 0 ? (root.u * 100) / root.t : null} detail={root ? `${formatBytes(root.u)} / ${formatBytes(root.t)}` : ''} />
                  <div className="flex items-center justify-between gap-3 pt-1 text-xs text-muted">
                    <span title={t('host.spark')}><Spark values={h.cpu_spark} /></span>
                    <span>{t('host.up')} {uptimeText(h.uptime)}</span>
                    <button type="button" className="underline hover:text-fg" onClick={() => setOpen(h)}>{t('host.more')}</button>
                  </div>
                </div>
              )}
            </Card>
          )
        })}
      </div>
      {open && <Drawer title={open.name} onClose={() => setOpen(null)}><Detail host={open} /></Drawer>}
    </div>
  )
}
