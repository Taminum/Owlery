import { Fragment, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'

// The pieces of a server's resource view, shared by the Resources page and the server card.
export interface Disk { m: string; fs?: string; t: number; u: number }
export interface Host {
  id: string; name: string; online: boolean; has_data: boolean; updated_at: string | null
  os: string; kernel: string; arch: string; cpu_model: string; cpus: number; mem_total: number; swap_total: number
  cpu: number | null; load1: number; load5: number; load15: number; mem_used: number; swap_used: number; uptime: number
  estab: number; syn_recv: number; rx_bps: number; tx_bps: number; rx_pps: number
  disks: Disk[]; procs: Proc[]; units: Unit[]; cpu_spark: (number | null)[]; mem_spark: number[]
}
export interface Proc { n: string; u?: string; l?: string; c: number; cpu: number; rss: number }
export interface Unit { u: string; l?: string; c: number; cpu: number; rss: number }
export interface Point { at: string; cpu: number | null; load1: number; mem_pct: number; disk_pct: number; rx_bps: number; tx_bps: number; rx_pps: number; tx_pps: number; estab: number; syn_recv: number }

const HOURS = [1, 6, 24, 168] as const

export function tone(p: number): 'green' | 'amber' | 'red' {
  return p >= 90 ? 'red' : p >= 70 ? 'amber' : 'green'
}
const BAR = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' } as const

export function Meter({ label, pct, detail }: { label: string; pct: number | null; detail: string }) {
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
export function Line({ title, points, max, format, color = 'var(--color-cyan)' }: { title: string; points: { x: number; y: number | null }[]; max: number | null; format: (v: number) => string; color?: string }) {
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

function unitText(u: string | undefined, label?: string): string {
  if (!u) return ''
  if (u.startsWith('docker:')) return label ? t('host.container.named', { name: label }) : t('host.container', { id: u.slice(7, 19) })
  return u.replace(/\.service$/, '')
}

/** Who uses the processor or the memory right now: programs grouped with their unit, the busiest first. */
/** Containers and services as a whole: everything that runs in each, added up. */
export function Units({ host }: { host: Host }) {
  const cores = Math.max(1, host.cpus)
  if (host.units.length === 0) return null
  const list = [...host.units].sort((a, b) => b.cpu - a.cpu || b.rss - a.rss)
  return (
    <section aria-label={t('host.units')} className="space-y-3">
      <h3 className="text-[13px] font-medium">{t('host.units')}</h3>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('host.units')}</caption>
          <thead><tr className="text-left text-xs text-muted">
            <th scope="col" className="px-2 py-1 font-medium">{t('host.units.name')}</th>
            <th scope="col" className="px-2 py-1 text-right font-medium">{t('host.cpu')}</th>
            <th scope="col" className="px-2 py-1 text-right font-medium">{t('host.mem')}</th>
            <th scope="col" className="px-2 py-1 text-right font-medium">{t('host.units.procs')}</th>
          </tr></thead>
          <tbody>
            {list.map((u) => (
              <tr key={u.u} className="border-t border-line/60">
                <td className="px-2 py-1.5 font-medium text-fg">{unitText(u.u, u.l)}</td>
                <td className="tnum px-2 py-1.5 text-right" title={t('host.units.cpu.title', { n: cores })}>{u.cpu.toFixed(u.cpu < 10 ? 1 : 0)}%</td>
                <td className="tnum px-2 py-1.5 text-right">{formatBytes(u.rss)}</td>
                <td className="tnum px-2 py-1.5 text-right text-muted">{u.c}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export function Procs({ host }: { host: Host }) {
  const cores = Math.max(1, host.cpus)
  const byCpu = [...host.procs].filter((p) => p.cpu > 0.05).sort((a, b) => b.cpu - a.cpu).slice(0, 8)
  const byMem = [...host.procs].sort((a, b) => b.rss - a.rss).slice(0, 8)
  const row = (p: Proc, value: string, share: number, key: string) => (
    <li key={key} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
      <span className="min-w-0 truncate"><span className="font-medium text-fg">{p.n}</span>{p.c > 1 && <span className="ml-1 text-xs text-muted">×{p.c}</span>}{p.u && <span className="ml-2 text-xs text-muted">{unitText(p.u, p.l)}</span>}</span>
      <span className="tnum text-right">{value}</span>
      <span className="col-span-2 h-1.5 overflow-hidden rounded-full bg-elevated"><span className="block h-full rounded-full bg-cyan" style={{ width: `${Math.max(2, Math.min(100, share))}%` }} /></span>
    </li>
  )
  return (
    <section aria-label={t('host.procs')} className="space-y-3">
      <h3 className="text-[13px] font-medium">{t('host.procs')}</h3>
      {host.procs.length === 0 ? <p className="text-[13px] text-muted">{t('host.procs.none')}</p> : (
        <div className="grid gap-5 sm:grid-cols-2">
          <div>
            <h4 className="mb-2 text-xs text-muted">{t('host.procs.cpu')}</h4>
            {byCpu.length === 0 ? <p className="text-[13px] text-muted">{t('host.procs.idle')}</p> : <ul className="space-y-2 text-[13px]">{byCpu.map((p) => row(p, `${p.cpu.toFixed(p.cpu < 10 ? 1 : 0)}%`, p.cpu / cores, `${p.n}:${p.u ?? ''}`))}</ul>}
            <p className="mt-2 text-[11px] text-muted">{t('host.procs.cpu.hint', { n: cores })}</p>
          </div>
          <div>
            <h4 className="mb-2 text-xs text-muted">{t('host.procs.mem')}</h4>
            <ul className="space-y-2 text-[13px]">{byMem.map((p) => row(p, formatBytes(p.rss), host.mem_total > 0 ? (p.rss * 100) / host.mem_total : 0, `${p.n}:${p.u ?? ''}`))}</ul>
          </div>
        </div>
      )}
    </section>
  )
}

export function HostDetail({ host }: { host: Host }) {
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
      <Units host={host} />
      <Procs host={host} />
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
          <Line title={t('host.rxp')} points={series((p) => p.rx_pps)} max={null} format={(v) => `${Math.round(v).toLocaleString('ru-RU')}/с`} />
          <Line title={t('host.estab')} points={series((p) => p.estab)} max={null} format={(v) => String(Math.round(v))} color="var(--color-blue)" />
          <Line title={t('host.syn')} points={series((p) => p.syn_recv)} max={null} format={(v) => String(Math.round(v))} color="var(--color-amber)" />
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

export function uptimeText(sec: number): string {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  return d > 0 ? t('host.up.days', { d, h }) : t('host.up.hours', { h, m: Math.floor((sec % 3600) / 60) })
}

export function Spark({ values }: { values: (number | null)[] }) {
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

