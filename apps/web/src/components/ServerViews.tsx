import { useState } from 'react'
import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { VPSList, VPSSummary } from '../lib/types'
import { Chip } from './ui'
import { DataTable, type Column } from './DataTable'
import { tone, type Host } from './HostView'
import { StatusChip, type Server } from './ServerParts'

const BAR = { green: 'bg-green', amber: 'bg-amber', red: 'bg-red' } as const

/** A bar and a number, small enough to sit in a table cell. */
function MiniMeter({ pct, label }: { pct: number | null; label: string }) {
  if (pct === null) return <span className="text-muted">—</span>
  const v = Math.max(0, Math.min(100, pct))
  return (
    <span className="inline-flex w-[120px] items-center gap-2">
      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-elevated" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v)}>
        <span className={`block h-full rounded-full ${BAR[tone(v)]}`} style={{ width: `${v}%` }} />
      </span>
      <span className="tnum w-9 text-right text-xs">{Math.round(v)}%</span>
    </span>
  )
}

/** The fullest disk of a machine: what a person looking for "where is the space going" wants to see. */
export function fullestDisk(h: Pick<Host, 'disks'>): { pct: number; mount: string } | null {
  let best: { pct: number; mount: string } | null = null
  for (const d of h.disks) {
    if (d.t <= 0) continue
    const pct = (d.u * 100) / d.t
    if (!best || pct > best.pct) best = { pct, mount: d.m }
  }
  return best
}

const memPct = (h: Host) => (h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null)
const uptimeShort = (sec: number) => {
  const d = Math.floor(sec / 86400)
  const hrs = Math.floor((sec % 86400) / 3600)
  return d > 0 ? t('srv.up.days', { d, h: hrs }) : t('srv.up.hours', { h: hrs, m: Math.floor((sec % 3600) / 60) })
}

/** The machines by what they use: one row each, sortable, so the fullest disk is one click away. */
export function LoadTable({ list }: { list: Server[] }) {
  const has = (s: Server) => !!s.host?.has_data
  const columns: Column<Server>[] = [
    { key: 'name', title: t('srv.col.machine'), sort: (s) => s.name, cell: (s) => <Link to={`/servers/${s.id}?view=resources`} className="font-medium text-fg hover:text-cyan hover:underline">{s.name}</Link> },
    { key: 'status', title: t('srv.col.state'), sort: (s) => ({ bad: 0, warn: 1, unknown: 2, ok: 3 })[s.status], cell: (s) => <StatusChip s={s} /> },
    { key: 'cpu', title: t('host.cpu'), sort: (s) => (has(s) ? s.host!.cpu : null), descFirst: true, cell: (s) => (has(s) ? <MiniMeter pct={s.host!.cpu} label={`${t('host.cpu')}: ${s.name}`} /> : <span className="text-muted">—</span>) },
    { key: 'mem', title: t('host.mem'), sort: (s) => (has(s) ? memPct(s.host!) : null), descFirst: true, cell: (s) => (has(s) ? <MiniMeter pct={memPct(s.host!)} label={`${t('host.mem')}: ${s.name}`} /> : <span className="text-muted">—</span>) },
    { key: 'disk', title: t('host.disk'), sort: (s) => (has(s) ? fullestDisk(s.host!)?.pct ?? null : null), descFirst: true, cell: (s) => {
      const d = has(s) ? fullestDisk(s.host!) : null
      return d ? <span className="inline-flex items-center gap-1.5"><MiniMeter pct={d.pct} label={`${t('host.disk')} ${d.mount}: ${s.name}`} /><span className="text-xs text-muted">{d.mount}</span></span> : <span className="text-muted">—</span>
    } },
    { key: 'net', title: t('srv.col.net'), sort: (s) => (has(s) ? s.host!.rx_bps + s.host!.tx_bps : null), descFirst: true, align: 'right', className: 'whitespace-nowrap text-muted', cell: (s) => (has(s) ? `↓ ${formatRate(s.host!.rx_bps)} · ↑ ${formatRate(s.host!.tx_bps)}` : '—') },
    { key: 'up', title: t('srv.col.uptime'), sort: (s) => (has(s) ? s.host!.uptime : null), descFirst: true, align: 'right', className: 'whitespace-nowrap text-muted', cell: (s) => (has(s) ? uptimeShort(s.host!.uptime) : '—') },
  ]
  return <DataTable caption={t('srv.view.load')} rows={list} rowKey={(s) => s.id} columns={columns} initialSort={{ key: 'disk', desc: true }} pageSize={200} />
}

type Summary = Pick<VPSSummary, 'agent' | 'checks' | 'win'> & { fail2ban: { state: string; banned: number; total_banned: number } }

const isWindows = (s: Server) => /windows/i.test(s.os || s.host?.os || '')

/** What guards a machine, in a few words: the blocker on Windows, Fail2ban elsewhere, or the reason there is nothing to say. */
function guard(s: Server, sum: Summary | undefined): string {
  if (isWindows(s)) return sum?.win ? `${t('srv.guard.rdp')} · ${t('srv.guard.rdpFailed', { n: sum.win.rdp_failed })}` : t('srv.guard.rdp')
  if (!sum || sum.agent === 'none') return t('srv.guard.noAgent')
  const f = sum.fail2ban
  return f.state === 'ok' || f.state === 'stale' ? t('sec.fail2ban') : t(`sec.state.${f.state}` as MsgKey)
}

/** The machines by their protection. The numbers are Fail2ban's; what protects a Windows machine is named, its counts follow. */
export function ProtectTable({ list }: { list: Server[] }) {
  const sec = useLoad((s) => api.get<VPSList>('/api/v1/security/vps', s), [], 30_000)
  const byId = new Map<string, Summary>()
  for (const v of sec.data?.items ?? []) if (v.summary) byId.set(v.id, v.summary as Summary)
  const f2b = (s: Server) => {
    const x = byId.get(s.id)?.fail2ban
    return x && (x.state === 'ok' || x.state === 'stale') ? x : null
  }
  // Blocks now: Fail2ban's bans on Linux, the RDP blocker's addresses on Windows.
  const blocked = (s: Server) => (isWindows(s) ? byId.get(s.id)?.win?.blocked_now ?? null : f2b(s)?.banned ?? null)
  const [now] = useState(() => Date.now())
  const daysLeft = (iso: string | null | undefined) => (iso ? Math.floor((new Date(iso).getTime() - now) / 86_400_000) : null)
  const columns: Column<Server>[] = [
    { key: 'name', title: t('srv.col.machine'), sort: (s) => s.name, cell: (s) => <Link to={`/servers/${s.id}?view=security`} className="font-medium text-fg hover:text-cyan hover:underline">{s.name}</Link> },
    { key: 'agent', title: t('srv.col.agent'), sort: (s) => byId.get(s.id)?.agent ?? 'none', cell: (s) => {
      const a = byId.get(s.id)?.agent ?? 'none'
      return <Chip tone={a === 'online' ? 'green' : a === 'offline' ? 'amber' : 'muted'}>{t(`sec.card.agent.${a}` as MsgKey)}</Chip>
    } },
    { key: 'now', title: t('srv.col.bannedNow'), sort: (s) => blocked(s), descFirst: true, align: 'right', cell: (s) => blocked(s) ?? '—' },
    { key: 'total', title: t('srv.col.bannedTotal'), sort: (s) => f2b(s)?.total_banned ?? null, descFirst: true, align: 'right', className: 'text-muted', cell: (s) => f2b(s)?.total_banned ?? '—' },
    { key: 'ports', title: t('srv.col.ports'), sort: (s) => { const c = byId.get(s.id)?.checks; return c && c.ports_total > 0 ? c.ports_unexpected * 1000 + c.ports_down * 100 + c.ports_total : null }, descFirst: true, cell: (s) => {
      const c = byId.get(s.id)?.checks
      if (!c || c.ports_total === 0) return <span className="text-muted">—</span>
      return <span className="inline-flex items-center gap-1.5"><span className="tnum">{c.ports_total}</span>
        {c.ports_unexpected > 0 && <Chip tone="red">{t('srv.ports.unexpected', { n: c.ports_unexpected })}</Chip>}
        {c.ports_down > 0 && <Chip tone="amber">{t('srv.ports.down', { n: c.ports_down })}</Chip>}</span>
    } },
    { key: 'tls', title: t('srv.col.tls'), sort: (s) => { const c = byId.get(s.id)?.checks; return c && c.tls_total > 0 ? daysLeft(c.tls_nearest_end) ?? 99999 : null }, cell: (s) => {
      const c = byId.get(s.id)?.checks
      if (!c || c.tls_total === 0) return <span className="text-muted">—</span>
      const d = daysLeft(c.tls_nearest_end)
      return <span className="inline-flex items-center gap-1.5">{d !== null && <span className="tnum">{t('srv.tls.days', { d })}</span>}{c.tls_problems > 0 && <Chip tone="red">{t('srv.tls.problems', { n: c.tls_problems })}</Chip>}</span>
    } },
    { key: 'guard', title: t('srv.col.guard'), sort: (s) => guard(s, byId.get(s.id)), className: 'text-muted', cell: (s) => guard(s, byId.get(s.id)) },
  ]
  return (
    <>
      {sec.error && <p role="alert" className="mb-2 text-[13px] text-red">{sec.error}</p>}
      <DataTable caption={t('srv.view.protect')} rows={list} rowKey={(s) => s.id} columns={columns} pageSize={200} />
    </>
  )
}

