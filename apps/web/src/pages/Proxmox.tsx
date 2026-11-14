import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatDateTime } from '../lib/format'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import type { AlertsResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'

interface Guest {
  id: number; kind: 'lxc' | 'qemu'; name: string; status: string; cpu: number; mem: number; mem_max: number; disk: number; disk_max: number
  lan?: string; ts?: string; ts_up?: boolean; backup?: number; days_to_full?: number
}
interface Storage { name: string; used: number; total: number; backups?: boolean; active: boolean }
interface Host {
  vps_id: string; name: string; version?: string; updated_at: string; fresh: boolean; online: boolean; cpus?: number; cpu: number
  mem: number; mem_max: number; disk: number; disk_max: number; up: number; ts?: string; backup_ok?: boolean
  lxc: number; vms: number; running: number; guests: Guest[]; storages: Storage[]
}
interface Data { enabled: boolean; hosts: Host[] }
type Alerts = AlertsResponse['alerts']

const pct = (a: number, b: number) => (b > 0 ? Math.round((a * 100) / b) : 0)
const tone = (p: number) => (p >= 90 ? 'text-red' : p >= 75 ? 'text-amber' : '')

function Metric({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return <div className="rounded-control bg-elevated px-3 py-2.5"><div className="text-xs text-muted">{label}</div><div className="tnum text-xl font-semibold">{value}</div>{sub && <div className="text-[11px] text-muted">{sub}</div>}</div>
}

function backupCell(g: Guest) {
  if (!g.backup) return <span className="text-xs text-muted">{t('pve.backup.none')}</span>
  const age = Math.floor((Date.now() / 1000 - g.backup) / 86400)
  if (age >= 2) return <Chip tone="red">{t('pve.backup.days', { n: age })}</Chip>
  return <span className="text-xs text-muted">{age < 1 ? t('pve.backup.today') : t('pve.backup.days', { n: age })}</span>
}

function GuestRow({ g, open, onToggle }: { g: Guest; open: boolean; onToggle: () => void }) {
  const running = g.status === 'running'
  const dp = pct(g.disk, g.disk_max)
  return (
    <li className="py-2.5 text-[13px]">
      <button type="button" onClick={onToggle} aria-expanded={open} className="grid w-full grid-cols-[minmax(0,1.5fr)_auto] items-center gap-3 text-left sm:grid-cols-[minmax(0,1.5fr)_56px_52px_56px_52px_100px]">
        <span className="min-w-0">
          <span className="font-medium text-fg">{g.name}</span> <span className="text-xs text-muted">{g.id}</span>
          {!running && <span className="ml-2"><Chip tone="amber">{t('pve.stopped')}</Chip></span>}
          <span className="block truncate text-xs text-muted">{[g.lan, g.ts && `ts ${g.ts}`].filter(Boolean).join(' · ') || '—'}</span>
        </span>
        <span className="hidden sm:block"><Chip tone="cyan">{g.kind === 'lxc' ? 'LXC' : 'VM'}</Chip></span>
        <span className="tnum hidden sm:block">{running ? `${Math.round(g.cpu)}%` : '—'}</span>
        <span className="tnum hidden sm:block">{running ? `${pct(g.mem, g.mem_max)}%` : '—'}</span>
        <span className={`tnum ${tone(dp)}`}>{g.disk_max > 0 ? `${dp}%` : '—'}</span>
        <span className="hidden sm:block">{backupCell(g)}</span>
      </button>
      {open && (
        <div className="mt-2 grid gap-3 rounded-control bg-elevated px-3 py-2.5 text-xs sm:grid-cols-3">
          <div><div className="text-muted">{t('pve.lan')}</div><div className="tnum">{g.lan || '—'}</div></div>
          <div>
            <div className="text-muted">{t('pve.ts')}</div>
            <div className="tnum">{g.ts || '—'}{g.ts_up != null && <span className={g.ts_up ? 'ml-2 text-green' : 'ml-2 text-amber'}>{g.ts_up ? t('pve.ts.up') : t('pve.ts.down')}</span>}</div>
          </div>
          <div>
            <div className="text-muted">{t('pve.disk')}</div>
            <div className="tnum">{g.disk_max > 0 ? `${formatBytes(g.disk)} / ${formatBytes(g.disk_max)}` : '—'}</div>
            {g.days_to_full != null && g.days_to_full <= 60 && <div className="text-amber">{t('pve.full', { n: Math.max(1, Math.round(g.days_to_full)) })}</div>}
          </div>
        </div>
      )}
    </li>
  )
}

function HostCard({ h, tz, trouble }: { h: Host; tz: string; trouble: Alerts }) {
  const [open, setOpen] = useState<number | null>(null)
  const live = h.online && h.fresh
  return (
    <Card title={h.name} note={[h.version && `Proxmox ${h.version}`, h.ts && `Tailscale ${h.ts}`].filter(Boolean).join(' · ')} right={
      live ? <Chip tone="green">{t('pve.online')} · {Math.floor(h.up / 86400)} д</Chip> : <Chip tone="red">{h.online ? t('pve.stale') : t('pve.offline')} · {formatDateTime(h.updated_at, tz)}</Chip>
    }>
      <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label={t('pve.cpu')} value={`${Math.round(h.cpu)}%`} sub={h.cpus ? t('pve.cores', { n: h.cpus }) : undefined} />
        <Metric label={t('pve.mem')} value={`${pct(h.mem, h.mem_max)}%`} sub={`${formatBytes(h.mem)} / ${formatBytes(h.mem_max)}`} />
        <Metric label={t('pve.nodeDisk')} value={`${pct(h.disk, h.disk_max)}%`} sub={`${formatBytes(h.disk)} / ${formatBytes(h.disk_max)}`} />
        <Metric label={t('pve.guests')} value={t('pve.guests.of', { n: h.running, all: h.guests.length })} sub={t('pve.guests.sub', { lxc: h.lxc, vms: h.vms })} />
      </div>
      <ul className="divide-y divide-line/60">
        {h.guests.map((g) => <GuestRow key={g.id} g={g} open={open === g.id} onToggle={() => setOpen(open === g.id ? null : g.id)} />)}
      </ul>
      {h.storages.length > 0 && (
        <div className="mt-4">
          <div className="mb-1 text-xs text-muted">{t('pve.storage')}</div>
          <ul className="text-[13px]">
            {h.storages.map((s) => (
              <li key={s.name} className="flex items-center justify-between gap-3 py-1">
                <span>{s.name}{s.backups && <span className="ml-2 text-xs text-muted">{t('pve.storage.backups')}</span>}</span>
                <span className={`tnum ${tone(pct(s.used, s.total))}`}>{s.active ? `${pct(s.used, s.total)}% · ${formatBytes(s.used)} / ${formatBytes(s.total)}` : '—'}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="mt-4">
        <div className="mb-1 text-xs text-muted">{t('pve.trouble')}</div>
        {h.backup_ok === false && <p className="text-[13px] text-red">{t('pve.job.bad')}</p>}
        {trouble.length === 0 && h.backup_ok !== false ? <p className="text-[13px] text-muted">{t('pve.none')}</p> : (
          <ul className="space-y-1 text-[13px]">{trouble.map((a) => <li key={a.id}><span className="font-medium">{a.label}</span> <span className="text-muted">{a.detail}</span></li>)}</ul>
        )}
      </div>
    </Card>
  )
}

export default function ProxmoxPage() {
  const tz = useApp().filters.tz
  const { data, error } = useLoad((s) => api.get<Data>('/api/v1/home/proxmox', s), [], 30_000)
  const alerts = useLoad((s) => api.get<AlertsResponse>('/api/v1/alerts', s), [], 60_000)
  const trouble = (alerts.data?.alerts ?? []).filter((a) => a.kind.startsWith('pve_') && !a.resolved_at)
  return (
    <div className="space-y-4">
      <PageHead title={t('pve.title')} subtitle={t('pve.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && !data.enabled && <Card title={t('pve.title')}><p className="text-[13px] text-muted">{t('pve.off')}</p></Card>}
      {data?.enabled && data.hosts.length === 0 && (
        <Card title={t('pve.setup.title')} note={t('pve.setup.text')}><pre className="overflow-x-auto rounded-control bg-elevated p-3 text-xs">{t('pve.setup.cmd')}</pre></Card>
      )}
      {data?.enabled && data.hosts.map((h) => <HostCard key={h.vps_id} h={h} tz={tz} trouble={trouble.filter((a) => (a.subject ?? '').startsWith(h.vps_id))} />)}
    </div>
  )
}
