import { Link } from 'react-router-dom'
import { useState } from 'react'
import { AlertTriangle, CheckCircle2, FileWarning, CalendarClock, Gauge, Wallet, ShieldOff, ShieldQuestion, HardDrive, MemoryStick, Siren, Network, Radar, ServerOff, ShieldAlert, Waypoints, Container } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useApp } from '../lib/context'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { useAuth } from '../lib/auth'
import { errorText } from '../lib/errors'
import { GhostButton, inputCls } from '../components/Modal'
import { DataTable, type Column } from '../components/DataTable'
import type { AlertsResponse } from '../lib/types'

type AlertRow = AlertsResponse['alerts'][number]
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'

const ICON = { agent_silent: ServerOff, panel_sync: Waypoints, sec_agent_silent: ShieldAlert, sec_tls: FileWarning, sec_port: Network, dns_check_failed: Radar, dns_change: Radar, user_expiry: CalendarClock, user_traffic: Gauge, bill_due: Wallet, awg_down: ShieldOff, awg_tools_old: ShieldQuestion, host_disk: HardDrive, host_disk_forecast: HardDrive, host_cpu: Gauge, host_mem: MemoryStick, host_flood: Siren, host_container: Container, host_container_down: Container } as const

// What can be put off: the resource and security alerts of machines, which are the owner's. The others (a panel that
// does not answer, a server that went silent) say something is down, and are not put off.
const SNOOZABLE = (kind: string) => kind.startsWith('host_') || kind.startsWith('sec_') || kind === 'awg_down'

/** Buttons on an open alert: put it off for a day or a week, or go and set this machine's threshold. */
function AlertActions({ a, onDone }: { a: { id: string; kind: string; subject?: string }; onDone: () => void }) {
  const auth = useAuth()
  const owner = auth.state.status === 'authed' && auth.state.me.account.is_owner
  const [err, setErr] = useState('')
  if (!owner || !SNOOZABLE(a.kind)) return null
  const machine = a.kind.startsWith('host_') ? (a.subject ?? '').split(':')[0] : ''
  async function snooze(hours: number) {
    setErr('')
    try {
      await api.post(`/api/v1/alerts/${a.id}/snooze`, { hours })
      onDone()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <GhostButton onClick={() => void snooze(24)}>{t('al.snooze.day')}</GhostButton>
      <GhostButton onClick={() => void snooze(168)}>{t('al.snooze.week')}</GhostButton>
      {machine && a.kind !== 'host_flood' && <Link to={`/servers/${machine}?view=alerts`} className="text-[13px] text-cyan underline-offset-2 hover:underline">{t('al.snooze.tune')}</Link>}
      {err && <span role="alert" className="text-[13px] text-red">{err}</span>}
    </div>
  )
}

/** A short "what to do" for the kinds that have one, so a red card explains itself. */
function TodoLine({ kind }: { kind: string }) {
  const key = `al.todo.${kind}` as MsgKey
  const text = t(key) // a kind with no text gives undefined and shows nothing
  if (!text) return null
  return <p className="mt-1 text-[13px] text-muted"><span className="font-medium text-fg/80">{t('al.todo')}:</span> {text}</p>
}

export default function Alerts() {
  const { filters, update } = useApp()
  const q = filters.panels.length ? `&panel_ids=${filters.panels.join(',')}` : ''
  const { data, error, reload } = useLoad((s) => api.get<AlertsResponse>(`/api/v1/alerts?state=all${q}`, s), [q], 30_000)
  // With a panel picked, the page shows that panel's alerts only, while the counter in the menu counts every open one
  // (servers, DNS and the like belong to no panel). Say so instead of letting the two disagree.
  const filtered = filters.panels.length > 0
  const everything = useLoad((s) => (filtered ? api.get<AlertsResponse>('/api/v1/alerts?state=open', s) : Promise.resolve(null)), [filtered], 30_000)
  const tz = filters.tz
  const open = data?.alerts.filter((a) => !a.resolved_at) ?? []
  const closed = data?.alerts.filter((a) => a.resolved_at) ?? []
  const hidden = filtered && everything.data ? Math.max(0, everything.data.open - open.length) : 0
  const [find, setFind] = useState('')
  const needle = find.trim().toLowerCase()
  const found = needle ? closed.filter((a) => `${a.label} ${a.detail} ${a.panel_name}`.toLowerCase().includes(needle)) : closed
  const columns: Column<AlertRow>[] = [
    { key: 'what', title: t('al.what'), sort: (a) => a.label, cell: (a) => <><span className="font-medium">{a.label}</span> <Chip tone="muted">{a.panel_name}</Chip></> },
    { key: 'detail', title: t('al.detail'), className: 'text-muted', cell: (a) => a.detail },
    { key: 'opened', title: t('al.opened'), sort: (a) => a.opened_at, descFirst: true, className: 'tnum whitespace-nowrap text-muted', cell: (a) => formatDateTime(a.opened_at, tz) },
    { key: 'closed', title: t('al.closed'), sort: (a) => a.resolved_at, descFirst: true, className: 'tnum whitespace-nowrap text-muted', cell: (a) => (a.resolved_at ? formatDateTime(a.resolved_at, tz) : '') },
  ]

  return (
    <div className="space-y-4">
      <PageHead title={t('al.title')} subtitle={t('al.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {hidden > 0 && (
        <div role="status" className="flex flex-wrap items-center gap-3 rounded-card border border-amber/40 bg-amber/10 px-4 py-3 text-[13px]">
          <span>{t('al.hidden', { n: hidden })}</span>
          <button type="button" className="underline hover:text-fg" onClick={() => update({ panels: [] })}>{t('al.hidden.show')}</button>
        </div>
      )}
      {data && (
        <>
          {open.length === 0 ? (
            <div role="status" className="flex items-center gap-3 rounded-card border border-green/30 bg-green/10 px-4 py-4 text-[14px]">
              <CheckCircle2 size={20} aria-hidden className="text-green" />
              <span>{t('al.allGood')}</span>
            </div>
          ) : (
            <div className="space-y-3" aria-label={t('al.open')}>
              {open.map((a) => {
                const Icon = ICON[a.kind as keyof typeof ICON] ?? AlertTriangle
                return (
                  <div key={a.id} role="alert" className="flex gap-3 rounded-card border border-amber/40 bg-amber/10 px-4 py-3">
                    <Icon size={20} aria-hidden className="mt-0.5 shrink-0 text-amber" />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="font-semibold">{a.label}</span>
                        <span className="text-xs text-muted">{a.panel_name}</span>
                      </div>
                      <p className="mt-0.5 text-[13px] text-fg/90">{a.detail}</p>
                      <TodoLine kind={a.kind} />
                      <AlertActions a={a} onDone={reload} />
                      <p className="tnum mt-1 text-xs text-muted">{t('al.since')} {formatDateTime(a.opened_at, tz)}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
          <Card title={t('al.history')} note={t('al.historyNote')}>
            {closed.length === 0 ? <p className="py-4 text-center text-[13px] text-muted">{t('al.noHistory')}</p> : (
              <>
                <input type="search" className={`${inputCls} mb-3 !h-8 max-w-xs !text-[13px]`} aria-label={t('al.find')} placeholder={t('al.find')} value={find} onChange={(e) => setFind(e.target.value)} />
                <DataTable caption={t('al.history')} columns={columns} rows={found} rowKey={(a) => a.id} empty={<p className="py-4 text-center text-[13px] text-muted">{t('al.nothing')}</p>} />
              </>
            )}
          </Card>
        </>
      )}
    </div>
  )
}
