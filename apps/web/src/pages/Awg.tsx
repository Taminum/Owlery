import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { C } from '../lib/colors'
import { useApp } from '../lib/context'
import { formatAxisTime, formatBytes, formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { useAuth } from '../lib/auth'
import { Card, Chip } from '../components/ui'
import { PageHead } from '../components/Analyzer'
import { Drawer } from '../components/Drawer'
import { controlCls } from '../components/Popover'
import { AddDevice, RenameDevice, RevokeDevice } from '../components/AwgDevice'
import { GhostButton } from '../components/Modal'

interface Peer {
  id: string; label: string; tunnel_ip?: string; key_short: string; state: 'active' | 'recent' | 'stale' | 'never' | 'unknown'
  handshake_at: string | null; first_seen: string; gone: boolean
  download_total: number; upload_total: number; download_range: number; upload_range: number
  total_download: number; total_upload: number; total_since: string | null
  last_seen_at: string | null; last_seen_source?: 'live' | 'recorded' | 'panel'
}
interface Instance {
  id: string; container: string; interface: string; port?: number; variant?: string; mode: string
  last_report: string; report_fresh: boolean; counters_since: string | null; peers: Peer[]
}
interface AwgResponse { instances: Instance[]; period: string }
interface Series { bucket_seconds: number; from: string; to: string; points: { ts: string; download: number; upload: number }[] }

const PERIODS = ['1h', '24h', '7d', '30d'] as const
const TONE: Record<Peer['state'], 'green' | 'cyan' | 'amber' | 'muted'> = { active: 'green', recent: 'cyan', stale: 'amber', never: 'muted', unknown: 'muted' }

function ago(iso: string | null): string {
  if (!iso) return t('awg.never')
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 90) return t('awg.ago', { n: `${s} с` })
  if (s < 5400) return t('awg.ago', { n: `${Math.round(s / 60)} мин` })
  if (s < 172800) return t('awg.ago', { n: `${Math.round(s / 3600)} ч` })
  return t('awg.ago', { n: `${Math.round(s / 86400)} дн` })
}

/** Download and upload side by side, in the device's own point of view. */
function Pair({ down, up }: { down: number | null; up: number | null }) {
  if (down == null && up == null) return <span className="text-muted">—</span>
  return <span className="whitespace-nowrap"><span title={t('awg.col.down')}>↓ {formatBytes(down ?? 0)}</span><span className="text-muted"> · </span><span title={t('awg.col.up')}>↑ {formatBytes(up ?? 0)}</span></span>
}

function PeerDetail({ peer, range }: { peer: Peer; range: string }) {
  const { filters } = useApp()
  const tz = filters.tz
  const q = useLoad((s) => api.get<Series>(`/api/v1/awg/peers/${peer.id}/series?range=${range}`, s), [peer.id, range])
  const pts = (q.data?.points ?? []).map((p) => ({ ts: Math.floor(new Date(p.ts).getTime() / 1000), download: p.download, upload: p.upload }))
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <Chip tone={TONE[peer.state]}>{t(`awg.state.${peer.state}` as MsgKey)}</Chip>
        {peer.tunnel_ip && <span className="font-mono text-xs text-muted">{peer.tunnel_ip}</span>}
        <span className="font-mono text-xs text-muted">{peer.key_short}</span>
      </div>
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {q.data && pts.length === 0 && <p className="text-[13px] text-muted">{t('awg.noPoints')}</p>}
      {pts.length > 0 && (
        <div className="h-[220px]" role="img" aria-label={t('awg.detail')}>
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <BarChart data={pts} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
              <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
              <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => formatAxisTime(v, tz, q.data?.bucket_seconds ?? 3600)} />
              <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={56} tickFormatter={(v: number) => formatBytes(v)} />
              <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v), tz)} formatter={(v) => formatBytes(Number(v))} />
              <Bar dataKey="download" name={t('awg.col.down')} stackId="a" fill={C.blue} isAnimationActive={false} />
              <Bar dataKey="upload" name={t('awg.col.up')} stackId="a" fill={C.cyan} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      <p className="text-xs leading-5 text-muted">{t('awg.direction')}</p>
    </div>
  )
}

export default function Awg() {
  const { filters } = useApp()
  const tz = filters.tz
  const [period, setPeriod] = useState<(typeof PERIODS)[number]>('24h')
  const [open, setOpen] = useState<Peer | null>(null)
  const [adding, setAdding] = useState<Instance | null>(null)
  const [revoking, setRevoking] = useState<Peer | null>(null)
  const [renaming, setRenaming] = useState<Peer | null>(null)
  const q = useLoad((s) => api.get<AwgResponse>(`/api/v1/awg?period=${period}`, s), [period], 30_000)
  const { state: auth } = useAuth()
  const canForget = auth.status === 'authed' && auth.me.account.is_owner
  async function forget(p: Peer) {
    try {
      await api.del(`/api/v1/awg/peers/${p.id}`)
    } catch {
      /* the list below is reloaded either way: a failed removal shows up as the row still being there */
    }
    q.reload()
  }
  const day = (iso: string | null) => (iso ? formatDateTime(iso, tz) : '—')

  function lastSeen(p: Peer) {
    if (!p.last_seen_at) return <span className="text-muted">{t('awg.never')}</span>
    return <span>{p.last_seen_source === 'live' ? ago(p.last_seen_at) : day(p.last_seen_at)}</span>
  }

  return (
    <div className="space-y-5">
      <PageHead title={t('awg.title')} subtitle={t('awg.subtitle')}
        right={
          <label className="flex items-center gap-2 text-[13px] text-muted">
            {t('awg.period')}
            <select className={controlCls} value={period} onChange={(e) => setPeriod(e.target.value as (typeof PERIODS)[number])}>
              {PERIODS.map((p) => <option key={p} value={p}>{t(`awg.p.${p}` as MsgKey)}</option>)}
            </select>
          </label>
        } />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {q.data && q.data.instances.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('awg.empty')}</p>}
      {q.data?.instances.map((in_) => (
        <Card key={in_.id}
          right={canForget && in_.mode === 'managed' ? <GhostButton onClick={() => setAdding(in_)}>{t('awg.add')}</GhostButton> : undefined}
          title={`${in_.container} · ${in_.interface}`}
          note={[in_.port ? t('awg.port', { n: in_.port }) : '', in_.variant ? t('awg.variant', { v: in_.variant }) : '', t(`awg.mode.${in_.mode}` as MsgKey), t('awg.report', { when: ago(in_.last_report) })].filter(Boolean).join(' · ')}>
          {!in_.report_fresh && <p role="status" className="mb-3 text-[13px] text-amber">{t('awg.noReport')}</p>}
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{`${in_.container} ${in_.interface}`}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.peer')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.ip')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.state')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.lastSeen')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.range')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.total')}</th>
                {canForget && <th scope="col" className="px-2 py-2"><span className="sr-only">{t('awg.actions')}</span></th>}
              </tr></thead>
              <tbody>
                {in_.peers.map((p) => (
                  <tr key={p.id} className={`border-t border-line/60 ${p.gone ? 'opacity-60' : ''}`}>
                    <td className="px-2 py-2">
                      <button type="button" onClick={() => setOpen(p)} className="font-medium underline-offset-2 hover:text-cyan hover:underline">{p.label}</button>
                      {p.gone && <span className="ml-2 text-xs text-muted">{t('awg.gone')}</span>}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-muted">{p.tunnel_ip ?? '—'}</td>
                    <td className="px-2 py-2"><Chip tone={TONE[p.state]}>{t(`awg.state.${p.state}` as MsgKey)}</Chip></td>
                    <td className="px-2 py-2 text-muted">{lastSeen(p)}</td>
                    <td className="tnum px-2 py-2">{in_.report_fresh ? <Pair down={p.download_range} up={p.upload_range} /> : <span className="text-muted">—</span>}</td>
                    <td className="tnum px-2 py-2" title={p.total_since ? t('awg.sinceTip', { when: day(p.total_since) }) : undefined}><Pair down={p.total_download} up={p.total_upload} /></td>
                    {canForget && (
                      <td className="whitespace-nowrap px-2 py-2 text-right">
                        {!p.gone && <button type="button" onClick={() => setRenaming(p)} className="mr-3 text-xs text-muted underline-offset-2 hover:text-cyan hover:underline" aria-label={`${t('awg.rename')}: ${p.label}`}>{t('awg.rename')}</button>}
                        {!p.gone && in_.mode === 'managed' && <button type="button" onClick={() => setRevoking(p)} className="text-xs text-muted underline-offset-2 hover:text-red hover:underline" aria-label={`${t('awg.revoke')}: ${p.label}`}>{t('awg.revoke')}</button>}
                        {p.gone && <button type="button" onClick={() => void forget(p)} className="text-xs text-muted underline-offset-2 hover:text-red hover:underline" aria-label={`${t('awg.forget')}: ${p.label}`}>{t('awg.forget')}</button>}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 space-y-1 text-xs leading-5 text-muted">
            <p>{in_.counters_since ? t('awg.since.server', { when: day(in_.counters_since) }) : t('awg.since.serverUnknown')}</p>
            <p>{t('awg.since.total')}</p>
          </div>
        </Card>
      ))}
      {q.data && q.data.instances.length > 0 && (
        <div className="space-y-1 text-xs leading-5 text-muted"><p>{t('awg.state.hint')}</p><p>{t('awg.direction')}</p></div>
      )}
      {adding && <AddDevice instanceId={adding.id} container={adding.container} onClose={() => setAdding(null)} onDone={() => q.reload()} />}
      {revoking && <RevokeDevice peerId={revoking.id} label={revoking.label} onClose={() => setRevoking(null)} onDone={() => q.reload()} />}
      {renaming && <RenameDevice peerId={renaming.id} label={renaming.label} onClose={() => setRenaming(null)} onDone={() => q.reload()} />}
      {open && <Drawer title={open.label} onClose={() => setOpen(null)}><PeerDetail peer={open} range={period} /></Drawer>}
    </div>
  )
}
