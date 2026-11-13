import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { C } from '../lib/colors'
import { useApp } from '../lib/context'
import { formatAxisTime, formatBytes, formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { SitesResponse } from '../lib/types'
import { Chip } from './ui'

export interface Peer {
  id: string; label: string; tunnel_ip?: string; key_short: string; state: 'active' | 'recent' | 'stale' | 'never' | 'unknown'
  handshake_at: string | null; first_seen: string; gone: boolean
  download_total: number; upload_total: number; download_range: number; upload_range: number
  total_download: number; total_upload: number; total_since: string | null
  last_seen_at: string | null; last_seen_source?: 'live' | 'recorded' | 'panel'
  expires_at: string | null; traffic_limit_bytes: number | null; used_bytes: number; auto_revoked?: string
}

interface Series { bucket_seconds: number; from: string; to: string; points: { ts: string; download: number; upload: number }[] }

export const TONE: Record<Peer['state'], 'green' | 'cyan' | 'amber' | 'muted'> = { active: 'green', recent: 'cyan', stale: 'amber', never: 'muted', unknown: 'muted' }

export function ago(iso: string | null): string {
  if (!iso) return t('awg.never')
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 90) return t('awg.ago', { n: `${s} с` })
  if (s < 5400) return t('awg.ago', { n: `${Math.round(s / 60)} мин` })
  if (s < 172800) return t('awg.ago', { n: `${Math.round(s / 3600)} ч` })
  return t('awg.ago', { n: `${Math.round(s / 86400)} дн` })
}

/** Download and upload side by side, in the device's own point of view. */
export function Pair({ down, up }: { down: number | null; up: number | null }) {
  if (down == null && up == null) return <span className="text-muted">—</span>
  return <span className="whitespace-nowrap"><span title={t('awg.col.down')}>↓ {formatBytes(down ?? 0)}</span><span className="text-muted"> · </span><span title={t('awg.col.up')}>↑ {formatBytes(up ?? 0)}</span></span>
}

export function PeerDetail({ peer, range, panelId }: { peer: Peer; range: string; panelId?: string }) {
  const { filters } = useApp()
  const tz = filters.tz
  const q = useLoad((s) => api.get<Series>(`/api/v1/awg/peers/${peer.id}/series?range=${range}`, s), [peer.id, range])
  // Where the device went: the sites of its tunnel address, when the server reports flows.
  const sites = useLoad((s) => (panelId && peer.tunnel_ip
    ? api.get<SitesResponse>(`/api/v1/analytics/sites?subject=${encodeURIComponent(`awg:${panelId}|${peer.tunnel_ip}`)}&range=${range}&limit=10`, s)
    : Promise.resolve(null)), [panelId, peer.tunnel_ip, range])
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
      {panelId && peer.tunnel_ip && (
        <div>
          <h3 className="mb-2 text-[13px] font-medium text-fg">{t('awg.sites')}</h3>
          {sites.data && sites.data.rows.length === 0 && <p className="text-[13px] text-muted">{t('awg.sitesNone')}</p>}
          <ul className="space-y-1 text-[13px]">
            {sites.data?.rows.map((r) => (
              <li key={r.site} className="flex items-baseline justify-between gap-3">
                <span className="min-w-0 truncate" title={r.site}>{r.site}{r.service ? <span className="ml-2 text-xs text-cyan">{r.service}</span> : null}</span>
                <span className="tnum shrink-0 text-muted">{formatInt(r.connections)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

