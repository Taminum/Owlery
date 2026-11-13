import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { useModulesOff } from '../lib/modules'
import type { Range } from '../lib/filters'
import { Card, Chip } from './ui'
import { DataTable } from './DataTable'
import { Drawer } from './Drawer'
import { Pair, PeerDetail, TONE, ago, type Peer } from './AwgPeer'
import { LimitLine } from './AwgLimits'

interface Instance { id: string; panel_id: string; host?: string; container: string; interface: string; report_fresh: boolean; peers: Peer[] }
interface Row { peer: Peer; panel: string; host: string; fresh: boolean }

/** The AmneziaWG server answers for 1 hour, 24 hours, 7 or 30 days; the page's own period is rounded to the nearest of them. */
const PERIOD: Record<Range, '1h' | '24h' | '7d' | '30d'> = { '15m': '1h', '1h': '1h', '24h': '24h', '7d': '7d', '30d': '30d', custom: '24h' }

/**
 * The AmneziaWG clients beside the Remnawave users: who they are, whether they are on now, and what they moved in the period.
 * Looking only; adding, revoking and limits stay on the AmneziaWG page.
 */
export function AwgClients({ range, tz }: { range: Range; tz: string }) {
  const off = useModulesOff()
  const period = PERIOD[range]
  const q = useLoad((s) => (off.has('awg') ? Promise.resolve(null) : api.get<{ instances: Instance[] }>(`/api/v1/awg?period=${period}`, s)), [off, period], 60_000)
  const [open, setOpen] = useState<Row | null>(null)
  const rows = useMemo<Row[]>(() => (q.data?.instances ?? []).flatMap((i) => i.peers.filter((p) => !p.gone).map((p) => ({ peer: p, panel: i.panel_id, host: i.host ?? i.container, fresh: i.report_fresh }))), [q.data])
  if (off.has('awg') || !q.data || rows.length === 0) return null
  return (
    <Card title={t('awgu.title')} note={t('awgu.note')} right={<Link to="/awg" className="text-[13px] text-cyan hover:underline">{t('awgu.manage')}</Link>}>
      <DataTable caption={t('awgu.title')} rows={rows} rowKey={(r) => r.peer.id} columns={[
        { key: 'client', title: t('awgu.client'), sort: (r) => r.peer.label, cell: (r) => (
          <>
            <button type="button" onClick={() => setOpen(r)} className="font-medium text-fg underline-offset-2 hover:text-cyan hover:underline">{r.peer.label}</button>
            {r.peer.tunnel_ip && <div className="font-mono text-xs text-muted">{r.peer.tunnel_ip}</div>}
            <LimitLine p={r.peer} tz={tz} />
          </>) },
        { key: 'host', title: t('awgu.host'), sort: (r) => r.host, className: 'text-muted', cell: (r) => r.host },
        { key: 'state', title: t('awgu.state'), sort: (r) => r.peer.state, cell: (r) => <Chip tone={TONE[r.peer.state]}>{t(`awg.state.${r.peer.state}` as MsgKey)}</Chip> },
        { key: 'last', title: t('awgu.last'), sort: (r) => r.peer.last_seen_at, descFirst: true, className: 'whitespace-nowrap text-muted', cell: (r) => (r.peer.last_seen_at ? (r.peer.last_seen_source === 'live' ? ago(r.peer.last_seen_at) : formatDateTime(r.peer.last_seen_at, tz)) : t('awg.never')) },
        { key: 'traffic', title: t('awgu.traffic', { p: t(`awg.p.${period}` as MsgKey) }), sort: (r) => r.peer.download_range + r.peer.upload_range, descFirst: true, align: 'right', className: 'tnum', cell: (r) => (r.fresh ? <Pair down={r.peer.download_range} up={r.peer.upload_range} /> : <span className="text-muted">—</span>) },
      ]} />
      {open && <Drawer title={open.peer.label} onClose={() => setOpen(null)}><PeerDetail peer={open.peer} range={period} panelId={open.panel} /></Drawer>}
    </Card>
  )
}
