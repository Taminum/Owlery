import { DataTable } from '../components/DataTable'
import { t } from '../i18n'
import { useApp } from '../lib/context'
import { formatDateTime, formatInt, formatPct } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { NodesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { formatRate } from '../lib/format'
import { CoverageLine, NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

const AGENT = {
  live: ['an.nodes.agentLive', 'green'],
  stale: ['an.nodes.agentStale', 'amber'],
  none: ['an.nodes.agentNone', 'muted'],
} as const

interface PulseNode { node_uuid: string; name: string; down_bps: number; up_bps: number }
interface PulsePanel { panel_id: string; nodes: PulseNode[] }

export default function Nodes() {
  const { filters } = useApp()
  const pulse = useLoad((s) => api.get<{ panels: PulsePanel[] }>('/api/v1/pulse/nodes', s), [], 15_000)
  const speed = new Map<string, PulseNode>()
  for (const p of pulse.data?.panels ?? []) for (const n of p.nodes) speed.set(`${p.panel_id}:${n.name}`, n)
  const { data, error } = useAnalytics<NodesResponse>('nodes', filters)
  const tz = filters.tz
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0

  return (
    <div className="space-y-4">
      <PageHead title={t('an.nodes.title')} subtitle={t('an.nodes.subtitle')} />
      {data && <CoverageLine meta={data.meta} tz={tz} />}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && data.rows.length === 0 && <NoDataPanel meta={data.meta} />}
      {data && data.rows.length > 0 && (
        <Card title={t('an.total', { n: formatInt(data.total_connections) })}>
          <DataTable caption={t('an.nodes.title')} rows={data.rows} rowKey={(r) => `${r.panel_id}:${r.node_id}`} columns={[
            { key: 'node', title: t('an.nodes.node'), sort: (r) => r.name, className: 'font-medium text-fg', cell: (r) => r.name },
            { key: 'panel', title: t('an.users.panel'), sort: (r) => r.panel_name, className: 'text-muted', cell: (r) => r.panel_name },
            { key: 'agent', title: t('an.nodes.agent'), sort: (r) => t((AGENT[r.agent] ?? AGENT.none)[0]), cell: (r) => { const [label, tone] = AGENT[r.agent] ?? AGENT.none; return <Chip tone={tone}>{t(label)}</Chip> } },
            { key: 'speed', title: t('pulse.speed'), hint: t('pulse.hint'), className: 'tnum whitespace-nowrap text-muted', cell: (r) => {
              const v = speed.get(`${r.panel_id}:${r.name}`)
              return v ? `↓ ${formatRate(v.down_bps)} · ↑ ${formatRate(v.up_bps)}` : t('pulse.none')
            } },
            { key: 'event', title: t('an.nodes.lastEvent'), sort: (r) => r.last_event_at, descFirst: true, className: 'whitespace-nowrap text-muted', cell: (r) => (r.last_event_at ? formatDateTime(r.last_event_at, tz) : '—') },
            { key: 'conn', title: t('an.connections'), sort: (r) => r.connections, descFirst: true, align: 'right', className: 'text-fg', cell: (r) => formatInt(r.connections) },
            { key: 'share', title: t('an.share'), className: 'w-[150px]', cell: (r) => <ShareBar share={r.share} max={max} /> },
            { key: 'users', title: t('an.users'), sort: (r) => r.users, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => r.users },
            { key: 'dests', title: t('an.users.dests'), sort: (r) => r.destinations, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => r.destinations },
            { key: 'udp', title: t('an.users.udp'), sort: (r) => r.udp_share, descFirst: true, align: 'right', className: 'text-muted', cell: (r) => formatPct(r.udp_share) },
          ]} />
        </Card>
      )}
    </div>
  )
}
