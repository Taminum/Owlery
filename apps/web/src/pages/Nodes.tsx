import { t } from '../i18n'
import { useApp } from '../lib/context'
import { formatDateTime, formatInt, formatPct } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { NodesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { CoverageLine, NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'

const AGENT = {
  live: ['an.nodes.agentLive', 'green'],
  stale: ['an.nodes.agentStale', 'amber'],
  none: ['an.nodes.agentNone', 'muted'],
} as const

export default function Nodes() {
  const { filters } = useApp()
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
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('an.nodes.title')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('an.nodes.node')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.users.panel')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.nodes.agent')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.nodes.lastEvent')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users.dests')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users.udp')}</th>
              </tr></thead>
              <tbody>
                {data.rows.map((r) => {
                  const [label, tone] = AGENT[r.agent] ?? AGENT.none
                  return (
                    <tr key={`${r.panel_id}:${r.node_id}`} className="border-t border-line/60">
                      <td className="px-2 py-2 font-medium text-fg">{r.name}</td>
                      <td className="px-2 py-2 text-muted">{r.panel_name}</td>
                      <td className="px-2 py-2"><Chip tone={tone}>{t(label)}</Chip></td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{r.last_event_at ? formatDateTime(r.last_event_at, tz) : '—'}</td>
                      <td className="tnum px-2 py-2 text-right text-fg">{formatInt(r.connections)}</td>
                      <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.users}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.destinations}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{formatPct(r.udp_share)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
