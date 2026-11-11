import { Link } from 'react-router-dom'
import { useState } from 'react'
import { ChevronRight, Globe2, Layers, Network, Tags } from 'lucide-react'
import { t } from '../i18n'
import { useApp } from '../lib/context'
import { formatBytes, formatDateTime, formatInt } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import type { DestResponse, DestRow, NetworksResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { CoverageLine, NoDataPanel, ShareBar, TableSkeleton, confidenceLabel } from '../components/Analyzer'
import { hasAwg } from '../components/SourceMarks'
import { controlCls } from '../components/Popover'

const PAGE = 50

const KIND_ICON: Record<string, typeof Globe2> = { ip: Network, service: Layers, category: Tags }

/** Filters inherited down the hierarchy, so every level uses the same classification. */
interface Ctx { service?: string; category?: string }

function childQuery(r: DestRow, ctx: Ctx): { params: Record<string, string>; next: Ctx } | null {
  switch (r.kind) {
    case 'category': return { params: { group_by: 'service', category: r.key }, next: { ...ctx, category: r.key } }
    case 'service': return { params: { group_by: 'site', service: r.key, ...(ctx.category ? { category: ctx.category } : {}) }, next: { ...ctx, service: r.key } }
    case 'site': return { params: { group_by: 'host', site: r.key, ...(ctx.service ? { service: ctx.service } : {}), ...(ctx.category ? { category: ctx.category } : {}) }, next: ctx }
    default: return null
  }
}

/** One row of the tree. Category, service and site rows open to show what is inside them. */
function Node({ r, max, tz, depth, subject, ctx }: { r: DestRow; max: number; tz: string; depth: number; subject: string; ctx: Ctx }) {
  const [open, setOpen] = useState(false)
  const child = childQuery(r, ctx)
  const K = KIND_ICON[r.kind] ?? Globe2
  return (
    <>
      <tr className={`border-t border-line/60 ${depth ? 'bg-elevated/40' : ''}`}>
        <td className="max-w-[340px] px-2 py-2" style={{ paddingLeft: 8 + depth * 22 }}>
          <div className="flex items-center gap-2">
            {child ? (
              <button type="button" aria-expanded={open} aria-label={`${t('an.expand')}: ${r.key}`} onClick={() => setOpen((o) => !o)} className="grid h-6 w-6 shrink-0 place-items-center rounded text-muted hover:text-fg">
                <ChevronRight size={15} aria-hidden className={`transition-transform ${open ? 'rotate-90' : ''}`} />
              </button>
            ) : <span className="w-6 shrink-0" />}
            <K size={14} className="shrink-0 text-muted" aria-label={t(`an.kind.${r.kind}` as 'an.kind.domain')} />
            <span className="min-w-0 truncate font-medium text-fg" title={r.key}>{r.key}</span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 pl-[54px]">
            {(r.kind === 'domain' || r.kind === 'ip' || r.kind === 'site') && <Link to={`/intel?target=${encodeURIComponent(r.key)}`} className="shrink-0 text-xs text-muted underline-offset-2 hover:text-cyan hover:underline" aria-label={`${t('intel.investigate')}: ${r.key}`}>{t('intel.investigate')}</Link>}
            {r.service && r.kind !== 'service' && r.kind !== 'category' && <Chip tone="cyan">{r.service}{r.confidence && r.confidence !== 'high' ? ` · ${confidenceLabel(r.confidence)}` : ''}</Chip>}
            {r.owner && <span className="truncate text-xs text-muted" title={`AS${r.asn} · ${t('an.ownerHint')}`}>{r.owner}</span>}
            {r.category && r.kind !== 'ip' && r.kind !== 'category' && <span className="text-xs text-muted">{r.category}</span>}
          </div>
        </td>
        <td className="tnum px-2 py-2 text-right text-fg">{formatInt(r.connections)}</td>
        <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
        <td className="tnum px-2 py-2 text-right text-muted">{r.users}</td>
        <td className="tnum px-2 py-2 text-right text-muted">{r.nodes}</td>
        <td className="tnum px-2 py-2 text-right text-muted" title={r.bytes == null ? t('an.bytesNone') : t('an.bytesHint')}>{r.bytes == null ? '—' : formatBytes(r.bytes)}</td>
        <td className="tnum max-w-[140px] truncate px-2 py-2 text-muted" title={r.ports.join(', ')}>{r.ports.join(', ')}</td>
        <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatDateTime(r.last_seen, tz)}</td>
      </tr>
      {open && child && <Children params={child.params} ctx={child.next} depth={depth + 1} subject={subject} tz={tz} />}
    </>
  )
}

function Children({ params, ctx, depth, subject, tz }: { params: Record<string, string>; ctx: Ctx; depth: number; subject: string; tz: string }) {
  const { filters } = useApp()
  const { data, error } = useAnalytics<DestResponse>('destinations', filters, { ...params, subject, limit: '100' })
  if (error) return <tr><td colSpan={8} className="px-3 py-2 text-[13px] text-red">{error}</td></tr>
  if (!data) return <tr><td colSpan={8} className="px-3 py-2 text-[13px] text-muted">{t('state.loading')}</td></tr>
  const max = Math.max(0, ...data.rows.map((r) => r.share))
  return <>{data.rows.map((r) => <Node key={`${r.kind}:${r.key}`} r={r} max={max} tz={tz} depth={depth} subject={subject} ctx={ctx} />)}</>
}

/** Bare-IP traffic grouped by who owns the address range. */
function NetworksView({ subject }: { subject: string }) {
  const { filters } = useApp()
  const { data, error } = useAnalytics<NetworksResponse>('networks', filters, { subject, limit: '60' })
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.meta.state === 'no_data') return <NoDataPanel meta={data.meta} />
  return (
    <Card title={t('net.title')} note={t('net.note')}>
      {data.rows.length === 0 ? <p className="py-6 text-center text-[13px] text-muted">{t('geo.none')}</p> : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <caption className="sr-only">{t('net.title')}</caption>
            <thead><tr className="text-left text-xs text-muted">
              <th scope="col" className="px-2 py-2 font-medium">{t('net.owner')}</th>
              <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
              <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
              <th scope="col" className="px-2 py-2 text-right font-medium">{t('net.ips')}</th>
              <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.bytes')}</th>
              <th scope="col" className="px-2 py-2 font-medium">{t('net.examples')}</th>
            </tr></thead>
            <tbody>
              {data.rows.map((r) => (
                <tr key={r.asn} className="border-t border-line/60">
                  <td className="max-w-[320px] px-2 py-2"><span className="font-medium">{r.org}</span> <span className="text-xs text-muted">AS{r.asn}</span></td>
                  <td className="tnum px-2 py-2 text-right">{formatInt(r.connections)}</td>
                  <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
                  <td className="tnum px-2 py-2 text-right text-muted">{formatInt(r.ips)}</td>
                  <td className="tnum px-2 py-2 text-right text-muted">{r.bytes == null ? '—' : formatBytes(r.bytes)}</td>
                  <td className="tnum px-2 py-2 text-xs text-muted">{r.examples.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-xs leading-5 text-muted">{t('net.coverage', { matched: formatInt(data.matched), total: formatInt(data.ip_only) })} {t('net.caveat')}</p>
      <p className="mt-1 text-[11px] text-muted/80">{t('net.credit')}</p>
    </Card>
  )
}

/** The groupings of the destinations that a tab of the Sites and domains page shows. */
export type DestGroup = 'service' | 'host' | 'ip' | 'networks'

/**
 * One grouping of where the connections go (services, domains and addresses, bare addresses, networks), without a page
 * around it: the filters belong to the page that holds it. The page gives it the person whose traffic it is about and the
 * search words (already waited out), and keys it by them, so paging starts over when any of them changes.
 */
export function DestinationsView({ group, subject, q }: { group: DestGroup; subject: string; q: string }) {
  const { filters } = useApp()
  const [offset, setOffset] = useState(0)
  const { data, error } = useAnalytics<DestResponse>('destinations', filters, { group_by: group, q, subject, limit: String(PAGE), offset: String(offset) }, group !== 'networks')
  const tz = filters.tz
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0
  if (group === 'networks') return <NetworksView subject={subject} />
  return (
    <div className="space-y-4">
      {data && <CoverageLine meta={data.meta} tz={tz} />}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {data && data.meta.state === 'ok' && (
        <Card note={t('an.classNote')} title={`${t('an.total', { n: formatInt(data.total_connections) })} · ${t('an.groups', { n: formatInt(data.groups) })}`}>
          {data.rows.length === 0 ? <p className="py-6 text-center text-[13px] text-muted">{t('an.noMatch')}</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <caption className="sr-only">{t('an.domains.title')}</caption>
                <thead><tr className="text-left text-xs text-muted">
                  <th scope="col" className="px-2 py-2 font-medium">{t('an.dest')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                  <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.nodes')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium" title={t('an.bytesHint')}>{t('an.bytes')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('an.ports')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('an.lastSeen')}</th>
                </tr></thead>
                <tbody>
                  {data.rows.map((r) => <Node key={`${group}:${r.kind}:${r.key}`} r={r} max={max} tz={tz} depth={0} subject={subject} ctx={{}} />)}
                </tbody>
              </table>
            </div>
          )}
          {hasAwg(data.rows) && <p className="mt-3 text-xs leading-5 text-muted">{t('src.awg.note')}</p>}
          {data.groups > PAGE && (
            <nav aria-label="pagination" className="mt-3 flex items-center justify-between gap-3 text-[13px] text-muted">
              <span className="tnum">{t('an.page', { from: offset + 1, to: Math.min(offset + PAGE, data.groups), total: data.groups })}</span>
              <div className="flex gap-2">
                <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className={`${controlCls} disabled:opacity-40`}>{t('an.prev')}</button>
                <button type="button" disabled={offset + PAGE >= data.groups} onClick={() => setOffset(offset + PAGE)} className={`${controlCls} disabled:opacity-40`}>{t('an.next')}</button>
              </div>
            </nav>
          )}
        </Card>
      )}
    </div>
  )
}
