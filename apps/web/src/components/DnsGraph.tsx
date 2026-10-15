import { useMemo } from 'react'
import { t, type MsgKey } from '../i18n'
import type { DnsGraph as Graph, DnsGraphEdge, DnsGraphNode } from '../lib/types'

const COL_X: Record<DnsGraphNode['kind'], number> = { ns: 20, name: 290, mail: 560, ip: 830 }
const W = 200
const H = 26
const GAP = 36
const TYPE_CLASS: Record<string, string> = { A: 'text-cyan', AAAA: 'text-blue', CNAME: 'text-amber', MX: 'text-green', NS: 'text-muted' }

interface Placed extends DnsGraphNode { x: number; y: number }

function layout(nodes: DnsGraphNode[]): { placed: Map<string, Placed>; height: number } {
  const cols: Record<string, DnsGraphNode[]> = { ns: [], name: [], mail: [], ip: [] }
  for (const n of nodes) cols[n.kind].push(n)
  cols.name.sort((a, b) => (a.group ?? '').localeCompare(b.group ?? '') || a.label.localeCompare(b.label))
  for (const k of ['ns', 'mail', 'ip']) cols[k].sort((a, b) => a.label.localeCompare(b.label))
  const placed = new Map<string, Placed>()
  let rows = 1
  for (const k of Object.keys(cols) as DnsGraphNode['kind'][]) {
    cols[k].forEach((n, i) => placed.set(n.id, { ...n, x: COL_X[k], y: 20 + i * GAP }))
    rows = Math.max(rows, cols[k].length)
  }
  return { placed, height: 40 + rows * GAP }
}

function path(a: Placed, b: Placed): string {
  // From the right edge of the left node to the left edge of the right one; a link inside one column loops out to its right.
  if (a.x === b.x) {
    const x = a.x + W
    const mid = x + 40
    return `M ${x} ${a.y + H / 2} C ${mid} ${a.y + H / 2}, ${mid} ${b.y + H / 2}, ${x} ${b.y + H / 2}`
  }
  const [l, r] = a.x < b.x ? [a, b] : [b, a]
  const x1 = l.x + W
  const x2 = r.x
  const c = (x2 - x1) / 2
  return `M ${x1} ${l.y + H / 2} C ${x1 + c} ${l.y + H / 2}, ${x2 - c} ${r.y + H / 2}, ${x2} ${r.y + H / 2}`
}

/** The map as an SVG: columns of names, name servers, mail servers and addresses, and one line per observed record. */
export function DnsGraph({ graph, selected, onSelect, query }: { graph: Graph; selected: string | null; onSelect: (n: DnsGraphNode) => void; query: string }) {
  const { placed, height } = useMemo(() => layout(graph.nodes), [graph.nodes])
  const q = query.trim().toLowerCase()
  const linked = useMemo(() => {
    const s = new Set<string>()
    if (selected) {
      s.add(selected)
      for (const e of graph.edges) {
        if (e.from === selected) s.add(e.to)
        if (e.to === selected) s.add(e.from)
      }
    }
    return s
  }, [graph.edges, selected])

  return (
    <div className="overflow-auto rounded-control border border-line bg-surface">
      <svg role="img" aria-label={t('dns.tab.map')} viewBox={`0 0 ${COL_X.ip + W + 20} ${height}`} width="100%" className="block min-w-[640px]" style={{ aspectRatio: `${COL_X.ip + W + 20} / ${height}` }}>
        {graph.edges.map((e: DnsGraphEdge, i) => {
          const a = placed.get(e.from)
          const b = placed.get(e.to)
          if (!a || !b) return null
          const on = !selected || e.from === selected || e.to === selected
          return (
            <path key={i} d={path(a, b)} fill="none" strokeWidth={on && selected ? 2 : 1.25} strokeDasharray={e.unverified ? '5 4' : undefined}
              opacity={e.no_longer_observed ? 0.3 : on ? 0.9 : 0.15} stroke="currentColor" className={TYPE_CLASS[e.type] ?? 'text-muted'}>
              <title>{`${a.label} → ${b.label} (${e.type}${e.label ? ' ' + e.label : ''})`}</title>
            </path>
          )
        })}
        {[...placed.values()].map((n) => {
          const hit = q !== '' && n.label.toLowerCase().includes(q)
          const dim = (selected && !linked.has(n.id)) || (q !== '' && !hit)
          return (
            <g key={n.id} role="button" tabIndex={0} aria-label={`${t(`dns.map.kind.${n.kind}` as MsgKey)} ${n.label}`} aria-pressed={selected === n.id}
              onClick={() => onSelect(n)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(n) } }}
              transform={`translate(${n.x} ${n.y})`} opacity={dim ? 0.35 : 1} className="cursor-pointer outline-none focus-visible:[&>rect]:stroke-cyan">
              <rect width={W} height={H} rx={6} className={selected === n.id ? 'fill-elevated stroke-cyan' : 'fill-elevated stroke-line'} strokeWidth={selected === n.id || hit ? 2 : 1} />
              <text x={10} y={17} fontSize={12} className="fill-current" style={{ fontFamily: n.kind === 'name' ? 'inherit' : 'ui-monospace, monospace' }}>
                {n.label.length > 28 ? n.label.slice(0, 27) + '…' : n.label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
