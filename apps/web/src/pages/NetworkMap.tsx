import { useState, type ReactElement } from 'react'
import { useNavigate } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Segmented, Skeleton } from '../components/ui'
import { PageHead } from '../components/Analyzer'

interface Iface { name: string; up: boolean; rx_bps: number; tx_bps: number }
interface Client { ip: string; mac: string; host?: string }
interface Dev {
  id: string; name: string; kind?: string; online: boolean; last_seen: string | null; parent_id: string | null
  view: { board: string; conn?: number; ifaces: Iface[]; clients: Client[] }
}

const SHOWN = 6 // clients drawn under a router; the rest are one "ещё N"
const BW = 196, BH = 56 // a router
const CW = 150, CH = 26, CGAP = 6 // a client
const GAP = 24, VGAP = 48

const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

// The port the internet comes in by: the busiest port that is neither a bridge, a radio nor a virtual one.
function uplink(d: Dev): { port: string; rx: number; tx: number } | null {
  const own = d.view.ifaces.filter((f) => f.up && !/^(lo|bridge|br-|docker|wlan|ra\d|phy|veth|tun|wg|ap)/i.test(f.name))
  if (own.length === 0) return null
  const f = own.reduce((a, b) => (b.rx_bps + b.tx_bps > a.rx_bps + a.tx_bps ? b : a))
  return { port: f.name, rx: f.rx_bps, tx: f.tx_bps }
}

const curve = (x1: number, y1: number, x2: number, y2: number) => `M${x1} ${y1} C${x1} ${y1 + VGAP / 2}, ${x2} ${y2 - VGAP / 2}, ${x2} ${y2}`
const EDGE = { fill: 'none', stroke: 'var(--color-muted)', strokeOpacity: 0.55, strokeWidth: 1.5 } as const

interface Lay { w: number; h: number; cx: number; items: ReactElement[] }

// A router, its devices in a column under it and the routers behind it in a row, each laid out the same way. The box is centred over
// everything below it, and lines run from the bottom of the box to the top of each part.
function layout(d: Dev, all: Dev[], withClients: boolean, go: (to: string) => void): Lay {
  const kids = all.filter((x) => x.parent_id === d.id).map((k) => layout(k, all, withClients, go))
  const clients = withClients ? d.view.clients : []
  const shown = clients.slice(0, SHOWN)
  const extra = clients.length - shown.length
  const rows = shown.length + (extra > 0 ? 1 : 0)
  const colW = rows > 0 ? CW : 0
  const colH = rows * (CH + CGAP) - (rows > 0 ? CGAP : 0)
  const parts = [...(rows > 0 ? [{ w: colW, h: colH }] : []), ...kids.map((k) => ({ w: k.w, h: k.h }))]
  const rowW = parts.reduce((s, p) => s + p.w, 0) + GAP * Math.max(0, parts.length - 1)
  const w = Math.max(BW, rowW)
  const bx = (w - BW) / 2
  const x0 = (w - rowW) / 2
  const ry = BH + VGAP
  const items: ReactElement[] = []
  const stroke = d.last_seen !== null && !d.online ? 'var(--color-red)' : d.kind === 'openwrt' ? 'var(--color-blue)' : 'var(--color-cyan)'
  const tint = d.kind === 'openwrt' ? 'var(--color-blue)' : 'var(--color-cyan)'
  const state = d.last_seen === null ? t('map.never') : d.online ? '' : t('map.silent')
  const sub = [d.view.board, d.view.conn !== undefined && t('map.conns', { n: d.view.conn })].filter(Boolean).join(' · ')
  items.push(
    <g key="box" role="link" tabIndex={0} aria-label={`${d.name}: ${t('map.open')}`} style={{ cursor: 'pointer' }} onClick={() => go('/routers')} onKeyDown={(e) => e.key === 'Enter' && go('/routers')}>
      <rect x={bx} y={0} width={BW} height={BH} rx={9} fill={`color-mix(in oklab, ${tint} 14%, var(--color-elevated))`} stroke={stroke} strokeWidth={1.5} />
      <text x={bx + BW / 2} y={state ? 17 : 21} textAnchor="middle" fontSize={14} fontWeight={600} fill="var(--color-fg)">{cut(d.name, 22)}</text>
      <text x={bx + BW / 2} y={state ? 33 : 40} textAnchor="middle" fontSize={11} fill="var(--color-muted)">{cut(sub, 30)}</text>
      {state && <text x={bx + BW / 2} y={48} textAnchor="middle" fontSize={11} fill="var(--color-red)">{state}</text>}
    </g>,
  )
  let x = x0
  if (rows > 0) {
    items.push(<path key="e-col" d={curve(bx + BW / 2, BH, x + CW / 2, ry)} {...EDGE} />)
    shown.forEach((c, i) => {
      const y = ry + i * (CH + CGAP)
      items.push(
        <g key={`c-${c.mac}`}>
          <title>{`${c.ip} · ${c.mac}`}</title>
          <rect x={x} y={y} width={CW} height={CH} rx={7} fill="var(--color-elevated)" stroke="var(--color-line)" />
          <text x={x + CW / 2} y={y + CH / 2 + 4} textAnchor="middle" fontSize={12} fill="var(--color-fg)">{cut(c.host || c.ip, 20)}</text>
        </g>,
      )
    })
    if (extra > 0) {
      items.push(<text key="more" x={x + CW / 2} y={ry + shown.length * (CH + CGAP) + CH / 2 + 4} textAnchor="middle" fontSize={12} fill="var(--color-muted)">{t('map.more', { n: extra })}</text>)
    }
    x += colW + GAP
  }
  kids.forEach((k, i) => {
    items.push(<path key={`e-${i}`} d={curve(bx + BW / 2, BH, x + k.cx, ry)} {...EDGE} />)
    items.push(<g key={`k-${i}`} transform={`translate(${x},${ry})`}>{k.items}</g>)
    x += k.w + GAP
  })
  return { w, h: parts.length > 0 ? ry + Math.max(0, ...parts.map((p) => p.h)) : BH, cx: bx + BW / 2, items }
}

function Network({ root, all, withClients }: { root: Dev; all: Dev[]; withClients: boolean }) {
  const navigate = useNavigate()
  const lay = layout(root, all, withClients, navigate)
  const up = uplink(root)
  const IW = 150, IH = 34
  const W = Math.max(lay.w, 300)
  const ox = (W - lay.w) / 2
  const top = IH + VGAP
  const H = top + lay.h
  const mid = ox + lay.cx
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={t('map.network', { name: root.name })} style={{ width: '100%', maxWidth: W * 1.25, height: 'auto' }}>
      <rect x={mid - IW / 2} y={0} width={IW} height={IH} rx={9} fill="var(--color-surface)" stroke="var(--color-line)" strokeWidth={1.5} />
      <text x={mid} y={IH / 2 + 5} textAnchor="middle" fontSize={13} fontWeight={600} fill="var(--color-fg)">{t('map.internet')}</text>
      <path d={`M${mid} ${IH} L${mid} ${top}`} {...EDGE} />
      <text x={mid + 10} y={IH + 17} fontSize={11} fill="var(--color-muted)">{up ? `↓ ${formatRate(up.rx)} · ↑ ${formatRate(up.tx)}` : t('map.noRate')}</text>
      {up && <text x={mid + 10} y={IH + 31} fontSize={11} fill="var(--color-muted)">{t('map.viaPort', { port: up.port })}</text>}
      <g transform={`translate(${ox},${top})`}>{lay.items}</g>
    </svg>
  )
}

export default function NetworkMap() {
  const { data, error } = useLoad((s) => api.get<{ devices: Dev[] }>('/api/v1/net-devices', s), [], 30_000)
  const [mode, setMode] = useState<'all' | 'routers'>('all')
  const all = data?.devices ?? []
  const known = new Set(all.map((d) => d.id))
  // A router whose parent has gone away is treated as standing at the edge.
  const roots = all.filter((d) => !d.parent_id || !known.has(d.parent_id))
  return (
    <div className="space-y-5">
      <PageHead title={t('map.title')} subtitle={t('map.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <Skeleton className="h-40" />}
      {data && all.length === 0 && <p className="text-[13px] text-muted">{t('map.empty')}</p>}
      {data && all.length > 0 && (
        <>
          <Segmented label={t('map.mode')} value={mode} onChange={setMode} options={[{ value: 'all', label: t('map.mode.all') }, { value: 'routers', label: t('map.mode.routers') }]} />
          <div className="grid gap-4 xl:grid-cols-2">
            {roots.map((r) => (
              <Card key={r.id} title={t('map.network', { name: r.name })}>
                <div className="flex justify-center"><Network root={r} all={all} withClients={mode === 'all'} /></div>
              </Card>
            ))}
          </div>
          <p className="text-xs text-muted">{t('map.hint')}</p>
        </>
      )}
    </div>
  )
}
