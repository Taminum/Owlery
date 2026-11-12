import { useState } from 'react'
import { Link } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Segmented, Skeleton } from '../components/ui'
import { PageHead } from '../components/Analyzer'

interface Iface { name: string; up: boolean; rx_bps: number; tx_bps: number }
interface Client { ip: string; mac: string; host?: string }
interface Dev {
  id: string; name: string; kind?: string; online: boolean; last_seen: string | null; parent_id: string | null
  view: { board: string; conn?: number; ifaces: Iface[]; clients: Client[] }
}

const SHOWN = 8

// The port the internet comes in by: the busiest port that is neither a bridge, a radio nor a virtual one.
function uplink(d: Dev): { port: string; rx: number; tx: number } | null {
  const own = d.view.ifaces.filter((f) => f.up && !/^(lo|bridge|br-|docker|wlan|ra\d|phy|veth|tun|wg|ap)/i.test(f.name))
  if (own.length === 0) return null
  const f = own.reduce((a, b) => (b.rx_bps + b.tx_bps > a.rx_bps + a.tx_bps ? b : a))
  return { port: f.name, rx: f.rx_bps, tx: f.tx_bps }
}

function Router({ d, all, withClients, depth }: { d: Dev; all: Dev[]; withClients: boolean; depth: number }) {
  const kids = all.filter((x) => x.parent_id === d.id)
  const state = d.last_seen === null ? t('map.never') : d.online ? '' : t('map.silent')
  const clients = d.view.clients
  return (
    <div className={depth > 0 ? 'ml-4 border-l border-line pl-4' : ''}>
      <Link to="/routers" title={t('map.open')} className={`block rounded-control border bg-elevated px-3 py-2.5 hover:border-cyan ${d.online || d.last_seen === null ? 'border-line' : 'border-red/60'}`}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{d.name}</span>
          <Chip tone={d.kind === 'openwrt' ? 'muted' : 'cyan'}>{d.kind === 'openwrt' ? 'OpenWrt' : 'MikroTik'}</Chip>
          {state && <Chip tone={d.last_seen === null ? 'amber' : 'red'}>{state}</Chip>}
        </div>
        <div className="mt-0.5 text-xs text-muted">{[d.view.board, d.view.conn !== undefined && t('map.conns', { n: d.view.conn })].filter(Boolean).join(' · ')}</div>
      </Link>
      <div className="mt-2 space-y-2">
        {kids.map((k) => <Router key={k.id} d={k} all={all} withClients={withClients} depth={depth + 1} />)}
        {withClients && (
          <div className="ml-4 border-l border-line pl-4">
            {clients.length === 0 ? <p className="text-xs text-muted">{t('map.noClients')}</p> : (
              <div className="flex flex-wrap gap-1.5">
                {clients.slice(0, SHOWN).map((c) => (
                  <span key={c.mac} title={`${c.ip} · ${c.mac}`} className="rounded-control border border-line px-2 py-1 text-xs">{c.host || c.ip}</span>
                ))}
                {clients.length > SHOWN && <span className="px-1 py-1 text-xs text-muted">{t('map.more', { n: clients.length - SHOWN })}</span>}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
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
          <div className="grid gap-4 lg:grid-cols-2">
            {roots.map((r) => {
              const up = uplink(r)
              return (
                <Card key={r.id} title={t('map.network', { name: r.name })}>
                  <div className="mb-3 flex flex-wrap items-center gap-2 text-[13px]">
                    <Chip tone="muted">{t('map.internet')}</Chip>
                    <span className="tnum text-muted">
                      {up ? `↓ ${formatRate(up.rx)} · ↑ ${formatRate(up.tx)} · ${t('map.viaPort', { port: up.port })}` : t('map.noRate')}
                    </span>
                  </div>
                  <Router d={r} all={all} withClients={mode === 'all'} depth={0} />
                </Card>
              )
            })}
          </div>
          <p className="text-xs text-muted">{t('map.hint')}</p>
        </>
      )}
    </div>
  )
}
