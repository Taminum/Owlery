import { t } from '../i18n'
import { formatRate } from '../lib/format'
import { Card, Chip } from './ui'
import type { Server } from './ServerParts'
import type { Hardware } from '../lib/types'

type Nic = Hardware['nics'][number]

const isV6 = (a: string) => a.includes(':')

/** Addresses of a private network: the ones that do not leave the building. */
function isLocal(a: string): boolean {
  if (isV6(a)) return /^f[cd]/i.test(a)
  const [x, y] = a.split('.').map(Number)
  return x === 10 || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168) || (x === 100 && y >= 64 && y <= 127)
}

function speedText(mbps?: number): string {
  if (!mbps) return '—'
  return mbps >= 1000 ? `${String(mbps / 1000).replace('.', ',')} Гбит/с` : `${mbps} Мбит/с`
}

/** The interface the machine goes out through: the one with a gateway, else the first one with an address. */
function mainNic(nics: Nic[]): Nic | undefined {
  return nics.find((n) => n.gateway) ?? nics[0]
}

function Fact({ label, value, note, mono }: { label: string; value: string; note?: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-muted">{label}</div>
      <div className={`break-words text-[16px] font-semibold ${mono ? 'tnum' : ''}`}>{value}</div>
      {note && <div className="text-xs text-muted">{note}</div>}
    </div>
  )
}

/**
 * What the machine's network looks like from inside: its outside address, its own addresses, the gateway and name servers
 * and the interfaces. The Remnawave nodes are shown only where there are some.
 */
export function NetworkView({ s }: { s: Server }) {
  const nics = s.hardware?.nics ?? []
  const main = mainNic(nics)
  const inner = (main?.ips ?? []).find((a) => !isV6(a))
  const rate = s.host && s.host.has_data ? `↓ ${formatRate(s.host.rx_bps)} · ↑ ${formatRate(s.host.tx_bps)}` : ''
  return (
    <div className="space-y-4">
      <Card title={t('net.addresses')}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Fact label={t('net.external')} value={s.external_ip || '—'} note={t('net.externalNote')} mono />
          <Fact label={t('net.inner')} value={inner ?? '—'} note={main ? main.name : undefined} mono />
          <Fact label={t('net.gateway')} value={main?.gateway || '—'} mono />
          <Fact label={t('net.dns')} value={main?.dns?.length ? main.dns.join(' · ') : '—'} mono />
          {rate && <Fact label={t('net.now')} value={rate} note={t('net.nowNote')} />}
        </div>
      </Card>

      <Card title={t('net.interfaces')}>
        {nics.length === 0 ? <p className="text-[13px] text-muted">{t('net.noData')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left text-xs text-muted">
                  <th className="px-2 py-1.5 font-medium">{t('net.col.name')}</th>
                  <th className="px-2 py-1.5 font-medium">{t('net.col.speed')}</th>
                  <th className="px-2 py-1.5 font-medium">{t('net.col.ips')}</th>
                  <th className="px-2 py-1.5 font-medium">{t('net.gateway')}</th>
                  <th className="px-2 py-1.5 font-medium">{t('net.dns')}</th>
                </tr>
              </thead>
              <tbody className="[&>tr]:border-t [&>tr]:border-line/60">
                {nics.map((n) => (
                  <tr key={n.name} className="align-top">
                    <td className="px-2 py-1.5 font-medium">{n.name}</td>
                    <td className="tnum whitespace-nowrap px-2 py-1.5 text-muted">{speedText(n.speed_mbps)}</td>
                    <td className="px-2 py-1.5">
                      {(n.ips ?? []).length === 0 ? '—' : (n.ips ?? []).map((a) => (
                        <div key={a} className="tnum break-all">{a}{isLocal(a) && <span className="ml-2"><Chip tone="muted">{t('net.local')}</Chip></span>}</div>
                      ))}
                    </td>
                    <td className="tnum px-2 py-1.5">{n.gateway || '—'}</td>
                    <td className="tnum px-2 py-1.5">{n.dns?.length ? n.dns.map((d) => <div key={d}>{d}</div>) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-2 text-xs text-muted">{t('net.note')}</p>
      </Card>

      {s.nodes.length > 0 && (
        <Card title={t('srv.nodes.title')}>
          <ul className="divide-y divide-line">
            {s.nodes.map((n) => (
              <li key={n.node_id} className="flex flex-wrap items-center justify-between gap-3 py-2 text-[13px]">
                <span>{n.name} <span className="text-xs text-muted">· {n.panel_name}{n.xray && ` · Xray ${n.xray}`}</span></span>
                <span className="flex items-center gap-3 text-xs text-muted">
                  {t('srv.nodes.users', { n: n.users_online })}
                  <Chip tone={n.online ? 'green' : 'red'}>{n.online ? t('srv.nodes.on') : t('srv.nodes.off')}</Chip>
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}
