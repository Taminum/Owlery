import type { ReactNode } from 'react'
import { Cpu, Database, MemoryStick, Network, Tv } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { formatBytes } from '../lib/format'
import type { Hardware } from '../lib/types'
import { Card, Chip } from './ui'
import { Meter } from './HostView'
import type { Host } from './HostView'

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-t border-line/60 py-1.5 text-[13px] first:border-t-0">
      <span className="shrink-0 text-muted">{k}</span>
      <span className="min-w-0 break-words text-right">{children}</span>
    </div>
  )
}


const KIND_TONE = { nvme: 'cyan', ssd: 'green', hdd: 'muted', unknown: 'muted' } as const

function mhz(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1).replace('.', ',')} ГГц` : `${n} МГц`
}

/** What the machine is made of: system, processor, memory, disks, video card, network. The agent reads it every
 * couple of hours; a blank block means the machine did not say, not that it has none. */
export function HardwareSection({ hw, host }: { hw: Hardware; host: Host | null }) {
  const cpu = hw.cpu
  const m = hw.memory
  const volumes = host?.has_data ? host.disks : []
  return (
    <section aria-label={t('hw.title')} className="space-y-3">
      <h2 className="text-[13px] font-semibold uppercase tracking-wide text-muted">{t('hw.title')}</h2>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3 [&>*]:min-w-0">
        <Card title={t('hw.system')} className="h-full">
          <Row k={t('hw.type')}>{hw.virtual ? `${t('hw.virtual')}${hw.hypervisor ? `, ${hw.hypervisor}` : ''}` : t('hw.physical')}</Row>
          {hw.vendor && <Row k={t('hw.vendor')}>{hw.vendor}</Row>}
          {hw.model && <Row k={t('hw.model')}>{hw.model}</Row>}
          {hw.bios && <Row k="BIOS">{hw.bios}</Row>}
          {hw.os_build && <Row k={t('hw.os')}>{hw.os_build}</Row>}
        </Card>

        <Card title={t('host.cpu')} className="h-full">
          <div className="mb-1 flex items-center gap-2 text-[13px] font-medium"><Cpu size={15} className="text-blue" aria-hidden />{cpu.model || '—'}</div>
          {cpu.cores > 0 && <Row k={t('hw.cores')}>{cpu.cores}{cpu.threads > 0 && cpu.threads !== cpu.cores ? ` / ${cpu.threads}` : ''}</Row>}
          {cpu.mhz ? <Row k={t('hw.clock')}>{mhz(cpu.mhz)}{cpu.max_mhz && cpu.max_mhz > cpu.mhz ? `, ${t('hw.upTo')} ${mhz(cpu.max_mhz)}` : ''}</Row> : cpu.max_mhz ? <Row k={t('hw.clock')}>{t('hw.upTo')} {mhz(cpu.max_mhz)}</Row> : null}
          {cpu.cache_mb ? <Row k={t('hw.cache')}>{cpu.cache_mb} {t('hw.mb')} L3</Row> : null}
        </Card>

        <Card title={t('host.mem')} className="h-full">
          <div className="mb-1 flex items-center gap-2 text-[13px] font-medium"><MemoryStick size={15} className="text-blue" aria-hidden />{host?.has_data && host.mem_total > 0 ? formatBytes(host.mem_total) : '—'}</div>
          {m.slots ? <Row k={t('hw.slots')}>{t('hw.slotsOf', { used: m.slots_used ?? 0, n: m.slots })}</Row> : null}
          {m.type ? <Row k={t('hw.memType')}>{m.type}{m.speed_mt ? `, ${m.speed_mt} ${t('hw.mts')}` : ''}</Row> : null}
        </Card>

        <Card title={t('host.disk')} className="h-full">
          {hw.disks.length === 0 && volumes.length === 0 && <p className="text-[13px] text-muted">{t('hw.none')}</p>}
          <ul className="space-y-2">
            {hw.disks.map((d, i) => (
              <li key={`${d.model}${i}`} className="flex items-center justify-between gap-3 text-[13px]">
                <span className="flex min-w-0 items-center gap-2"><Database size={14} className="shrink-0 text-blue" aria-hidden /><span className="truncate" title={d.model}>{d.model}</span></span>
                <span className="flex shrink-0 items-center gap-2">
                  <span className="tnum text-muted">{formatBytes(d.size)}</span>
                  <Chip tone={KIND_TONE[d.kind as keyof typeof KIND_TONE] ?? 'muted'}>{t(`hw.kind.${d.kind}` as MsgKey)}</Chip>
                </span>
              </li>
            ))}
          </ul>
          {volumes.length > 0 && (
            <div className="mt-3 space-y-2.5 border-t border-line/60 pt-3">
              {volumes.map((v) => <Meter key={v.m} label={v.m} pct={v.t > 0 ? (v.u * 100) / v.t : null} detail={`${formatBytes(v.u)} / ${formatBytes(v.t)}`} />)}
            </div>
          )}
        </Card>

        <Card title={t('hw.gpu')} className="h-full">
          {hw.gpus.length === 0 ? <p className="text-[13px] text-muted">{t('hw.none')}</p> : (
            <ul className="space-y-2">
              {hw.gpus.map((g, i) => (
                <li key={`${g.name}${i}`} className="text-[13px]">
                  <div className="flex items-center gap-2 font-medium"><Tv size={14} className="shrink-0 text-blue" aria-hidden />{g.name}</div>
                  {(g.mem || g.driver) && <div className="ml-6 text-xs text-muted">{[g.mem ? formatBytes(g.mem) : '', g.driver ? `${t('hw.driver')} ${g.driver}` : ''].filter(Boolean).join(' · ')}</div>}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={t('hw.net')} className="h-full">
          {hw.nics.length === 0 ? <p className="text-[13px] text-muted">{t('hw.none')}</p> : (
            <ul className="space-y-2">
              {hw.nics.map((n) => (
                <li key={n.name} className="text-[13px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2 font-medium"><Network size={14} className="shrink-0 text-blue" aria-hidden />{n.name}</span>
                    {n.speed_mbps ? <span className="tnum text-xs text-muted">{n.speed_mbps >= 1000 ? `${String(n.speed_mbps / 1000).replace(".", ",")} Гбит/с` : `${n.speed_mbps} Мбит/с`}</span> : null}
                  </div>
                  {n.ips && n.ips.length > 0 && <div className="tnum ml-6 break-all text-xs text-muted">{n.ips.join(' · ')}</div>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </section>
  )
}

