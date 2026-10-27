import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatRate } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { Drawer } from '../components/Drawer'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { HostDetail, Meter, Spark, uptimeText, type Host } from '../components/HostView'

export default function Hosts() {
  const q = useLoad((s) => api.get<{ hosts: Host[] }>('/api/v1/hosts', s), [], 15_000)
  const [open, setOpen] = useState<Host | null>(null)
  const hosts = q.data?.hosts ?? []
  return (
    <div className="space-y-4">
      <PageHead title={t('host.title')} subtitle={t('host.subtitle')} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && hosts.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('host.empty')}</p>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {hosts.map((h) => {
          const root = h.disks.find((d) => d.m === '/') ?? h.disks[0]
          const memPct = h.mem_total > 0 ? (h.mem_used * 100) / h.mem_total : null
          return (
            <Card key={h.id} title={h.name} note={[h.os, h.cpus > 0 ? `${h.cpus} ${t('host.cores')}` : '', h.mem_total > 0 ? formatBytes(h.mem_total) : ''].filter(Boolean).join(' · ') || undefined}
              right={<Chip tone={!h.has_data ? 'muted' : h.online ? 'green' : 'amber'}>{!h.has_data ? t('host.noAgent') : h.online ? t('host.online') : t('host.stale')}</Chip>}>
              {!h.has_data ? <p className="text-[13px] text-muted">{t('host.noAgent.hint')}</p> : (
                <div className="cursor-pointer space-y-3" onClick={() => setOpen(h)}>
                  <Meter label={t('host.cpu')} pct={h.cpu} detail={t('host.loadAvg', { n: h.load1.toFixed(2) })} />
                  <Meter label={t('host.mem')} pct={memPct} detail={`${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}`} />
                  <Meter label={root ? `${t('host.disk')} ${root.m}` : t('host.disk')} pct={root && root.t > 0 ? (root.u * 100) / root.t : null} detail={root ? `${formatBytes(root.u)} / ${formatBytes(root.t)}` : ''} />
                  <p className="text-xs text-muted" title={t('host.net.title')}>{t('host.net')}: ↓ {formatRate(h.rx_bps)} · ↑ {formatRate(h.tx_bps)} · {t('host.conns', { n: h.estab })}{h.syn_recv > 0 && <span className={h.syn_recv >= 300 ? 'text-red' : ''}> · {t('host.synShort', { n: h.syn_recv })}</span>}</p>
                  {h.procs.length > 0 && <p className="truncate text-xs text-muted" title={t('host.top')}>{t('host.top')}: {[...h.procs].filter((p) => p.cpu > 0.05).sort((a, b) => b.cpu - a.cpu).slice(0, 3).map((p) => `${p.n} ${Math.round(p.cpu)}%`).join(' · ') || t('host.procs.idle')}</p>}
                  <div className="flex items-center justify-between gap-3 pt-1 text-xs text-muted">
                    <span title={t('host.spark')}><Spark values={h.cpu_spark} /></span>
                    <span>{t('host.up')} {uptimeText(h.uptime)}</span>
                    <button type="button" className="underline hover:text-fg" onClick={() => setOpen(h)}>{t('host.more')}</button>
                  </div>
                </div>
              )}
            </Card>
          )
        })}
      </div>
      {open && <Drawer title={open.name} onClose={() => setOpen(null)}><HostDetail host={open} /></Drawer>}
    </div>
  )
}
