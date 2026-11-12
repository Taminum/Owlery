import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useApp } from '../lib/context'
import { C } from '../lib/colors'
import { formatBytes, formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Skeleton } from './ui'
import { DataTable } from './DataTable'
import { Sparkline } from './Kpi'

export interface PanelHealthData {
  requests: {
    since: string | null; total: number; failed: number; slow: number
    worst: { at: string; method: string; path: string; status: number; ms: number }[]
    hourly: { hour: string; total: number; failed: number; slow: number }[]
  }
  db_bytes: number
  db_samples: { day: string; bytes: number }[]
  backups: { taken_at: string; bytes: number; ok: boolean }[]
  backup_stale_hours: number
}

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'red' | 'amber' | 'green' }) {
  const color = tone === 'red' ? 'text-red' : tone === 'amber' ? 'text-amber' : tone === 'green' ? 'text-green' : 'text-fg'
  return (
    <div className="rounded-card border border-line bg-surface p-4">
      <div className="text-xs text-muted">{label}</div>
      <div className={`tnum mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  )
}

/** The owner's page about Owlery itself: how its answers are going, how big the database is and grows, whether the nightly dump reported. */
export default function PanelHealth() {
  const { filters } = useApp()
  const { data, error } = useLoad((s) => api.get<PanelHealthData>('/api/v1/panel-health', s), [], 60_000)
  const tz = filters.tz
  const [now] = useState(() => Date.now())
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <div className="space-y-4" aria-busy="true" aria-label={t('state.loading')}><Skeleton className="h-24" /><Skeleton className="h-40" /></div>

  const last = data.backups[0]
  const lastOk = data.backups.find((b) => b.ok)
  const ageH = lastOk ? (now - new Date(lastOk.taken_at).getTime()) / 3_600_000 : null
  const backupTone = !last ? undefined : ageH === null || ageH > data.backup_stale_hours ? 'red' : 'green'
  const growth = data.db_samples.length >= 2 ? data.db_bytes - data.db_samples[0].bytes : null
  const r = data.requests

  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">{t('ph.intro')}</p>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label={t('ph.requests')} value={formatInt(r.total)} sub={r.since ? t('ph.since', { at: formatDateTime(r.since, tz) }) : t('ph.noneYet')} />
        <Tile label={t('ph.failed')} value={formatInt(r.failed)} tone={r.failed > 0 ? 'red' : 'green'} sub={t('ph.failedHint')} />
        <Tile label={t('ph.slow')} value={formatInt(r.slow)} tone={r.slow > 20 ? 'amber' : undefined} sub={t('ph.slowHint')} />
        <Tile label={t('ph.db')} value={formatBytes(data.db_bytes)} sub={growth === null ? undefined : t('ph.dbGrowth', { n: `${growth >= 0 ? '+' : '−'}${formatBytes(Math.abs(growth))}`, d: data.db_samples.length - 1 })} />
      </div>

      <Card title={t('ph.backup')} note={t('ph.backupNote')}>
        <div className="mb-3 flex flex-wrap items-center gap-2 text-[13px]">
          {!last ? <Chip tone="amber">{t('ph.backupNone')}</Chip>
            : <Chip tone={backupTone}>{backupTone === 'green' ? t('ph.backupOk', { at: formatDateTime(lastOk!.taken_at, tz) }) : t('ph.backupBad')}</Chip>}
        </div>
        {data.backups.length > 0 && (
          <DataTable caption={t('ph.backup')} rows={data.backups} rowKey={(b) => b.taken_at} pageSize={14} columns={[
            { key: 'at', title: t('ph.col.when'), sort: (b) => b.taken_at, descFirst: true, className: 'tnum whitespace-nowrap', cell: (b) => formatDateTime(b.taken_at, tz) },
            { key: 'size', title: t('ph.col.size'), sort: (b) => b.bytes, descFirst: true, align: 'right', className: 'tnum', cell: (b) => formatBytes(b.bytes) },
            { key: 'ok', title: t('ph.col.result'), cell: (b) => <Chip tone={b.ok ? 'green' : 'red'}>{b.ok ? t('ph.ok') : t('ph.fail')}</Chip> },
          ]} />
        )}
      </Card>

      {data.db_samples.length >= 2 && (
        <Card title={t('ph.dbTitle')} note={t('ph.dbNote')}>
          <Sparkline series={{ v: data.db_samples.map((s) => s.bytes) } as never} color={C.cyan} id="dbsize" />
        </Card>
      )}

      <Card title={t('ph.worst')} note={t('ph.worstNote')}>
        {r.worst.length === 0 ? <p className="text-[13px] text-muted">{t('ph.worstNone')}</p> : (
          <DataTable caption={t('ph.worst')} rows={r.worst} rowKey={(w) => `${w.at}|${w.method}|${w.path}`} pageSize={12} columns={[
            { key: 'at', title: t('ph.col.when'), sort: (w) => w.at, descFirst: true, className: 'tnum whitespace-nowrap text-muted', cell: (w) => formatDateTime(w.at, tz) },
            { key: 'req', title: t('ph.col.request'), cell: (w) => <span className="font-mono text-xs">{w.method} {w.path}</span> },
            { key: 'status', title: t('ph.col.status'), sort: (w) => w.status, cell: (w) => <Chip tone={w.status >= 500 ? 'red' : 'amber'}>{w.status}</Chip> },
            { key: 'ms', title: t('ph.col.time'), sort: (w) => w.ms, descFirst: true, align: 'right', className: 'tnum', cell: (w) => `${(w.ms / 1000).toFixed(1)} с` },
          ]} />
        )}
      </Card>
    </div>
  )
}
