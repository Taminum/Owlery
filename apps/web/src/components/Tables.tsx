import { Globe2, Network } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { formatClock, formatInt, formatPct } from '../lib/format'
import type { Overview, Row } from '../lib/types'
import { Card, Chip } from './ui'

const th = 'sticky top-0 bg-surface px-2 py-2 text-left text-xs font-medium text-muted'

function ShareBar({ share, max, other }: { share: number; max: number; other?: boolean }) {
  return (
    <div className="h-1.5 w-full min-w-10 overflow-hidden rounded-full bg-elevated" aria-hidden>
      <div className={`h-full rounded-full ${other ? 'bg-blue' : 'bg-blue/80'}`} style={{ width: `${Math.max(3, Math.min(100, max > 0 ? (share / max) * 100 : 0))}%` }} />
    </div>
  )
}

const confLabel: Record<string, MsgKey> = { high: 'conf.high', medium: 'conf.medium', low: 'conf.low' }

export function TopTable({ title, note, firstCol, rows, showConfidence = false, mono = false }: { title: string; note?: string; firstCol: string; rows: Row[]; showConfidence?: boolean; mono?: boolean }) {
  const maxShare = Math.max(0, ...rows.map((r) => r.share))
  return (
    <Card title={title} note={note} className="h-full">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr>
              <th scope="col" className={`${th} w-7`}>{t('table.num')}</th>
              <th scope="col" className={th}>{firstCol}</th>
              {showConfidence && <th scope="col" className={th}>{t('table.confidence')}</th>}
              <th scope="col" className={`${th} text-right`}>{t('table.connections')}</th>
              <th scope="col" className={`${th} w-[120px]`}>{t('table.share')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={r.key} className="border-t border-line/60">
                <td className="tnum px-2 py-2 text-muted">{r.other ? '' : i + 1}</td>
                <td className={`max-w-[200px] truncate px-2 py-2 ${r.other ? 'text-muted' : 'text-fg'} ${mono ? 'tnum' : ''}`} title={r.label}>{r.other ? t('table.other') : r.label}</td>
                {showConfidence && <td className="px-2 py-2 text-muted">{r.confidence ? t(confLabel[r.confidence]) : '—'}</td>}
                <td className="tnum px-2 py-2 text-right text-fg">{formatInt(r.count)}</td>
                <td className="px-2 py-2">
                  <div className="flex items-center gap-2">
                    <span className="tnum w-11 shrink-0 text-right text-muted">{formatPct(r.share)}</span>
                    <ShareBar share={r.share} max={maxShare} other={r.other} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export function RecentTable({ ov, tz, multiPanel }: { ov: Overview; tz: string; multiPanel: boolean }) {
  return (
    <Card title={t('table.recent')} note="connection_count · accepted" className="h-full">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('table.recent')}</caption>
          <thead>
            <tr>
              <th scope="col" className={th}>{t('table.time')}</th>
              {multiPanel && <th scope="col" className={th}>{t('table.panel')}</th>}
              <th scope="col" className={th}>{t('table.node')}</th>
              <th scope="col" className={th}>{t('table.user')}</th>
              <th scope="col" className={th}>{t('table.proto')}</th>
              <th scope="col" className={th}>{t('table.dest')}</th>
            </tr>
          </thead>
          <tbody>
            {ov.recent.map((r, i) => (
              <tr key={`${r.ts}-${i}`} className="border-t border-line/60">
                <td className="tnum px-2 py-1.5 text-muted">{formatClock(r.ts, tz, true)}</td>
                {multiPanel && <td className="px-2 py-1.5 text-muted">{r.panel_name}</td>}
                <td className="px-2 py-1.5 text-muted">{r.node_name}</td>
                <td className={`px-2 py-1.5 ${r.user_label === 'система' ? 'text-muted' : 'text-fg'}`}>{r.user_label === 'система' ? t('table.system') : r.user_label}</td>
                <td className="px-2 py-1.5 font-medium uppercase text-fg/90">{r.protocol}</td>
                <td className="max-w-[220px] truncate px-2 py-1.5 text-fg" title={r.dest}>
                  <span className="mr-1.5 inline-block align-[-2px] text-muted">{r.dest_type === 'ip' ? <Network size={13} aria-label="IP" /> : <Globe2 size={13} aria-label="домен" />}</span>
                  {r.dest}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

/** Honest placeholder: no country numbers until a trustworthy GeoIP source exists. */
export function CountriesPlaceholder() {
  return (
    <Card title={t('table.countries')} className="h-full">
      <div className="flex h-full min-h-[150px] flex-col items-start justify-center gap-3">
        <Chip icon={Globe2}>{t('nav.soon')}</Chip>
        <p className="text-[13px] leading-5 text-muted">{t('countries.empty')}</p>
      </div>
    </Card>
  )
}
