import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { formatBytes, formatDateTime } from '../lib/format'
import type { DockerContainer, DockerInfo } from '../lib/types'
import { Card } from './ui'
import { durationText } from './ServerParts'

const GOOD = new Set(['running'])
const STOPPED = new Set(['exited', 'dead', 'created'])

function stateText(c: DockerContainer): string {
  switch (c.state) {
    case 'running': return t('dk.state.running', { d: c.started ? durationText(c.started, null) : '' }).trim()
    case 'restarting': return t('dk.state.restarting', { n: c.restarts })
    case 'exited': return c.finished ? t('dk.state.exited', { d: durationText(c.finished, null) }) : t('dk.state.exitedNo')
    default: return t(`dk.state.${c.state}` as MsgKey)
  }
}

/** A container that keeps falling is the one to look at first: it is shown in amber, whatever its state says this second. */
function troubled(c: DockerContainer): boolean {
  return c.state === 'restarting' || c.restarts_1h >= 3 || (c.health === 'unhealthy')
}

function Tile({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className={`rounded-control border px-3 py-2.5 ${warn ? 'border-amber/40 bg-amber/10' : 'border-line bg-elevated'}`}>
      <div className={`text-xs ${warn ? 'text-amber' : 'text-muted'}`}>{label}</div>
      <div className={`tnum mt-0.5 text-[22px] font-medium ${warn ? 'text-amber' : ''}`}>{value}</div>
    </div>
  )
}

function Detail({ c }: { c: DockerContainer }) {
  const rows: [string, string][] = [
    [t('dk.d.image'), c.image],
    [t('dk.d.policy'), c.policy || '—'],
    [t('dk.d.restarts'), `${c.restarts}` + (c.restarts_1h > 0 ? ` (${t('dk.d.restarts1h')}: ${c.restarts_1h})` : '')],
  ]
  if (c.state !== 'running' && c.state !== 'created') rows.push([t('dk.d.exit'), String(c.exit ?? 0)])
  if (c.started) rows.push([t('dk.d.started'), formatDateTime(c.started, 'local')])
  if (c.finished) rows.push([t('dk.d.finished'), formatDateTime(c.finished, 'local')])
  if (c.health) rows.push([t('dk.d.health'), c.health === 'unhealthy' ? t('dk.unhealthy') : c.health])
  rows.push([t('dk.d.id'), c.id])
  return (
    <dl className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-[auto_1fr]">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-muted">{k}</dt>
          <dd className="tnum break-all">{v}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

/** The "Docker" tab of a Linux machine: what runs in containers and what does not. Only a view: nothing here starts or stops. */
export function DockerView({ info }: { info: DockerInfo | null | undefined }) {
  const [open, setOpen] = useState<string>('')
  if (!info) return <p className="text-[13px] text-muted">{t('dk.none')}</p>
  const list = info.containers
  const running = list.filter((c) => GOOD.has(c.state)).length
  const stopped = list.filter((c) => STOPPED.has(c.state)).length
  const trouble = list.filter(troubled).length
  const mem = list.reduce((n, c) => n + (c.mem ?? 0), 0)
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label={t('dk.running')} value={String(running)} />
        <Tile label={t('dk.stopped')} value={String(stopped)} />
        <Tile label={t('dk.restarting')} value={String(trouble)} warn={trouble > 0} />
        <Tile label={t('dk.mem')} value={formatBytes(mem)} />
      </div>
      <Card title="Docker" note={t('dk.note')}>
        {list.length === 0 ? <p className="py-3 text-[13px] text-muted">{t('dk.empty')}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead>
                <tr className="text-left text-xs text-muted">
                  <th scope="col" className="w-6 py-2" />
                  <th scope="col" className="py-2 pr-3 font-normal">{t('dk.col.name')}</th>
                  <th scope="col" className="pr-3 font-normal">{t('dk.col.image')}</th>
                  <th scope="col" className="pr-3 font-normal">{t('dk.col.state')}</th>
                  <th scope="col" className="pr-3 font-normal">{t('dk.col.cpu')}</th>
                  <th scope="col" className="pr-3 font-normal">{t('dk.col.mem')}</th>
                  <th scope="col" className="font-normal">{t('dk.col.ports')}</th>
                </tr>
              </thead>
              <tbody>
                {list.map((c) => {
                  const bad = troubled(c)
                  const isOpen = open === c.id
                  const tone = bad ? 'text-amber' : c.state === 'running' ? 'text-green' : 'text-muted'
                  return (
                    <Fragment key={c.id}>
                      <tr className={`cursor-pointer border-t border-line/60 hover:bg-elevated ${bad ? 'bg-amber/10' : ''}`} onClick={() => setOpen(isOpen ? '' : c.id)}>
                        <td className="py-2 text-muted">
                          <button type="button" aria-expanded={isOpen} aria-label={c.name} onClick={(e) => { e.stopPropagation(); setOpen(isOpen ? '' : c.id) }}>
                            {isOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
                          </button>
                        </td>
                        <td className="py-2 pr-3 font-medium">{c.name}</td>
                        <td className="max-w-[16rem] truncate pr-3 text-muted" title={c.image}>{c.image}</td>
                        <td className={`pr-3 ${tone}`}>{c.state === 'running' && !bad ? '● ' : bad ? '● ' : '○ '}{stateText(c)}</td>
                        <td className="tnum pr-3">{c.cpu != null ? `${c.cpu.toFixed(c.cpu < 10 ? 1 : 0)}%` : '—'}</td>
                        <td className="tnum pr-3">{c.mem ? formatBytes(c.mem) : '—'}</td>
                        <td className="tnum text-muted">{c.ports.length ? c.ports.join(', ') : '—'}</td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-elevated/50">
                          <td />
                          <td colSpan={6} className="pb-3 pt-1"><Detail c={c} /></td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
