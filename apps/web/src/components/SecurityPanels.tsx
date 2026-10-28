import { useState } from 'react'
import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { SecAgent, SecCategory, SecEvent, SecEventDetail, SecFwDiff, SecFwModel, SecFwSnapshot, SecJail, SecListener, SecOverview } from '../lib/types'
import { Card, Chip } from './ui'
import { CommandHistory, useBanControls } from './SecurityBan'
import { DangerButton, GhostButton, Modal, PrimaryButton } from './Modal'

type Tone = 'muted' | 'amber' | 'green' | 'red' | 'cyan'
const STATE_TONE: Record<string, Tone> = { ok: 'green', stale: 'amber', waiting: 'muted', agent_required: 'muted', not_installed: 'muted', stopped: 'amber', permission_denied: 'amber', unsupported: 'muted', error: 'red' }

function Code({ children }: { children: string }) {
  return <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-control border border-line bg-elevated p-3 font-mono text-[12px]">{children}</pre>
}

export function StateChip({ state }: { state: string }) {
  return <Chip tone={STATE_TONE[state] ?? 'muted'}>{t(`sec.state.${state}` as MsgKey)}</Chip>
}

/** A category's header: what state it is in and when the data was taken, so old data never looks current. */
function Freshness({ c }: { c: SecCategory<unknown> }) {
  return (
    <div className="mb-3 space-y-1 text-[13px]">
      <div className="flex flex-wrap items-center gap-3">
        <StateChip state={c.state} />
        {c.observed_at && <span className="tnum text-muted">{t('sec.observed')}: {formatDateTime(c.observed_at, 'local')}</span>}
      </div>
      {c.state === 'stale' && <p className="text-amber">{t('sec.staleHint')}</p>}
      {Math.abs(c.clock_skew_ms) > 120_000 && <p className="text-amber">{t('sec.skew', { n: Math.round(Math.abs(c.clock_skew_ms) / 1000) })}</p>}
    </div>
  )
}

function useCategory<T>(vpsId: string, cat: string) {
  return useLoad((s) => api.get<SecCategory<T>>(`/api/v1/security/vps/${vpsId}/${cat}`, s), [vpsId, cat], 15_000)
}

const hasData = (c: SecCategory<unknown>) => c.data != null && c.status === 'ok'

export function Fail2banTab({ vpsId }: { vpsId: string }) {
  const { data: c, error, reload } = useCategory<{ jails: SecJail[] }>(vpsId, 'fail2ban')
  const [changed, setChanged] = useState(0)
  const jails = c && hasData(c) ? c.data!.jails.map((j) => j.name) : []
  const { unban, form, dialog } = useBanControls(vpsId, c?.manage, jails, () => { setChanged((n) => n + 1); reload() })
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!c) return null
  return (
    <>
    <Card title="Fail2ban" note={t('sec.f2b.readonly')}>
      <Freshness c={c} />
      {hasData(c) && c.data!.jails.length === 0 && <p className="text-[13px] text-muted">{t('sec.f2b.noJails')}</p>}
      {hasData(c) && c.data!.jails.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-xs text-muted"><th className="py-2 pr-4 font-medium">{t('sec.f2b.jails')}</th><th className="pr-4 font-medium">{t('sec.f2b.failed')}</th><th className="pr-4 font-medium">{t('sec.f2b.banned')}</th><th className="font-medium">{t('sec.f2b.ips')}</th></tr></thead>
            <tbody>
              {c.data!.jails.map((j) => (
                <tr key={j.name} className="border-t border-line align-top">
                  <td className="py-2 pr-4 font-medium">{j.name}</td>
                  <td className="tnum pr-4">{j.currently_failed} / {j.total_failed}</td>
                  <td className="tnum pr-4">{j.currently_banned} / {j.total_banned}</td>
                  <td className="font-mono text-[12px]">
                    {j.banned_ips.length === 0 ? '—' : j.banned_ips.map((ip) => (
                      <span key={ip} className="mr-3 inline-block">
                        <Link to={`/intel?target=${encodeURIComponent(ip)}`} title={t('sec.openIntel')} className="hover:text-cyan hover:underline">{ip}</Link>
                        {unban(j.name, ip)}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {hasData(c) && form}
    </Card>
    <CommandHistory vpsId={vpsId} refreshKey={changed} />
    {dialog}
    </>
  )
}

function scope(addr: string): MsgKey {
  if (addr === '0.0.0.0' || addr === '::') return 'sec.ports.scope.all'
  if (addr.startsWith('127.') || addr === '::1') return 'sec.ports.scope.loopback'
  return 'sec.ports.scope.one'
}

export function PortsTab({ vpsId }: { vpsId: string }) {
  const { data: c, error } = useCategory<{ listeners: SecListener[]; process_info: boolean }>(vpsId, 'ports')
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!c) return null
  return (
    <Card title={t('sec.ports.title')} note={t('sec.ports.hint')}>
      <Freshness c={c} />
      {hasData(c) && !c.data!.process_info && <p className="mb-3 text-[13px] text-muted">{t('sec.ports.noProc')}</p>}
      {hasData(c) && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-xs text-muted"><th className="py-2 pr-4 font-medium">{t('sec.ports.proto')}</th><th className="pr-4 font-medium">{t('sec.ports.addr')}</th><th className="pr-4 font-medium">{t('sec.ports.port')}</th><th className="font-medium">{t('sec.ports.process')}</th></tr></thead>
            <tbody>
              {c.data!.listeners.map((l) => (
                <tr key={`${l.proto}|${l.addr}|${l.port}`} className="border-t border-line">
                  <td className="py-2 pr-4 uppercase">{l.proto}</td>
                  <td className="pr-4 font-mono text-[12px]">{l.addr} <span className="font-sans text-muted">· {t(scope(l.addr))}</span></td>
                  <td className="tnum pr-4">{l.port}</td>
                  <td>{l.process ? `${l.process}${l.pid ? ` (${l.pid})` : ''}` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function FwStructure({ m }: { m: SecFwModel }) {
  const chains = m.tables.reduce((n, x) => n + x.chains.length, 0)
  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">{t('sec.fw.summary', { tables: m.tables.length, chains, rules: m.rules })}</p>
      {m.tables.map((tb) => (
        <div key={`${tb.family}|${tb.name}`} className="rounded-control border border-line">
          <div className="border-b border-line bg-elevated px-3 py-2 text-[13px] font-medium">{tb.family} {tb.name}</div>
          <div className="space-y-3 p-3">
            {tb.chains.map((c) => (
              <div key={c.name}>
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <span className="font-mono font-medium">{c.name}</span>
                  {c.hook && <Chip tone="cyan">{c.hook}{c.priority ? ` ${c.priority}` : ''}</Chip>}
                  {c.policy && <Chip tone={c.policy === 'drop' ? 'amber' : 'muted'}>{t('sec.fw.policy')} {c.policy}</Chip>}
                </div>
                {c.rules.length === 0 ? <p className="mt-1 text-[12px] text-muted">{t('sec.fw.noRules')}</p> : (
                  <pre className="mt-1 max-h-[260px] overflow-auto whitespace-pre-wrap break-all font-mono text-[12px] leading-5">{c.rules.join('\n')}</pre>
                )}
              </div>
            ))}
            {tb.other && tb.other.length > 0 && <p className="text-[12px] text-muted">{t('sec.fw.other')}: {tb.other.join(', ')}</p>}
          </div>
        </div>
      ))}
    </div>
  )
}

const OP_CLASS: Record<string, string> = { '+': 'bg-green/10 text-green', '-': 'bg-red/10 text-red', '…': 'text-muted' }

function FwChanges({ vpsId }: { vpsId: string }) {
  const diff = useLoad((s) => api.get<SecFwDiff>(`/api/v1/security/vps/${vpsId}/firewall/diff`, s), [vpsId], 30_000)
  const hist = useLoad((s) => api.get<{ items: SecFwSnapshot[] }>(`/api/v1/security/vps/${vpsId}/firewall/history?limit=15`, s), [vpsId], 30_000)
  const d = diff.data
  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">{t('sec.fw.diff.hint')}</p>
      {diff.error && <p role="alert" className="text-[13px] text-red">{diff.error}</p>}
      {d && !d.available && <p className="text-[13px] text-muted">{d.reason === 'a_reading_was_incomplete' ? t('sec.fw.diff.incomplete') : t('sec.fw.diff.none')}</p>}
      {d?.available && (
        <>
          <p className="tnum text-[13px] text-muted">{t('sec.fw.diff.range', { from: formatDateTime(d.from!.observed_at, 'local'), to: formatDateTime(d.to!.observed_at, 'local') })}</p>
          {d.backend_changed && <p className="text-[13px] text-amber">{t('sec.fw.diff.backend')}</p>}
          {(d.lines ?? []).length === 0 ? <p className="text-[13px]">{t('sec.fw.diff.same')}</p> : (
            <>
              <p className="text-[13px]">{t('sec.fw.diff.counts', { added: d.added ?? 0, removed: d.removed ?? 0 })}</p>
              <pre className="max-h-[420px] overflow-auto rounded-control border border-line bg-elevated p-3 font-mono text-[12px] leading-5">
                {d.lines!.map((l, i) => (
                  <div key={i} className={OP_CLASS[l.op] ?? ''}>{l.op === '…' ? '…' : `${l.op} ${l.text.replace(/^\t+/, (x) => '  '.repeat(x.length))}`}</div>
                ))}
              </pre>
              {d.truncated && <p className="text-[13px] text-amber">{t('sec.fw.diff.truncated')}</p>}
            </>
          )}
        </>
      )}
      <div>
        <h3 className="mb-1 text-[13px] font-medium">{t('sec.fw.history')}</h3>
        {hist.data && hist.data.items.length === 0 && <p className="text-[13px] text-muted">{t('sec.fw.history.none')}</p>}
        <ul className="space-y-1 text-[13px]">
          {(hist.data?.items ?? []).map((x) => (
            <li key={x.id} className="flex flex-wrap items-center gap-3">
              <span className="tnum text-muted">{formatDateTime(x.observed_at, 'local')}</span>
              <span className="font-mono text-[12px] text-muted">{x.hash.slice(0, 8)}</span>
              {x.status !== 'ok' && <StateChip state={x.status} />}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

export function FirewallTab({ vpsId }: { vpsId: string }) {
  const { data: c, error } = useCategory<{ backend: string; rules: string; truncated?: boolean }>(vpsId, 'firewall')
  const [view, setView] = useState<'structure' | 'changes' | 'raw'>('structure')
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!c) return null
  const model = hasData(c) ? c.model : undefined
  const views: ('structure' | 'changes' | 'raw')[] = ['structure', 'changes', 'raw']
  return (
    <Card title="Firewall" note={t('sec.fw.hint')}>
      <Freshness c={c} />
      {hasData(c) && (
        <>
          <p className="mb-3 text-[13px] text-muted">{t('sec.fw.backend')}: <span className="text-fg">{c.data!.backend}</span></p>
          <div role="tablist" className="mb-3 flex gap-2 text-[13px]">
            {views.map((v) => (
              <button key={v} role="tab" aria-selected={view === v} onClick={() => setView(v)}
                className={`rounded-control border px-3 py-1 ${view === v ? 'border-cyan text-cyan' : 'border-line text-muted hover:text-fg'}`}>
                {t(`sec.fw.${v}` as MsgKey)}
              </button>
            ))}
          </div>
          {view === 'structure' && (model && model.tables.length > 0 ? <FwStructure m={model} /> : (
            <>
              <p className="mb-2 text-[13px] text-muted">{c.data!.rules === '' ? t('sec.fw.empty') : t('sec.fw.noModel')}</p>
              {c.data!.rules !== '' && <Code>{c.data!.rules}</Code>}
            </>
          ))}
          {view === 'changes' && <FwChanges vpsId={vpsId} />}
          {view === 'raw' && (c.data!.rules === '' ? <p className="text-[13px] text-muted">{t('sec.fw.empty')}</p> : (
            <pre className="max-h-[480px] overflow-auto rounded-control border border-line bg-elevated p-3 font-mono text-[12px] leading-5">{c.data!.rules}</pre>
          ))}
          {c.data!.truncated && <p className="mt-2 text-[13px] text-amber">{t('sec.fw.truncated')}</p>}
        </>
      )}
    </Card>
  )
}

export function eventText(e: SecEvent): string {
  const key = (e.type.endsWith('.state_changed') ? 'sec.ev.state_changed' : `sec.ev.${e.type}`) as MsgKey
  const p: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(e.payload)) if (typeof v === 'string' || typeof v === 'number') p[k] = v
  try {
    return t(key, p)
  } catch {
    return e.type
  }
}

const SEV_TONE = { info: 'muted', warning: 'amber', critical: 'red' } as const

/** An event's text that opens its detail: the full payload and what else happened around it. */
export function EventLink({ e, className = '' }: { e: SecEvent; className?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" title={t('sec.ev.open')} onClick={() => setOpen(true)} className={`text-left hover:text-cyan hover:underline ${className}`}>{eventText(e)}</button>
      {open && <EventDetail id={e.id} onClose={() => setOpen(false)} />}
    </>
  )
}

function Payload({ p }: { p: Record<string, unknown> }) {
  const rows = Object.entries(p)
  if (rows.length === 0) return <p className="text-[13px] text-muted">—</p>
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="break-all font-mono text-[12px]">{typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v)}</dd>
        </div>
      ))}
    </dl>
  )
}

export function EventDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useLoad((s) => api.get<SecEventDetail>(`/api/v1/security/events/${id}`, s), [id])
  return (
    <Modal title={t('sec.ev.detail')} onClose={onClose}>
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {data && (
        <div className="space-y-4">
          <div>
            <p className="text-[14px]"><Chip tone={SEV_TONE[data.event.severity]}>{t(`sec.sev.${data.event.severity}` as MsgKey)}</Chip> <span className="ml-2">{eventText(data.event)}</span></p>
            <p className="mt-1 text-[12px] text-muted">
              {t('sec.ev.server')}: <Link to={`/security/${data.event.vps_id}`} className="hover:text-cyan hover:underline">{data.event.vps_name}</Link>
              {' · '}{t('sec.ev.time')}: <span className="tnum">{formatDateTime(data.event.observed_at, 'local')}</span>
              {' · '}{t('sec.ev.source')}: {t(data.event.source === 'external_check' ? 'sec.ext.source' : 'sec.events.source')}
            </p>
          </div>
          <div>
            <h3 className="mb-1 text-[13px] font-medium">{t('sec.ev.details')}</h3>
            <Payload p={data.event.payload} />
          </div>
          <div>
            <h3 className="mb-1 text-[13px] font-medium">{t('sec.ev.related')}</h3>
            {data.related.length === 0 ? <p className="text-[13px] text-muted">{t('sec.ev.noRelated')}</p> : (
              <ul className="space-y-1 text-[13px]">
                {data.related.map((r) => (
                  <li key={r.id} className="flex flex-wrap items-baseline gap-2">
                    <span className="tnum text-xs text-muted">{formatDateTime(r.observed_at, 'local')}</span>
                    <Chip tone={SEV_TONE[r.severity]}>{t(`sec.sev.${r.severity}` as MsgKey)}</Chip>
                    <span>{eventText(r)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </Modal>
  )
}

const HEALTH_TONE = { healthy: 'green', attention: 'amber', unknown: 'muted', disabled: 'muted' } as const

function reasonText(r: { code: string; detail?: string }): string {
  try {
    return t(`sec.ov.reason.${r.code}` as MsgKey, { name: r.detail ? t(`sec.ov.coverage.${r.detail === 'sockets' ? 'ports' : r.detail}` as MsgKey) : '' })
  } catch {
    return r.code
  }
}

export function OverviewTab({ vpsId }: { vpsId: string }) {
  const { data: o, error } = useLoad((s) => api.get<SecOverview>(`/api/v1/security/vps/${vpsId}/overview`, s), [vpsId], 15_000)
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!o) return null
  const hint = o.health === 'healthy' ? 'sec.ov.healthyHint' : o.health === 'unknown' ? 'sec.ov.unknownHint' : o.health === 'disabled' ? 'sec.ov.disabledHint' : null
  const c = o.checks
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title={t(`sec.ov.health.${o.health}` as MsgKey)}>
        <div className="mb-3"><Chip tone={HEALTH_TONE[o.health]}>{t(`sec.ov.health.${o.health}` as MsgKey)}</Chip></div>
        {hint && <p className="text-[13px] text-muted">{t(hint as MsgKey)}</p>}
        {o.reasons.length > 0 && (
          <ul className="list-disc space-y-1 pl-5 text-[13px]">{o.reasons.map((r, i) => <li key={i}>{reasonText(r)}</li>)}</ul>
        )}
      </Card>
      <Card title={t('sec.ov.coverage')}>
        <dl className="space-y-2 text-[13px]">
          <div><dt className="text-muted">{t('sec.ov.coverage.agent')}</dt><dd>{t(`sec.card.agent.${o.agent}` as MsgKey)}</dd></div>
          {(['fail2ban', 'sockets', 'firewall'] as const).map((k) => (
            <div key={k}>
              <dt className="text-muted">{k === 'sockets' ? t('sec.ports') : k === 'fail2ban' ? 'Fail2ban' : 'Firewall'}</dt>
              <dd className="flex flex-wrap items-center gap-2"><StateChip state={o.categories[k]?.state ?? 'waiting'} />
                {o.categories[k]?.observed_at && <span className="tnum text-xs text-muted">{formatDateTime(o.categories[k].observed_at, 'local')}</span>}</dd>
            </div>
          ))}
          <div><dt className="text-muted">{t('sec.ov.coverage.ports')}</dt>
            <dd>{c.ports_total === 0 ? t('sec.ov.coverage.none') : t('sec.ov.coverage.portsLine', { n: c.ports_total, u: c.ports_unexpected, d: c.ports_down })}</dd></div>
          <div><dt className="text-muted">{t('sec.ov.coverage.tls')}</dt>
            <dd>{c.tls_total === 0 ? t('sec.ov.coverage.none') : t('sec.ov.coverage.tlsLine', { n: c.tls_total, p: c.tls_problems })}</dd></div>
          {c.tls_nearest_end && <div><dt className="text-muted">{t('sec.ov.nearestEnd')}</dt><dd className="tnum">{formatDateTime(c.tls_nearest_end, 'local')}</dd></div>}
          {c.last_checked_at && <div><dt className="text-muted">{t('sec.ov.lastCheck')}</dt><dd className="tnum">{formatDateTime(c.last_checked_at, 'local')}</dd></div>}
        </dl>
      </Card>
      <Card title={t('sec.tab.events')}>
        <p className="mb-2 text-[13px] text-muted">{t('sec.ov.events24h')}: <span className="text-fg">{o.events_24h}</span></p>
        {o.last_event ? (
          <p className="text-[13px]"><span className="text-muted">{t('sec.ov.lastEvent')}:</span> <EventLink e={o.last_event} />
            <span className="tnum ml-2 text-xs text-muted">{formatDateTime(o.last_event.observed_at, 'local')}</span></p>
        ) : <p className="text-[13px] text-muted">{t('sec.ov.noEvents')}</p>}
      </Card>
    </div>
  )
}

export function EventsTab({ vpsId }: { vpsId: string }) {
  const [extra, setExtra] = useState<SecEvent[]>([])
  const [more, setMore] = useState<boolean | null>(null)
  const [err, setErr] = useState('')
  const first = useLoad((s) => api.get<{ items: SecEvent[]; more: boolean }>(`/api/v1/security/vps/${vpsId}/events?limit=50`, s), [vpsId], 15_000)
  const items = [...(first.data?.items ?? []), ...extra]
  const hasMore = more ?? first.data?.more ?? false
  async function loadMore() {
    const last = items[items.length - 1]
    try {
      const r = await api.get<{ items: SecEvent[]; more: boolean }>(`/api/v1/security/vps/${vpsId}/events?limit=50&before_ts=${encodeURIComponent(last.observed_at)}&before_id=${last.id}`)
      setExtra((x) => [...x, ...r.items])
      setMore(r.more)
    } catch (e) {
      setErr(errorText(e))
    }
  }
  if (first.error) return <p role="alert" className="text-[13px] text-red">{first.error}</p>
  if (!first.data) return null
  return (
    <Card title={t('sec.tab.events')}>
      {items.length === 0 && <p className="text-[13px] text-muted">{t('sec.events.none')}</p>}
      <ul className="divide-y divide-line">
        {items.map((e) => (
          <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-3 py-2 text-[13px]">
            <span><Chip tone={e.severity === 'info' ? 'muted' : e.severity === 'warning' ? 'amber' : 'red'}>{t(`sec.sev.${e.severity}` as MsgKey)}</Chip> <EventLink e={e} className="ml-2" /></span>
            <span className="tnum text-xs text-muted">{formatDateTime(e.observed_at, 'local')} · {t(e.source === 'external_check' ? 'sec.ext.source' : 'sec.events.source')}</span>
          </li>
        ))}
      </ul>
      {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
      {hasMore && <div className="mt-3"><GhostButton onClick={() => void loadMore()}>{t('sec.events.more')}</GhostButton></div>}
    </Card>
  )
}

export function AgentCard({ vpsId, canEdit }: { vpsId: string; canEdit: boolean }) {
  const { data, error, reload } = useLoad((s) => api.get<{ agent: SecAgent | null }>(`/api/v1/security/vps/${vpsId}/agent`, s), [vpsId], 15_000)
  const [token, setToken] = useState('')
  const [os, setOS] = useState<'linux' | 'windows'>('linux')
  const [shell, setShell] = useState(true)
  const [desk, setDesk] = useState(true)
  const [scr, setScr] = useState(false)
  const [err, setErr] = useState('')
  const [confirm, setConfirm] = useState(false)
  const agent = data?.agent ?? null
  async function create() {
    setErr('')
    try {
      const r = await api.post<{ token: string }>(`/api/v1/security/vps/${vpsId}/agent`)
      setToken(r.token)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  async function revoke() {
    setConfirm(false)
    setErr('')
    try {
      await api.del(`/api/v1/security/vps/${vpsId}/agent`)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <Card title={t('sec.agent')} note={t('sec.agent.onlyConn')}>
      {(error || err) && <p role="alert" className="mb-2 text-[13px] text-red">{error || err}</p>}
      {data && !agent && <p className="text-[13px] text-muted">{t('sec.agent.none')}</p>}
      {agent && (
        <div className="space-y-1 text-[13px]">
          <div className="flex flex-wrap items-center gap-3">
            <Chip tone={agent.online ? 'green' : 'muted'}>{agent.last_seen ? (agent.online ? t('sec.agent.online') : t('sec.agent.offline')) : t('sec.agent.waiting')}</Chip>
            {agent.agent_version && <span className="text-muted">v{agent.agent_version}{agent.hostname ? ` · ${agent.hostname}` : ''}</span>}
          </div>
          {agent.last_seen && <p className="tnum text-muted">{t('sec.agent.lastSeen')}: {formatDateTime(agent.last_seen, 'local')}</p>}
        </div>
      )}
      {canEdit && data && (
        <div className="mt-3 flex gap-3">
          {!agent && <PrimaryButton onClick={() => void create()}>{t('sec.agent.create')}</PrimaryButton>}
          {agent && <GhostButton onClick={() => setConfirm(true)}>{t('sec.agent.revoke')}</GhostButton>}
        </div>
      )}
      {token && (
        <Modal title={t('sec.onb.title')} onClose={() => setToken('')} wide>
          <div className="space-y-3 text-[13px]">
            <div role="tablist" aria-label={t('sec.onb.os')} className="flex gap-2">
              {(['linux', 'windows'] as const).map((x) => (
                <button key={x} role="tab" type="button" aria-selected={os === x} onClick={() => setOS(x)}
                  className={`h-8 rounded-control border px-3 text-[13px] ${os === x ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{x === 'linux' ? 'Linux' : 'Windows'}</button>
              ))}
            </div>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" checked={shell} onChange={(e) => setShell(e.target.checked)} />
              <span>{t('sec.onb.shell')}</span>
            </label>
            <p className="-mt-2 text-xs text-muted">{t('sec.onb.shellHint')}</p>
            {os === 'windows' ? (
              <>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="checkbox" checked={desk} onChange={(e) => setDesk(e.target.checked)} />
                  <span>{t('sec.onb.desk')}</span>
                </label>
                <p className="-mt-2 text-xs text-muted">{t('sec.onb.deskHint')}</p>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="checkbox" checked={scr} onChange={(e) => setScr(e.target.checked)} />
                  <span>{t('sec.onb.screen')}</span>
                </label>
                <p className="-mt-2 text-xs text-muted">{t('sec.onb.screenHint')}</p>
                <p className="text-muted">{t('sec.onb.win.intro')}</p>
                <p>{t('sec.onb.win.s1')}</p>
                <Code>{`$ErrorActionPreference = 'Stop'
$d = "$env:ProgramData\\Owlery"
New-Item -ItemType Directory -Force $d | Out-Null
if (Get-Service OwlerySecAgent -ErrorAction SilentlyContinue) { & "$d\\secagent.exe" uninstall | Out-Null }
Set-Content -Path "$d\\secagent.token" -Value '${token}' -NoNewline -Encoding ascii
icacls "$d\\secagent.token" /inheritance:r /grant:r "*S-1-5-18:R" "*S-1-5-32-544:F" | Out-Null
$a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Invoke-WebRequest "https://github.com/Taminum/Owlery/releases/latest/download/remnascope-secagent-windows-$a.exe" -OutFile "$d\\secagent.exe" -UseBasicParsing
& "$d\\secagent.exe" install -server "wss://${window.location.host}" -token-file "$d\\secagent.token"${shell ? ' -allow-shell' : ''}${desk ? ' -allow-desktop' : ''}${scr ? ' -allow-screen' : ''}${scr ? `
Invoke-WebRequest "https://github.com/Taminum/Owlery/releases/latest/download/owlery-remote-windows-$a.exe" -OutFile "$d\\owlery-remote.exe" -UseBasicParsing
Invoke-WebRequest "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip" -OutFile "$d\\ffmpeg.zip" -UseBasicParsing
Expand-Archive "$d\\ffmpeg.zip" -DestinationPath "$d\\ffmpeg-tmp" -Force
Copy-Item (Get-ChildItem "$d\\ffmpeg-tmp" -Recurse -Filter ffmpeg.exe | Select-Object -First 1).FullName "$d\\ffmpeg.exe" -Force
Remove-Item "$d\\ffmpeg.zip", "$d\\ffmpeg-tmp" -Recurse -Force
& "$d\\owlery-remote.exe" install` : ''}`}</Code>
                <p>{t('sec.onb.win.s2')}</p>
                <Code>{`Get-Service OwlerySecAgent
Get-Content "$env:ProgramData\\Owlery\\secagent.log" -Tail 5`}</Code>
                <p className="text-muted">{t('sec.onb.win.done')}</p>
              </>
            ) : (<>
            <p className="text-muted">{t('sec.onb.intro')}</p>
            <p>{t('sec.onb.s1')}</p>
            <Code>{'useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-sec\nuseradd --system --no-create-home --shell /usr/sbin/nologin remnascope-f2b'}</Code>
            <p>{t('sec.onb.s2')}</p>
            <Code>{`install -d -m 0755 /etc/remnascope && umask 077 && echo '${token}' > /etc/remnascope/secagent.token && chown root:remnascope-sec /etc/remnascope/secagent.token && chmod 0640 /etc/remnascope/secagent.token`}</Code>
            <p>{t('sec.onb.s3')}</p>
            <Code>{`cd /tmp
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64) A=arm64 ;; *) echo "unsupported processor"; exit 1 ;; esac
curl -fLO https://github.com/Taminum/Owlery/releases/latest/download/remnascope-secagent-linux-$A
curl -fLO https://github.com/Taminum/Owlery/releases/latest/download/remnascope-deploy-files.tar.gz
tar -xzf remnascope-deploy-files.tar.gz`}</Code>
            <p>{t('sec.onb.s4')}</p>
            <Code>{`install -m 0755 remnascope-secagent-linux-$A /usr/local/bin/remnascope-secagent
sed 's#wss://SCOPE_HOST#wss://${window.location.host}#' deploy/secagent/remnascope-secagent.service > /etc/systemd/system/remnascope-secagent.service
cp deploy/secagent/remnascope-secagent-f2b.service /etc/systemd/system/`}</Code>
            <p>{t('sec.onb.s5')}</p>
            <Code>{`mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/remnascope.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/fail2ban/fail2ban.sock ] && break; sleep 1; done; chgrp remnascope-f2b /run/fail2ban/fail2ban.sock && chmod 0660 /run/fail2ban/fail2ban.sock"
EOF
systemctl daemon-reload && systemctl restart fail2ban
systemctl enable --now remnascope-secagent-f2b remnascope-secagent`}</Code>
            <p className="text-muted">{t('sec.onb.s5hint')}</p>
            {shell && (
              <>
                <p>{t('sec.onb.shellStep')}</p>
                <Code>{`sed 's#wss://SCOPE_HOST#wss://${window.location.host}#' deploy/secagent/remnascope-shell.service > /etc/systemd/system/remnascope-shell.service
systemctl daemon-reload && systemctl enable --now remnascope-shell && systemctl restart remnascope-secagent`}</Code>
              </>
            )}
            <p>{t('sec.onb.s6')}</p>
            <Code>{`install -m 0755 deploy/secagent/remnascope-containers-list /usr/local/sbin/
cp deploy/secagent/remnascope-containers-list.service deploy/secagent/remnascope-containers-list.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now remnascope-containers-list.timer`}</Code>
            <p>{t('sec.onb.s7')}</p>
            <Code>{`systemctl is-active remnascope-secagent
journalctl -u remnascope-secagent -n 5 --no-pager`}</Code>
            <p className="text-muted">{t('sec.onb.done')}</p>
            </>)}
          </div>
          <div className="mt-4 flex justify-end"><PrimaryButton onClick={() => setToken('')}>{t('sec.agent.tokenSaved')}</PrimaryButton></div>
        </Modal>
      )}
      {confirm && (
        <Modal title={t('sec.agent.revoke')} onClose={() => setConfirm(false)}>
          <div className="flex justify-end gap-3">
            <GhostButton onClick={() => setConfirm(false)}>{t('common.cancel')}</GhostButton>
            <DangerButton onClick={() => void revoke()}>{t('sec.agent.revoke')}</DangerButton>
          </div>
        </Modal>
      )}
    </Card>
  )
}
