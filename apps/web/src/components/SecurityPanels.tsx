import { useState } from 'react'
import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { SecAgent, SecCategory, SecEvent, SecJail, SecListener } from '../lib/types'
import { Card, Chip } from './ui'
import { DangerButton, GhostButton, Modal, PrimaryButton } from './Modal'

type Tone = 'muted' | 'amber' | 'green' | 'red' | 'cyan'
const STATE_TONE: Record<string, Tone> = { ok: 'green', stale: 'amber', waiting: 'muted', agent_required: 'muted', not_installed: 'muted', stopped: 'amber', permission_denied: 'amber', unsupported: 'muted', error: 'red' }

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
  const { data: c, error } = useCategory<{ jails: SecJail[] }>(vpsId, 'fail2ban')
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!c) return null
  return (
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
                      <Link key={ip} to={`/intel?target=${encodeURIComponent(ip)}`} title={t('sec.openIntel')} className="mr-3 inline-block hover:text-cyan hover:underline">{ip}</Link>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
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

export function FirewallTab({ vpsId }: { vpsId: string }) {
  const { data: c, error } = useCategory<{ backend: string; rules: string; truncated?: boolean }>(vpsId, 'firewall')
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!c) return null
  return (
    <Card title="Firewall" note={t('sec.fw.hint')}>
      <Freshness c={c} />
      {hasData(c) && (
        <>
          <p className="mb-2 text-[13px] text-muted">{t('sec.fw.backend')}: <span className="text-fg">{c.data!.backend}</span></p>
          {c.data!.rules === '' ? <p className="text-[13px] text-muted">{t('sec.fw.empty')}</p> : (
            <pre className="max-h-[480px] overflow-auto rounded-control border border-line bg-elevated p-3 font-mono text-[12px] leading-5">{c.data!.rules}</pre>
          )}
          {c.data!.truncated && <p className="mt-2 text-[13px] text-amber">{t('sec.fw.truncated')}</p>}
        </>
      )}
    </Card>
  )
}

function eventText(e: SecEvent): string {
  const key = (e.type.endsWith('.state_changed') ? 'sec.ev.state_changed' : `sec.ev.${e.type}`) as MsgKey
  const p: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(e.payload)) if (typeof v === 'string' || typeof v === 'number') p[k] = v
  try {
    return t(key, p)
  } catch {
    return e.type
  }
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
            <span><Chip tone={e.severity === 'info' ? 'muted' : e.severity === 'warning' ? 'amber' : 'red'}>{t(`sec.sev.${e.severity}` as MsgKey)}</Chip> <span className="ml-2">{eventText(e)}</span></span>
            <span className="tnum text-xs text-muted">{formatDateTime(e.observed_at, 'local')} · {t('sec.events.source')}</span>
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
        <Modal title={t('sec.agent.create')} onClose={() => setToken('')}>
          <p className="text-[13px] text-muted">{t('sec.agent.token')}</p>
          <pre className="mt-2 overflow-x-auto rounded-control border border-line bg-elevated p-3 font-mono text-[12px]">{token}</pre>
          <pre className="mt-2 overflow-x-auto rounded-control border border-line bg-elevated p-3 font-mono text-[12px]">{`secagent -server wss://${window.location.host} -token-file /etc/remnascope/secagent.token`}</pre>
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
