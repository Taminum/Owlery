import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { can, useAuth } from '../lib/auth'
import { errorText } from '../lib/errors'
import { formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { Agent, PanelDTO } from '../lib/types'
import { Chip } from './ui'
import { DangerButton, GhostButton, Modal, PrimaryButton } from './Modal'

type PanelNode = { id: string; name: string }
const STALE_MS = 2 * 60 * 1000

function state(a: Agent | undefined, now: number) {
  if (!a) return <Chip>{t('agents.none')}</Chip>
  if (a.status === 'enrolling') return <Chip tone="amber">{t('agents.waiting')}</Chip>
  const seen = a.last_seen ? now - new Date(a.last_seen).getTime() : Infinity
  return seen > STALE_MS ? <Chip tone="amber">{t('agents.stale')}</Chip> : <Chip tone="green">{t('agents.live')}</Chip>
}

const bytes = (n: number) => (n < 1024 ? `${n} Б` : n < 1048576 ? `${(n / 1024).toFixed(0)} КБ` : `${(n / 1048576).toFixed(1)} МБ`)

export function AgentsDialog({ panel, tz, onClose }: { panel: PanelDTO; tz: string; onClose: () => void }) {
  const { state: auth } = useAuth()
  const nodes = useLoad((s) => api.get<{ nodes: PanelNode[] }>(`/api/v1/panels/${panel.id}/nodes`, s), [panel.id])
  const agents = useLoad((s) => api.get<{ agents: Agent[]; ingest_path: string }>(`/api/v1/panels/${panel.id}/agents`, s), [panel.id], 10000)
  const [issued, setIssued] = useState<{ node: string; token: string; path: string; kind: 'node' | 'router' | 'awg' } | null>(null)
  const [revoking, setRevoking] = useState<Agent | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [now] = useState(() => Date.now())
  const [coversUser, setCoversUser] = useState('')
  const [awgNode, setAwgNode] = useState('')
  if (auth.status !== 'authed') return null
  const admin = can(auth.me, panel.id, 'admin')
  const nodeAgents = (agents.data?.agents ?? []).filter((a) => a.kind !== 'router' && a.kind !== 'awg')
  const routerAgents = (agents.data?.agents ?? []).filter((a) => a.kind === 'router')
  const awgAgents = (agents.data?.agents ?? []).filter((a) => a.kind === 'awg')
  // Nodes that have no live AmneziaWG agent yet.
  const awgFree = (nodes.data?.nodes ?? []).filter((n) => !awgAgents.some((a) => a.node_id === n.id && a.status !== 'revoked'))
  const byNode = new Map(nodeAgents.map((a) => [a.node_id, a]))

  async function enroll(n: PanelNode, kind: 'node' | 'router' | 'awg' = 'node') {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ token: string; ingest_path: string }>(`/api/v1/panels/${panel.id}/agents`, { node_id: n.id, name: kind === 'router' ? 'OpenWrt' : kind === 'awg' ? `awg-${n.name}` : n.name, kind, ...(kind === 'router' && coversUser.trim() ? { covers_user: coversUser.trim() } : {}) })
      setIssued({ node: n.name, token: r.token, path: r.ingest_path, kind })
      agents.reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  async function revoke(a: Agent) {
    setBusy(true)
    setError('')
    try {
      await api.del(`/api/v1/panels/${panel.id}/agents/${a.id}`)
      setRevoking(null)
      agents.reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (issued) {
    const host = window.location.host
    return (
      <Modal title={issued.kind === 'router' ? t('agents.tokenTitleRouter') : issued.kind === 'awg' ? t('agents.tokenTitleAwg') : t('agents.tokenTitle', { node: issued.node })} onClose={() => setIssued(null)} wide>
        <div className="space-y-4">
          <p role="alert" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{t('agents.tokenWarn')}</p>
          <div>
            <div className="mb-1 text-[13px] font-medium">{t('agents.tokenLabel')}</div>
            <div className="flex gap-2">
              <input readOnly aria-label={t('agents.tokenLabel')} value={issued.token} onFocus={(e) => e.currentTarget.select()}
                className="h-10 min-w-0 flex-1 rounded-control border border-line bg-canvas px-3 font-mono text-[12px]" data-autofocus />
              <GhostButton onClick={() => void navigator.clipboard?.writeText(issued.token).then(() => setCopied(true))}>
                <span className="inline-flex items-center gap-2">{copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}{copied ? t('agents.copied') : t('agents.copy')}</span>
              </GhostButton>
            </div>
          </div>
          <div>
            {issued.kind === 'awg' ? <p className="text-[13px] text-muted">{t('agents.awgRun')}</p> : <><div className="mb-1 text-[13px] font-medium">{issued.kind === 'router' ? t('agents.runRouter') : t('agents.run')}</div>
            <pre className="overflow-x-auto rounded-control border border-line bg-canvas p-3 text-[12px] leading-5">{`remnascope-agent \\
  -server wss://${host}${issued.path} \\
  -token-file /etc/remnascope/agent.token \\
  -state-dir ${issued.kind === 'router' ? '/tmp/remnascope-agent' : '/var/lib/remnascope-agent'} \\
  ${issued.kind === 'router' ? '-clash-url http://192.168.1.1:9090 -leases-file /tmp/dhcp.leases -spool-max-mb 2' : '-exec "/usr/bin/docker exec remnanode tail -n 0 -F /var/log/xray/current"'}`}</pre></>}
          </div>
          <div className="flex justify-end"><PrimaryButton onClick={() => setIssued(null)}>{t('agents.done')}</PrimaryButton></div>
        </div>
      </Modal>
    )
  }

  return (
    <Modal title={`${t('agents.title')}: ${panel.name}`} onClose={onClose} wide busy={busy}>
      <div className="space-y-4">
        <p className="text-[13px] text-muted">{t('agents.intro')}</p>
        {(error || agents.error || nodes.error) && <p role="alert" className="text-[13px] text-red">{error || agents.error || nodes.error}</p>}
        {nodes.data && nodes.data.nodes.length === 0 && <p className="text-[13px] text-muted">{t('agents.noNodes')}</p>}
        {nodes.data && nodes.data.nodes.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('agents.title')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="py-2 pr-3 font-medium">{t('agents.node')}</th>
                <th scope="col" className="py-2 pr-3 font-medium">{t('agents.state')}</th>
                <th scope="col" className="py-2 pr-3 font-medium">{t('agents.lastSeen')}</th>
                <th scope="col" className="py-2 pr-3 text-right font-medium">{t('agents.events')}</th>
                <th scope="col" className="py-2 pr-3 text-right font-medium">{t('agents.spool')}</th>
                <th scope="col" className="py-2 pr-3 text-right font-medium">{t('agents.dropped')}</th>
                <th scope="col" className="py-2" />
              </tr></thead>
              <tbody>
                {nodes.data.nodes.map((n) => {
                  const a = byNode.get(n.id)
                  return (
                    <tr key={n.id} className="border-t border-line/60 align-top">
                      <td className="py-2 pr-3 font-medium">{n.name}</td>
                      <td className="py-2 pr-3">{state(a, now)}</td>
                      <td className="tnum py-2 pr-3 text-muted">{a?.last_seen ? formatDateTime(a.last_seen, tz) : '—'}</td>
                      <td className="tnum py-2 pr-3 text-right">{a ? formatInt(a.events_total) : '—'}</td>
                      <td className="tnum py-2 pr-3 text-right text-muted">{a ? bytes(a.spool_bytes) : '—'}</td>
                      <td className={`tnum py-2 pr-3 text-right ${a && a.dropped_total > 0 ? 'text-red' : 'text-muted'}`}>{a ? formatInt(a.dropped_total) : '—'}</td>
                      <td className="py-2 text-right">
                        {admin && !a && <GhostButton className="!h-8 !px-2.5 !text-xs" disabled={busy} onClick={() => void enroll(n)}>{t('agents.enroll')}</GhostButton>}
                        {admin && a && <GhostButton className="!h-8 !border-red/50 !px-2.5 !text-xs !text-red" disabled={busy} onClick={() => setRevoking(a)}>{t('agents.revoke')}</GhostButton>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {admin && nodes.data && nodes.data.nodes.length > 0 && (
          <div className="space-y-2 border-t border-line pt-4">
            <h3 className="text-[14px] font-semibold">{t('agents.routerTitle')}</h3>
            <p className="text-[13px] text-muted">{t('agents.routerIntro')}</p>
            {routerAgents.length === 0 && <p className="text-[13px] text-muted">{t('agents.routerNone')}</p>}
            {routerAgents.map((a) => (
              <div key={a.id} className="flex flex-wrap items-center gap-3 text-[13px]">
                {state(a, now)}
                <span className="font-medium">{a.name ?? 'router'}</span>
                <span className="tnum text-muted">{a.last_seen ? formatDateTime(a.last_seen, tz) : '—'}</span>
                <span className="tnum text-muted">{formatInt(a.events_total)}</span>
                <span className={`tnum ${a.dropped_total > 0 ? 'text-red' : 'text-muted'}`}>{formatInt(a.dropped_total)}</span>
                <GhostButton className="!h-8 !border-red/50 !px-2.5 !text-xs !text-red" disabled={busy} onClick={() => setRevoking(a)}>{t('agents.revoke')}</GhostButton>
              </div>
            ))}
            {routerAgents.length === 0 && (
              <label className="block text-[13px]">
                <span className="mb-1 block text-muted">{t('agents.coversUser')}</span>
                <input value={coversUser} onChange={(e) => setCoversUser(e.target.value)} maxLength={64} inputMode="text" autoComplete="off" placeholder="4"
                  className="h-9 w-40 rounded-control border border-line bg-canvas px-3" />
              </label>
            )}
            {routerAgents.length === 0 && <GhostButton className="!h-8 !px-2.5 !text-xs" disabled={busy} onClick={() => void enroll(nodes.data!.nodes[0], 'router')}>{t('agents.routerAdd')}</GhostButton>}
          </div>
        )}
        {admin && nodes.data && nodes.data.nodes.length > 0 && (
          <div className="space-y-2 border-t border-line pt-4">
            <h3 className="text-[14px] font-semibold">{t('agents.awgTitle')}</h3>
            <p className="text-[13px] text-muted">{t('agents.awgIntro')}</p>
            {awgAgents.length === 0 && <p className="text-[13px] text-muted">{t('agents.awgNone')}</p>}
            {awgAgents.map((a) => (
              <div key={a.id} className="flex flex-wrap items-center gap-3 text-[13px]">
                {state(a, now)}
                <span className="font-medium">{a.name ?? 'awg'}</span>
                <span className="tnum text-muted">{a.last_seen ? formatDateTime(a.last_seen, tz) : '—'}</span>
                <GhostButton className="!h-8 !border-red/50 !px-2.5 !text-xs !text-red" disabled={busy} onClick={() => setRevoking(a)}>{t('agents.revoke')}</GhostButton>
              </div>
            ))}
            {/* One AmneziaWG agent per node: a second server can have its own beside the first. */}
            {awgFree.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <select aria-label={t('agents.awgNode')} value={awgFree.some((n) => n.id === awgNode) ? awgNode : awgFree[0].id} onChange={(e) => setAwgNode(e.target.value)} className="h-9 rounded-control border border-line bg-canvas px-2 text-[13px]">
                  {awgFree.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                </select>
                <GhostButton className="!h-8 !px-2.5 !text-xs" disabled={busy} onClick={() => void enroll(awgFree.find((n) => n.id === awgNode) ?? awgFree[0], 'awg')}>{t('agents.awgAdd')}</GhostButton>
              </div>
            )}
          </div>
        )}
        {revoking && (
          <div role="alertdialog" aria-label={t('agents.revoke')} className="space-y-3 rounded-control border border-red/40 bg-red/10 p-3">
            <p className="text-[13px]">{t('agents.revokeConfirm', { node: revoking.node_name })}</p>
            <div className="flex gap-3"><DangerButton disabled={busy} onClick={() => void revoke(revoking)}>{t('agents.revoke')}</DangerButton><GhostButton onClick={() => setRevoking(null)}>{t('common.cancel')}</GhostButton></div>
          </div>
        )}
        <div className="flex justify-end"><PrimaryButton onClick={onClose}>{t('common.close')}</PrimaryButton></div>
      </div>
    </Modal>
  )
}

