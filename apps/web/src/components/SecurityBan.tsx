import { useEffect, useRef, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api, ApiError } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { SecCommand, SecManage } from '../lib/types'
import { Card, Chip } from './ui'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

type Tone = 'muted' | 'amber' | 'green' | 'red' | 'cyan'
const STATE_TONE: Record<string, Tone> = { pending: 'cyan', executed: 'green', confirmed_by_state: 'green', already_done: 'muted', rejected: 'red', failed: 'red', expired: 'amber', unknown: 'amber', duplicate: 'muted' }

export const cmdStateLabel = (c: Pick<SecCommand, 'state' | 'verified'>): string => t(`sec.cmd.state.${c.state}` as MsgKey)

interface Target { action: 'ban' | 'unban'; jail: string; ip: string }
interface Risk { reasons: string[] }

// A command is one request the owner confirmed. The idempotency key is made once per dialog, so a retry
// after a lost answer cannot send a second command.
const newKey = () => `ui-${crypto.randomUUID()}`

function useBan(vpsId: string, onDone: () => void) {
  const [target, setTarget] = useState<Target | null>(null)
  const open = (action: 'ban' | 'unban', jail: string, ip: string) => setTarget({ action, jail, ip })
  const dialog = target ? <ConfirmDialog vpsId={vpsId} target={target} onClose={() => { setTarget(null); onDone() }} /> : null
  return { open, dialog }
}

function ConfirmDialog({ vpsId, target, onClose }: { vpsId: string; target: Target; onClose: () => void }) {
  const key = useRef(newKey())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [risk, setRisk] = useState<Risk | null>(null)
  const [ack, setAck] = useState(false)
  const [cmd, setCmd] = useState<SecCommand | null>(null)
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => () => window.clearTimeout(timer.current), [])

  // Follow the command until it is final, for as long as the server could still be waiting for the agent.
  function follow(id: string, until: number) {
    timer.current = window.setTimeout(async () => {
      try {
        const r = await api.get<{ command: SecCommand }>(`/api/v1/security/commands/${id}`)
        setCmd(r.command)
        if (!r.command.final && Date.now() < until) follow(id, until)
      } catch (e) {
        setError(errorText(e))
      }
    }, 1000)
  }

  async function send() {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ command: SecCommand }>(`/api/v1/security/vps/${vpsId}/fail2ban/${target.action}`,
        { jail: target.jail, ip: target.ip, idempotency_key: key.current, acknowledge_risk: ack })
      setCmd(r.command)
      setRisk(null)
      if (!r.command.final) follow(r.command.id, Date.now() + 60_000)
    } catch (e) {
      if (e instanceof ApiError && e.code === 'risk') setRisk(e.details as Risk)
      else if (e instanceof ApiError && e.code) setError(errText(e))
      else setError(errorText(e))
    }
    setBusy(false)
  }

  const finished = cmd?.final
  return (
    <Modal title={t(target.action === 'ban' ? 'sec.cmd.banTitle' : 'sec.cmd.unbanTitle')} onClose={onClose} busy={busy}>
      <div className="space-y-3 text-[13px]">
        <p>{t(target.action === 'ban' ? 'sec.cmd.banText' : 'sec.cmd.unbanText', { ip: target.ip, jail: target.jail })}</p>
        <p className="text-muted">{t('sec.cmd.audited')}</p>
        {risk && (
          <div role="alert" className="space-y-2 rounded-control border border-amber/40 p-3 text-amber">
            {risk.reasons.map((r) => <p key={r}>{t(`sec.cmd.risk.${r}` as MsgKey)}</p>)}
            <label className="flex items-center gap-2 text-fg"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />{t('sec.cmd.ack')}</label>
          </div>
        )}
        {cmd && (
          <div role="status" className="space-y-1">
            <Chip tone={STATE_TONE[cmd.state] ?? 'muted'}>{cmdStateLabel(cmd)}</Chip>
            {cmd.state === 'unknown' && <p className="text-amber">{t('sec.cmd.unknownHint')}</p>}
            {cmd.result_code && cmd.state !== 'executed' && <p className="text-xs text-muted">{cmd.result_code}</p>}
          </div>
        )}
        {error && <p role="alert" className="text-red">{error}</p>}
      </div>
      <div className="mt-4 flex justify-end gap-3">
        <GhostButton onClick={onClose}>{finished ? t('sec.cmd.close') : t('common.cancel')}</GhostButton>
        {!cmd && (target.action === 'ban'
          ? <DangerButton disabled={busy || (!!risk && !ack)} onClick={() => void send()}>{t('sec.cmd.banDo')}</DangerButton>
          : <PrimaryButton disabled={busy || (!!risk && !ack)} onClick={() => void send()}>{t('sec.cmd.unbanDo')}</PrimaryButton>)}
      </div>
    </Modal>
  )
}

function errText(e: ApiError): string {
  const key = `sec.cmd.err.${e.code}` as MsgKey
  const s = t(key)
  return s ? s : e.message
}

/** Unban button for one address, and the form for banning another. Nothing here when the caller may not manage. */
export function useBanControls(vpsId: string, manage: SecManage | undefined, jails: string[], onDone: () => void) {
  const { open, dialog } = useBan(vpsId, onDone)
  const allowed = !!manage?.allowed
  const ready = !!manage?.ready
  const unban = (jail: string, ip: string) => allowed
    ? <button type="button" disabled={!ready} onClick={() => open('unban', jail, ip)} className="ml-2 text-xs text-muted underline hover:text-fg disabled:cursor-not-allowed disabled:opacity-40">{t('sec.cmd.unbanDo')}</button>
    : null
  const form = allowed ? <BanForm jails={jails} ready={ready} reason={manage?.reason} onAsk={(j, ip) => open('ban', j, ip)} /> : null
  return { unban, form, dialog }
}

function BanForm({ jails, ready, reason, onAsk }: { jails: string[]; ready: boolean; reason?: string; onAsk: (jail: string, ip: string) => void }) {
  const [jail, setJail] = useState('')
  const [ip, setIp] = useState('')
  const j = jail || jails[0] || ''
  return (
    <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); if (ready && j && ip.trim()) onAsk(j, ip.trim()) }}>
      <Field label={t('sec.f2b.jails')} htmlFor="ban-jail">
        <select id="ban-jail" className={inputCls} value={j} onChange={(e) => setJail(e.target.value)}>{jails.map((x) => <option key={x} value={x}>{x}</option>)}</select>
      </Field>
      <Field label="IP" htmlFor="ban-ip"><input id="ban-ip" className={inputCls} value={ip} onChange={(e) => setIp(e.target.value)} spellCheck={false} autoComplete="off" /></Field>
      <DangerButton type="submit" disabled={!ready || !j || !ip.trim()}>{t('sec.cmd.banDo')}</DangerButton>
      {!ready && reason && <p className="w-full text-[13px] text-muted">{t(`sec.cmd.why.${reason}` as MsgKey)}</p>}
    </form>
  )
}

/** The latest commands for the server, with what became of each. */
export function CommandHistory({ vpsId, refreshKey }: { vpsId: string; refreshKey: number }) {
  const { data } = useLoad((s) => api.get<{ items: SecCommand[] }>(`/api/v1/security/vps/${vpsId}/commands?limit=10`, s), [vpsId, refreshKey], 20_000)
  if (!data || data.items.length === 0) return null
  return (
    <Card title={t('sec.cmd.history')}>
      <ul className="divide-y divide-line text-[13px]">
        {data.items.map((c) => (
          <li key={c.id} className="flex flex-wrap items-center justify-between gap-3 py-2">
            <span><Chip tone={STATE_TONE[c.state] ?? 'muted'}>{cmdStateLabel(c)}</Chip> <span className="ml-2">{t(c.action === 'ban' ? 'sec.cmd.banShort' : 'sec.cmd.unbanShort')} <span className="font-mono text-[12px]">{c.ip}</span> · {c.jail}</span></span>
            <span className="tnum text-xs text-muted">{formatDateTime(c.requested_at, 'local')}</span>
          </li>
        ))}
      </ul>
    </Card>
  )
}
