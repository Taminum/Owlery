import { useCallback, useEffect, useRef, useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { isNewer } from '../lib/semver'
import { Chip } from './ui'
import { GhostButton, Modal, PrimaryButton } from './Modal'
import { updateErrorText } from './AgentSetup'
import type { Server } from './ServerParts'

type Phase = 'queued' | 'sending' | 'updating' | 'done' | 'failed' | 'stopped'
interface Row { phase: Phase; error?: string }

/** At the same time. Enough to be quick, few enough that the road to GitHub and the machines are not all busy at once. */
const PARALLEL = 3
/** How long a machine has to show the new version after the request went out. */
const WAIT_MS = 5 * 60_000

export interface Plan {
  ready: Server[]
  blocked: { s: Server; why: 'offline' | 'notAllowed' }[]
}

/**
 * Which machines can be updated from the panel now, and which have an old agent that cannot (and why). A machine without an
 * agent, or whose agent is already the newest, is not mentioned.
 */
export function planUpdates(list: Server[], latest: string): Plan {
  const plan: Plan = { ready: [], blocked: [] }
  if (!latest) return plan
  for (const s of list) {
    const a = s.agent
    if (!s.can_edit || !a || !isNewer(latest, a.version)) continue
    if (a.online && a.can_update) plan.ready.push(s)
    else plan.blocked.push({ s, why: a.online ? 'notAllowed' : 'offline' })
  }
  return plan
}

const sleep = (ms: number) => new Promise<void>((r) => window.setTimeout(r, ms))

/**
 * The button on the Servers page that updates agents in one go, and the window that shows how it goes. The queue lives here, not in
 * the window, so closing the window does not stop it; leaving the page does.
 */
export function BulkUpdate({ list, latest, onProgress, pollMs = 3000 }: { list: Server[]; latest: string; onProgress: () => void; pollMs?: number }) {
  const plan = planUpdates(list, latest)
  const [open, setOpen] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [rows, setRows] = useState<Record<string, Row>>({})
  const [running, setRunning] = useState(false)
  const stop = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])

  const set = useCallback((id: string, r: Row) => { if (alive.current) setRows((x) => ({ ...x, [id]: r })) }, [])

  // The machines that were in the queue stay in the window after they are updated (the list no longer offers them).
  const queued = Object.keys(rows)
  const byId = new Map(list.map((s) => [s.id, s]))
  const shown = queued.length > 0 ? queued.map((id) => byId.get(id)).filter((s): s is Server => !!s) : plan.ready
  const hasWork = plan.ready.length > 0 || queued.length > 0

  function show() {
    if (queued.length === 0) setPicked(new Set(plan.ready.map((s) => s.id)))
    setOpen(true)
  }

  async function one(id: string) {
    set(id, { phase: 'sending' })
    try {
      await api.post(`/api/v1/security/vps/${id}/agent/update`, { version: latest })
    } catch (e) {
      set(id, { phase: 'failed', error: updateErrorText(e) })
      return
    }
    set(id, { phase: 'updating' })
    const until = Date.now() + WAIT_MS
    while (alive.current && Date.now() < until) {
      await sleep(pollMs)
      try {
        const r = await api.get<{ agent: { agent_version: string | null } | null }>(`/api/v1/security/vps/${id}/agent`)
        if (r.agent?.agent_version === latest) {
          set(id, { phase: 'done' })
          onProgress()
          return
        }
      } catch { /* the agent is restarting; ask again */ }
    }
    if (alive.current) set(id, { phase: 'failed', error: t('bulk.err.timeout') })
  }

  async function start(ids: string[]) {
    if (ids.length === 0) return
    stop.current = false
    setRunning(true)
    setRows((x) => { const n = { ...x }; for (const id of ids) n[id] = { phase: 'queued' }; return n })
    const todo = [...ids]
    const worker = async () => {
      for (;;) {
        if (stop.current || !alive.current) return
        const id = todo.shift()
        if (!id) return
        await one(id)
      }
    }
    await Promise.all(Array.from({ length: Math.min(PARALLEL, ids.length) }, worker))
    // What the stop left in the queue is marked, so nobody wonders.
    if (alive.current) {
      setRows((x) => { const n = { ...x }; for (const id of todo) n[id] = { phase: 'stopped' }; return n })
      setRunning(false)
      onProgress()
    }
  }

  const done = Object.values(rows).filter((r) => r.phase === 'done').length
  const failed = Object.entries(rows).filter(([, r]) => r.phase === 'failed').map(([id]) => id)

  function close() {
    setOpen(false)
    if (!running) setRows({}) // a finished run is read once
  }

  if (!hasWork) return null
  return (
    <>
      <button type="button" onClick={show}
        className="h-10 rounded-control border border-amber/40 bg-amber/10 px-4 text-[14px] font-medium text-amber hover:brightness-110">
        {running ? t('bulk.running', { done, n: queued.length }) : t('bulk.button', { n: plan.ready.length })}
      </button>
      {open && (
        <Modal title={t('bulk.title', { v: latest })} onClose={close} wide>
          <p className="text-xs text-muted">{t('bulk.how', { n: PARALLEL })}</p>

          <div className="mt-3 max-h-[50vh] overflow-y-auto">
            {shown.map((s) => {
              const r = rows[s.id]
              return (
                <div key={s.id} className="grid grid-cols-[24px_minmax(0,1fr)_auto_190px] items-center gap-3 border-t border-line/60 px-1 py-2 text-[13px] first:border-t-0">
                  {queued.length === 0
                    ? <input type="checkbox" className="h-4 w-4" aria-label={s.name} checked={picked.has(s.id)}
                        onChange={(e) => setPicked((p) => { const n = new Set(p); if (e.target.checked) n.add(s.id); else n.delete(s.id); return n })} />
                    : <span />}
                  <span className="min-w-0 truncate">{s.name}{s.group && <span className="ml-2 text-xs text-muted">{s.group}</span>}</span>
                  <span className="tnum whitespace-nowrap text-xs text-muted">{s.agent?.version} → {latest}</span>
                  <span className="text-right text-xs" aria-live="polite">{r ? <PhaseText r={r} /> : <span className="text-muted">{/windows/i.test(s.os || s.host?.os || '') ? 'Windows' : 'Linux'}</span>}</span>
                </div>
              )
            })}
          </div>

          {queued.length === 0 && plan.blocked.length > 0 && (
            <div className="mt-4">
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">{t('bulk.blocked', { n: plan.blocked.length })}</div>
              {plan.blocked.map(({ s, why }) => (
                <div key={s.id} className="flex items-baseline justify-between gap-3 border-t border-line/60 px-1 py-1.5 text-[13px] first:border-t-0">
                  <span className="truncate">{s.name}</span>
                  <span className="text-right text-xs text-muted">{t(why === 'offline' ? 'bulk.why.offline' : 'bulk.why.notAllowed')}</span>
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs text-muted">
              {queued.length === 0
                ? <>{t('bulk.picked', { k: picked.size, n: plan.ready.length })} · <button type="button" className="underline hover:text-fg" onClick={() => setPicked(picked.size ? new Set() : new Set(plan.ready.map((s) => s.id)))}>{picked.size ? t('bulk.none') : t('bulk.all')}</button></>
                : running ? t('bulk.keepOpen') : t('bulk.finished', { done, n: queued.length })}
            </span>
            <span className="flex gap-3">
              {queued.length === 0 && <>
                <GhostButton onClick={close}>{t('common.cancel')}</GhostButton>
                <PrimaryButton disabled={picked.size === 0} onClick={() => void start(plan.ready.filter((s) => picked.has(s.id)).map((s) => s.id))}>{t('bulk.go', { n: picked.size })}</PrimaryButton>
              </>}
              {queued.length > 0 && running && <GhostButton onClick={() => { stop.current = true }}>{t('bulk.stop')}</GhostButton>}
              {queued.length > 0 && !running && failed.length > 0 && <GhostButton onClick={() => void start(failed)}>{t('bulk.retry', { n: failed.length })}</GhostButton>}
              {queued.length > 0 && <GhostButton onClick={close}>{running ? t('bulk.hide') : t('bulk.close')}</GhostButton>}
            </span>
          </div>
        </Modal>
      )}
    </>
  )
}

function PhaseText({ r }: { r: Row }) {
  switch (r.phase) {
    case 'queued': return <span className="text-muted">{t('bulk.phase.queued')}</span>
    case 'sending': return <Chip tone="amber">{t('bulk.phase.sending')}</Chip>
    case 'updating': return <Chip tone="amber">{t('bulk.phase.updating')}</Chip>
    case 'done': return <Chip tone="green">{t('bulk.phase.done')}</Chip>
    case 'stopped': return <span className="text-muted">{t('bulk.phase.stopped')}</span>
    default: return <span className="text-red" title={r.error}>{t('bulk.phase.failed')}: {r.error}</span>
  }
}

/** What a machine's agent is, in a pair of chips: its version, and the newer one that is out, if any. */
export function AgentChips({ s, latest }: { s: Server; latest: string }) {
  const a = s.agent
  if (!a || !a.version) return null
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className="rounded-full border border-line px-2 py-0.5 text-[11px] text-muted">{t('bulk.agentV', { v: a.version })}</span>
      {isNewer(latest, a.version) && <span className="rounded-full border border-amber/40 px-2 py-0.5 text-[11px] text-amber">{t('bulk.newer', { v: latest })}</span>}
    </span>
  )
}
