import { useMemo, useState, type ReactNode } from 'react'
import { RefreshCw } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { request } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatBytes, formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from './ui'
import { DangerButton, GhostButton, PrimaryButton, inputCls } from './Modal'

type Section = 'procs' | 'services' | 'startup' | 'sessions' | 'events' | 'conns'
const SECTIONS: Section[] = ['procs', 'services', 'startup', 'sessions', 'events', 'conns']

type Proc = { pid: number; ppid: number; name: string; user?: string; rss: number; cpu: number; started?: number; path?: string }
type Service = { name: string; display?: string; state: string; start: string; pid?: number }
type Startup = { kind: string; where: string; name: string; command?: string; user?: string }
type Session = { id: number; user?: string; state: string; client?: string; name?: string }
type Event = { time: string; log: string; source: string; id: number; level: string; message?: string }
type Conn = { proto: string; local: string; remote?: string; state?: string; pid: number; name?: string }

/** Sends one management request to the machine's agent and gives back what it answered. */
function ask<T>(serverId: string, op: string, args?: object, signal?: AbortSignal): Promise<T> {
  return request<{ data: T }>('POST', `/api/v1/servers/${serverId}/manage`, { op, args }, signal).then((r) => r.data)
}

const th = 'px-2 py-1.5 text-left text-xs font-medium text-muted'
const td = 'px-2 py-1.5 align-top'

function Table({ head, children, empty }: { head: ReactNode[]; children: ReactNode[]; empty: string }) {
  if (children.length === 0) return <p className="py-3 text-[13px] text-muted">{empty}</p>
  return (
    <div className="max-h-[65vh] overflow-auto rounded-control border border-line">
      <table className="w-full text-[13px]">
        <thead className="sticky top-0 bg-surface"><tr>{head.map((h, i) => <th key={i} className={th}>{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  )
}

/**
 * Looks at the machine and changes it, without showing anything on its screen: the agent does the work. Every change
 * is asked about first and is written to the audit log. Only on Windows, and only where the machine was installed to
 * allow it.
 */
export function ManageView({ serverId }: { serverId: string }) {
  const [section, setSection] = useState<Section>('procs')
  return (
    <Card title={t('mng.title')} note={t('mng.note')}>
      <div role="tablist" aria-label={t('mng.title')} className="mb-3 flex flex-wrap gap-2">
        {SECTIONS.map((s) => (
          <button key={s} role="tab" type="button" aria-selected={section === s} onClick={() => setSection(s)}
            className={`h-8 rounded-control border px-3 text-[13px] ${section === s ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(`mng.s.${s}` as MsgKey)}</button>
        ))}
      </div>
      {section === 'procs' && <Procs serverId={serverId} />}
      {section === 'services' && <Services serverId={serverId} />}
      {section === 'startup' && <StartupList serverId={serverId} />}
      {section === 'sessions' && <Sessions serverId={serverId} />}
      {section === 'events' && <Events serverId={serverId} />}
      {section === 'conns' && <Conns serverId={serverId} />}
    </Card>
  )
}

/** Loads one list and keeps the bar above it: a filter, a refresh, and the message of the last action. */
function useList<T>(serverId: string, op: string, args?: object) {
  const q = useLoad((sig) => ask<T[]>(serverId, op, args, sig), [serverId, op, JSON.stringify(args ?? {})])
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  // Runs a change the administrator confirmed, then reloads the list.
  async function act(confirmText: string, op2: string, args2: object, done?: string): Promise<boolean> {
    if (!window.confirm(confirmText)) return false
    setNote('')
    setError('')
    try {
      await ask(serverId, op2, args2)
      setNote(done ?? t('mng.done'))
      q.reload()
      return true
    } catch (e) {
      setError(errorText(e))
      return false
    }
  }
  return { rows: q.data ?? [], loading: !q.data && !q.error, loadError: q.error, reload: q.reload, note, error, act }
}

function Bar({ filter, setFilter, reload, extra, note, error, loadError, loading }: {
  filter?: string; setFilter?: (v: string) => void; reload: () => void; extra?: ReactNode; note: string; error: string; loadError: string; loading: boolean
}) {
  return (
    <div className="mb-2 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {setFilter && <input className={`${inputCls} max-w-xs`} value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t('mng.filter')} aria-label={t('mng.filter')} />}
        <GhostButton onClick={reload}><RefreshCw size={14} aria-hidden /> {t('mng.refresh')}</GhostButton>
        {extra}
        {loading && <span className="text-xs text-muted" role="status">{t('mng.loading')}</span>}
      </div>
      {(error || loadError) && <p role="alert" className="text-[13px] text-red">{error || loadError}</p>}
      {note && <p role="status" className="text-[13px] text-green">{note}</p>}
    </div>
  )
}

const KNOWN = {
  st: ['running', 'stopped', 'starting', 'stopping', 'resuming', 'pausing', 'paused'],
  sess: ['active', 'connected', 'connecting', 'shadow', 'disconnected', 'idle', 'reset', 'down', 'init'],
}

/** The word for a state, or the state as it came when it is one this page has no word for. */
const label = (kind: 'st' | 'sess', state: string): string => (KNOWN[kind].includes(state) ? t(`mng.${kind}.${state}` as MsgKey) : state)

const has = (hay: (string | number | undefined)[], q: string) => !q || hay.some((h) => String(h ?? '').toLowerCase().includes(q.toLowerCase()))

function Procs({ serverId }: { serverId: string }) {
  const l = useList<Proc>(serverId, 'procs')
  const [f, setF] = useState('')
  const rows = useMemo(() => l.rows.filter((p) => has([p.name, p.pid, p.user, p.path], f)), [l.rows, f])
  return (
    <>
      <Bar filter={f} setFilter={setF} reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} />
      <Table head={[t('mng.name'), 'PID', t('mng.user'), t('mng.cpu'), t('mng.mem'), t('mng.started'), '']} empty={t('mng.empty')}>
        {rows.map((p) => (
          <tr key={p.pid}>
            <td className={td} title={p.path}>{p.name}</td>
            <td className={`${td} tnum`}>{p.pid}</td>
            <td className={`${td} text-muted`}>{p.user}</td>
            <td className={`${td} tnum`}>{p.cpu.toFixed(1)}%</td>
            <td className={`${td} tnum`}>{formatBytes(p.rss)}</td>
            <td className={`${td} tnum text-muted`}>{p.started ? formatDateTime(p.started, 'local') : ''}</td>
            <td className={td}><DangerButton onClick={() => void l.act(t('mng.killAsk', { n: p.name, p: String(p.pid) }), 'proc_kill', { pid: p.pid })}>{t('mng.kill')}</DangerButton></td>
          </tr>
        ))}
      </Table>
    </>
  )
}

const STATE_TONE: Record<string, 'green' | 'muted' | 'amber'> = { running: 'green', stopped: 'muted' }

function Services({ serverId }: { serverId: string }) {
  const l = useList<Service>(serverId, 'services')
  const [f, setF] = useState('')
  const rows = useMemo(() => l.rows.filter((s) => has([s.name, s.display, s.state], f)), [l.rows, f])
  return (
    <>
      <Bar filter={f} setFilter={setF} reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} />
      <Table head={[t('mng.name'), t('mng.state'), t('mng.startType'), '']} empty={t('mng.empty')}>
        {rows.map((s) => (
          <tr key={s.name}>
            <td className={td}>{s.display || s.name}<span className="block font-mono text-xs text-muted">{s.name}</span></td>
            <td className={td}><Chip tone={STATE_TONE[s.state] ?? 'amber'}>{label('st', s.state)}</Chip></td>
            <td className={td}>
              <select className={`${inputCls} h-8 w-40`} value={s.start === 'auto-delayed' ? 'auto' : s.start} aria-label={t('mng.startType')}
                onChange={(e) => void l.act(t('mng.startAsk', { n: s.name }), 'svc_startup', { name: s.name, start: e.target.value })}>
                <option value="auto">{t('mng.start.auto')}</option>
                <option value="manual">{t('mng.start.manual')}</option>
                <option value="disabled">{t('mng.start.disabled')}</option>
                {!['auto', 'auto-delayed', 'manual', 'disabled'].includes(s.start) && <option value={s.start} disabled>{s.start}</option>}
              </select>
            </td>
            <td className={`${td} space-x-1 whitespace-nowrap`}>
              {s.state !== 'running' && <GhostButton onClick={() => void l.act(t('mng.svcAsk', { n: s.name, a: t('mng.start') }), 'svc_start', { name: s.name })}>{t('mng.start')}</GhostButton>}
              {s.state === 'running' && <GhostButton onClick={() => void l.act(t('mng.svcAsk', { n: s.name, a: t('mng.stop') }), 'svc_stop', { name: s.name })}>{t('mng.stop')}</GhostButton>}
              {s.state === 'running' && <GhostButton onClick={() => void l.act(t('mng.svcAsk', { n: s.name, a: t('mng.restart') }), 'svc_restart', { name: s.name })}>{t('mng.restart')}</GhostButton>}
            </td>
          </tr>
        ))}
      </Table>
    </>
  )
}

function StartupList({ serverId }: { serverId: string }) {
  const l = useList<Startup>(serverId, 'startup')
  const [f, setF] = useState('')
  const [name, setName] = useState('')
  const [command, setCommand] = useState('')
  const rows = useMemo(() => l.rows.filter((s) => has([s.name, s.command, s.user], f)), [l.rows, f])
  return (
    <>
      <Bar filter={f} setFilter={setF} reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} />
      <Table head={[t('mng.name'), t('mng.command'), t('mng.where'), '']} empty={t('mng.empty')}>
        {rows.map((s) => (
          <tr key={`${s.where}|${s.name}`}>
            <td className={td}>{s.name}</td>
            <td className={`${td} break-all font-mono text-xs`}>{s.command}</td>
            <td className={`${td} break-all text-xs text-muted`}>{s.kind === 'file' ? t('mng.folder') : s.where}</td>
            <td className={td}><DangerButton onClick={() => void l.act(t('mng.removeAsk', { n: s.name }), 'startup_remove', { kind: s.kind, where: s.where, name: s.name })}>{t('mng.remove')}</DangerButton></td>
          </tr>
        ))}
      </Table>
      <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={(e) => {
        e.preventDefault()
        if (name && command) void l.act(t('mng.addAsk', { n: name }), 'startup_add', { name, command }).then((ok) => { if (ok) { setName(''); setCommand('') } })
      }}>
        <input className={`${inputCls} w-48`} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('mng.name')} aria-label={t('mng.name')} />
        <input className={`${inputCls} min-w-[18rem] flex-1`} value={command} onChange={(e) => setCommand(e.target.value)} placeholder={t('mng.command')} aria-label={t('mng.command')} />
        <PrimaryButton type="submit" disabled={!name || !command}>{t('mng.add')}</PrimaryButton>
      </form>
    </>
  )
}

function Sessions({ serverId }: { serverId: string }) {
  const l = useList<Session>(serverId, 'sessions')
  return (
    <>
      <Bar reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} />
      <Table head={['ID', t('mng.user'), t('mng.state'), t('mng.client'), '']} empty={t('mng.empty')}>
        {l.rows.map((s) => (
          <tr key={s.id}>
            <td className={`${td} tnum`}>{s.id}</td>
            <td className={td}>{s.user || '—'}</td>
            <td className={td}>{label('sess', s.state)}{s.name ? <span className="block text-xs text-muted">{s.name}</span> : null}</td>
            <td className={`${td} text-muted`}>{s.client}</td>
            <td className={`${td} space-x-1 whitespace-nowrap`}>
              <GhostButton onClick={() => void l.act(t('mng.disconnectAsk', { n: s.user || String(s.id) }), 'session_disconnect', { id: s.id })}>{t('mng.disconnect')}</GhostButton>
              <DangerButton onClick={() => void l.act(t('mng.logoffAsk', { n: s.user || String(s.id) }), 'session_logoff', { id: s.id })}>{t('mng.logoff')}</DangerButton>
            </td>
          </tr>
        ))}
      </Table>
    </>
  )
}

function Events({ serverId }: { serverId: string }) {
  const [log, setLog] = useState('System')
  const [level, setLevel] = useState(3)
  const l = useList<Event>(serverId, 'events', { log, level, limit: 150 })
  const [f, setF] = useState('')
  const rows = useMemo(() => l.rows.filter((e) => has([e.source, e.message, e.id], f)), [l.rows, f])
  return (
    <>
      <Bar filter={f} setFilter={setF} reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} extra={
        <>
          <select className={`${inputCls} h-8 w-40`} value={log} onChange={(e) => setLog(e.target.value)} aria-label={t('mng.log')}>
            <option value="System">System</option>
            <option value="Application">Application</option>
            <option value="Security">Security</option>
          </select>
          <select className={`${inputCls} h-8 w-52`} value={level} onChange={(e) => setLevel(Number(e.target.value))} aria-label={t('mng.level')}>
            <option value={1}>{t('mng.lv.1')}</option>
            <option value={2}>{t('mng.lv.2')}</option>
            <option value={3}>{t('mng.lv.3')}</option>
            <option value={4}>{t('mng.lv.4')}</option>
          </select>
        </>} />
      <Table head={[t('mng.time'), t('mng.level'), t('mng.source'), t('mng.message')]} empty={t('mng.empty')}>
        {rows.map((e, i) => (
          <tr key={i}>
            <td className={`${td} tnum whitespace-nowrap text-muted`}>{formatDateTime(e.time, 'local')}</td>
            <td className={td}>{e.level}</td>
            <td className={td}>{e.source}<span className="block text-xs text-muted">ID {e.id}</span></td>
            <td className={`${td} whitespace-pre-wrap break-words text-xs`}>{e.message}</td>
          </tr>
        ))}
      </Table>
    </>
  )
}

function Conns({ serverId }: { serverId: string }) {
  const l = useList<Conn>(serverId, 'conns')
  const [f, setF] = useState('')
  const rows = useMemo(() => l.rows.filter((c) => has([c.local, c.remote, c.name, c.pid, c.state], f)), [l.rows, f])
  return (
    <>
      <Bar filter={f} setFilter={setF} reload={l.reload} note={l.note} error={l.error} loadError={l.loadError} loading={l.loading} />
      <Table head={[t('mng.proto'), t('mng.local'), t('mng.remote'), t('mng.state'), t('mng.process'), '']} empty={t('mng.empty')}>
        {rows.map((c, i) => (
          <tr key={i}>
            <td className={td}>{c.proto}</td>
            <td className={`${td} font-mono text-xs`}>{c.local}</td>
            <td className={`${td} font-mono text-xs`}>{c.remote}</td>
            <td className={`${td} text-muted`}>{c.state}</td>
            <td className={td}>{c.name} <span className="tnum text-xs text-muted">{c.pid}</span></td>
            <td className={td}>{c.pid > 4 && <DangerButton onClick={() => void l.act(t('mng.killAsk', { n: c.name || '?', p: String(c.pid) }), 'proc_kill', { pid: c.pid })}>{t('mng.kill')}</DangerButton>}</td>
          </tr>
        ))}
      </Table>
    </>
  )
}
