import { useEffect, useMemo, useState } from 'react'
import { Folder, File as FileIcon, RefreshCw } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { ApiError, request } from '../lib/api'
import { formatBytes, formatDateTime } from '../lib/format'
import { Card, Chip, Segmented } from './ui'
import { DangerButton, GhostButton, Modal, inputCls } from './Modal'

type Unit = { name: string; desc?: string; load: string; active: string; sub: string; enabled?: string; manage: boolean }
type Entry = { name: string; dir?: boolean; link?: boolean; size: number; mod: number }
type Answer = { units: Unit[]; dir: string; dirs: string[]; entries: Entry[]; text: string; truncated: boolean; active: string }

/** Sends one request about services or files to the machine's agent. */
function ask(serverId: string, body: { op: string; name?: string; path?: string; tail?: number }, signal?: AbortSignal): Promise<Answer> {
  return request<Answer>('POST', `/api/v1/servers/${serverId}/linux`, body, signal)
}

function why(e: unknown): string {
  if (e instanceof ApiError) {
    const k = `lx.err.${e.code}` as MsgKey
    const m = t(k)
    return m === k ? t('lx.err.other') : m
  }
  return t('lx.err.other')
}

type Body = { op: string; name?: string; path?: string; tail?: number }

/** Loads one answer from the machine (nothing while body is null), with the reason in words when it fails. */
function useAsk(serverId: string, body: Body | null) {
  const [state, setState] = useState<{ data: Answer | null; error: string }>({ data: null, error: '' })
  const [nonce, setNonce] = useState(0)
  const key = JSON.stringify(body)
  useEffect(() => {
    if (!body) return
    const ac = new AbortController()
    ask(serverId, body, ac.signal)
      .then((data) => setState({ data, error: '' }))
      .catch((e) => { if ((e as Error).name !== 'AbortError') setState((s) => ({ ...s, error: why(e) })) })
    return () => ac.abort()
    // The body is compared by its text, so that a new object with the same content does not load again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverId, key, nonce])
  // Nothing is asked while there is no body, so whatever an earlier one left is not shown.
  return { data: body ? state.data : null, error: body ? state.error : '', reload: () => setNonce((n) => n + 1) }
}

const STATE_KEYS = ['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading']
const BOOT_KEYS = ['enabled', 'disabled', 'static', 'masked', 'indirect', 'generated']
const word = (prefix: 'state' | 'boot', keys: string[], v: string) => (keys.includes(v) ? t(`lx.${prefix}.${v}` as MsgKey) : v)

type Section = 'services' | 'files'

/**
 * The «Управление» tab of a Linux machine: every service with how it is doing, and a read-only look at files. The machine's own
 * helper decides which services may be started and stopped and which folders may be read; this page only offers what it says.
 */
export function LinuxView({ serverId, enabled }: { serverId: string; enabled: boolean }) {
  const [section, setSection] = useState<Section>('services')
  if (!enabled) return <p className="text-[13px] text-muted">{t('lx.off')}</p>
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">{t('lx.note')}</p>
      <Segmented label={t('lx.sec')} value={section} onChange={setSection} options={[{ value: 'services', label: t('lx.s.services') }, { value: 'files', label: t('lx.s.files') }]} />
      {section === 'services' ? <Services serverId={serverId} /> : <Files serverId={serverId} />}
    </div>
  )
}

type Filter = 'all' | 'failed' | 'manage'

function Services({ serverId }: { serverId: string }) {
  const q = useAsk(serverId, { op: 'list' })
  const [filter, setFilter] = useState<Filter>('all')
  const [text, setText] = useState('')
  const [journal, setJournal] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const units = useMemo(() => {
    const all = (q.data?.units ?? []).filter((u) => u.load !== 'not-found')
    const s = text.trim().toLowerCase()
    return all
      .filter((u) => (filter === 'failed' ? u.active === 'failed' : filter === 'manage' ? u.manage : true) && (!s || u.name.toLowerCase().includes(s) || (u.desc ?? '').toLowerCase().includes(s)))
      .sort((a, b) => Number(b.active === 'failed') - Number(a.active === 'failed') || a.name.localeCompare(b.name))
  }, [q.data, filter, text])

  async function act(u: Unit, op: 'start' | 'stop' | 'restart') {
    const label = t(`lx.${op}` as MsgKey)
    if (!window.confirm(t('lx.ask', { a: label, name: u.name }))) return
    setNote('')
    setError('')
    try {
      const r = await ask(serverId, { op, name: u.name })
      setNote(t('lx.done', { name: u.name, state: word('state', STATE_KEYS, r.active) }))
      q.reload()
    } catch (e) {
      setError(why(e))
    }
  }

  return (
    <Card title={t('lx.s.services')} right={
      <div className="flex flex-wrap items-center gap-2">
        <input className={`${inputCls} w-44 text-xs`} style={{ height: 26, paddingTop: 0, paddingBottom: 0 }} value={text} onChange={(e) => setText(e.target.value)} placeholder={t('lx.filter')} aria-label={t('lx.filter')} />
        <button type="button" onClick={q.reload} aria-label={t('lx.refresh')} title={t('lx.refresh')} className="grid h-[26px] w-[26px] place-items-center rounded-[9px] border border-line bg-elevated text-muted hover:text-fg"><RefreshCw size={13} aria-hidden /></button>
      </div>}>
      <div className="mb-3">
        <Segmented label={t('lx.s.services')} value={filter} onChange={setFilter} options={[{ value: 'all', label: t('lx.f.all') }, { value: 'failed', label: t('lx.f.failed') }, { value: 'manage', label: t('lx.f.manage') }]} />
      </div>
      {(q.error || error) && <p role="alert" className="mb-2 text-[13px] text-red">{error || q.error}</p>}
      {note && <p role="status" className="mb-2 text-[13px] text-green">{note}</p>}
      {!q.data && !q.error ? <p className="py-3 text-[13px] text-muted" aria-busy="true">{t('state.loading')}</p> : units.length === 0 && !q.error ? <p className="py-3 text-[13px] text-muted">{t('lx.empty')}</p> : (
        <div className="max-h-[65vh] overflow-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-surface">
              <tr className="text-left text-xs text-muted">
                <th scope="col" className="py-2 pr-3 font-normal">{t('lx.col.name')}</th>
                <th scope="col" className="pr-3 font-normal">{t('lx.col.state')}</th>
                <th scope="col" className="pr-3 font-normal">{t('lx.col.boot')}</th>
                <th scope="col" className="text-right font-normal">{t('lx.col.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {units.map((u) => {
                const bad = u.active === 'failed'
                return (
                  <tr key={u.name} className={`border-t border-line/60 ${bad ? 'bg-red/5' : ''}`}>
                    <td className="py-2 pr-3">{u.name}{u.desc && <span className="block max-w-[28rem] truncate text-xs text-muted" title={u.desc}>{u.desc}</span>}</td>
                    <td className="pr-3"><Chip tone={bad ? 'red' : u.active === 'active' ? 'green' : u.active === 'inactive' ? 'muted' : 'amber'}>{word('state', STATE_KEYS, u.active)}</Chip></td>
                    <td className="pr-3 text-muted">{u.enabled ? word('boot', BOOT_KEYS, u.enabled) : '—'}</td>
                    <td className="whitespace-nowrap py-1 text-right">
                      <GhostButton size="s" aria-label={`${t('lx.journal')}: ${u.name}`} onClick={() => setJournal(u.name)}>{t('lx.journal')}</GhostButton>
                      {u.manage ? (
                        <>
                          {' '}
                          {u.active !== 'active' && <GhostButton size="s" aria-label={`${t('lx.start')}: ${u.name}`} onClick={() => void act(u, 'start')}>{t('lx.start')}</GhostButton>}{' '}
                          <GhostButton size="s" aria-label={`${t('lx.restart')}: ${u.name}`} onClick={() => void act(u, 'restart')}>{t('lx.restart')}</GhostButton>{' '}
                          {u.active === 'active' && <DangerButton size="s" aria-label={`${t('lx.stop')}: ${u.name}`} onClick={() => void act(u, 'stop')}>{t('lx.stop')}</DangerButton>}
                        </>
                      ) : <span className="ml-2 text-xs text-muted">{t('lx.readOnly')}</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {journal && <TextDialog serverId={serverId} title={t('lx.journalTitle', { name: journal })} note={t('lx.journalNote')} empty={t('lx.logEmpty')} body={{ op: 'journal', name: journal, tail: 200 }} onClose={() => setJournal('')} />}
    </Card>
  )
}

/** A window with a block of text fetched from the machine (a journal or a file), with refresh and copy. */
function TextDialog({ serverId, title, note, empty, body, onClose }: { serverId: string; title: string; note: string; empty: string; body: { op: string; name?: string; path?: string; tail?: number }; onClose: () => void }) {
  const [tick, setTick] = useState(0)
  const [state, setState] = useState<Answer | { error: string } | null>(null)
  const key = JSON.stringify(body)
  useEffect(() => {
    let live = true
    ask(serverId, JSON.parse(key))
      .then((r) => live && setState(r))
      .catch((e) => live && setState({ error: why(e) }))
    return () => { live = false }
  }, [serverId, key, tick])
  const copy = () => { if (state && 'text' in state) void navigator.clipboard?.writeText(state.text) }
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="mb-2 flex items-center justify-between gap-2 text-xs text-muted">
        <span>{note}{state && 'truncated' in state && state.truncated ? ` ${t('lx.cut')}` : ''}</span>
        <span className="flex gap-2">
          <GhostButton size="s" onClick={() => { setState(null); setTick((n) => n + 1) }}>{t('lx.refresh')}</GhostButton>
          <GhostButton size="s" onClick={copy}>{t('lx.copy')}</GhostButton>
        </span>
      </div>
      {!state ? <p className="text-[13px] text-muted" aria-busy="true">{t('state.loading')}</p>
        : 'error' in state ? <p role="alert" className="text-[13px] text-red">{state.error}</p>
        : <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-control bg-canvas p-3 font-mono text-xs leading-5">{state.text || empty}</pre>}
    </Modal>
  )
}

const join = (dir: string, name: string) => `${dir.replace(/\/$/, '')}/${name}`

function Files({ serverId }: { serverId: string }) {
  const roots = useAsk(serverId, { op: 'ls' })
  const [dir, setDir] = useState('')
  const [file, setFile] = useState('')
  const list = useAsk(serverId, dir ? { op: 'ls', path: dir } : null)
  const dirs = roots.data?.dirs ?? []
  // One level up, unless that would leave the allowed folders: then back to the list of them.
  const parent = dir.replace(/\/[^/]*$/, '') || '/'
  const up = () => setDir(dirs.some((d) => parent === d || parent.startsWith(`${d}/`)) ? parent : '')
  return (
    <Card title={t('lx.s.files')} right={dir ? <GhostButton size="s" onClick={up}>{dirs.includes(dir) ? t('lx.roots') : t('lx.up')}</GhostButton> : undefined}>
      {roots.error && <p role="alert" className="text-[13px] text-red">{roots.error}</p>}
      {!dir ? (
        !roots.data && !roots.error ? <p className="py-3 text-[13px] text-muted" aria-busy="true">{t('state.loading')}</p>
          : dirs.length === 0 ? <p className="py-3 text-[13px] text-muted">{t('lx.noFolders')}</p> : (
            <>
              <p className="mb-2 text-xs text-muted">{t('lx.folders')}</p>
              <ul className="space-y-1">
                {dirs.map((d) => (
                  <li key={d}><button type="button" className="inline-flex items-center gap-2 py-1 text-[13px] hover:text-cyan" onClick={() => setDir(d)}><Folder size={14} aria-hidden />{d}</button></li>
                ))}
              </ul>
            </>
          )
      ) : (
        <>
          <p className="mb-2 break-all font-mono text-xs text-muted">{dir}</p>
          {list.error && <p role="alert" className="mb-2 text-[13px] text-red">{list.error}</p>}
          {list.data && list.data.entries.length === 0 && <p className="py-3 text-[13px] text-muted">{t('lx.emptyDir')}</p>}
          {list.data && list.data.entries.length > 0 && (
            <div className="max-h-[60vh] overflow-auto">
              <table className="w-full border-collapse text-[13px]">
                <tbody>
                  {list.data.entries.map((e) => (
                    <tr key={e.name} className="border-t border-line/60">
                      <td className="py-1.5 pr-3">
                        <button type="button" className="inline-flex items-center gap-2 text-left hover:text-cyan" onClick={() => (e.dir ? setDir(join(dir, e.name)) : setFile(join(dir, e.name)))}>
                          {e.dir ? <Folder size={14} aria-hidden /> : <FileIcon size={14} aria-hidden />}{e.name}
                        </button>
                      </td>
                      <td className="tnum pr-3 text-right text-muted">{e.dir ? '' : formatBytes(e.size)}</td>
                      <td className="tnum whitespace-nowrap text-right text-muted">{formatDateTime(e.mod, 'local')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      {file && <TextDialog serverId={serverId} title={t('lx.fileTitle', { name: file })} note={t('lx.fileNote')} empty={t('lx.fileEmpty')} body={{ op: 'cat', path: file, tail: 500 }} onClose={() => setFile('')} />}
    </Card>
  )
}
