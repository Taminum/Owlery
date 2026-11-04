import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { BlockEntry, BlockSettings, BlockView } from '../lib/types'
import { Card } from './ui'
import { GhostButton, PrimaryButton, inputCls } from './Modal'

const MODES: BlockSettings['mode'][] = ['off', 'watch', 'block']

function Tile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-control bg-elevated px-3 py-2.5">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-0.5 text-[18px] font-semibold leading-6">{value}</div>
    </div>
  )
}

function Notice({ children }: { children: string }) {
  return <p role="status" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{children}</p>
}

function EntryTable({ rows, action, label, windowMin }: { rows: BlockEntry[]; action?: (ip: string) => void; label: string; windowMin: number }) {
  return (
    <table className="w-full text-[13px]">
      <thead>
        <tr className="text-left text-xs text-muted">
          <th className="py-1 font-normal">{t('prot.col.ip')}</th>
          <th className="py-1 font-normal">{t('prot.col.why')}</th>
          <th className="py-1 font-normal">{t('prot.col.until')}</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {rows.map((e) => (
          <tr key={e.ip + e.since} className="border-t border-line/60">
            <td className="py-1.5 font-mono">{e.ip}</td>
            <td>{t('prot.why', { n: e.failed, m: windowMin })}</td>
            <td className="tnum text-muted">{e.until ? formatDateTime(e.until, 'local') : t('prot.forever')}</td>
            <td className="text-right">{action && <GhostButton onClick={() => action(e.ip)}>{label}</GhostButton>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** The "Защита RDP" tab: how the machine's address blocker is set up, what it has done, and the buttons to change both. */
export function RdpProtect({ serverId }: { serverId: string }) {
  const q = useLoad((sig) => api.get<BlockView>(`/api/v1/servers/${serverId}/block`, sig), [serverId], 20_000)
  const [draft, setDraft] = useState<BlockSettings | null>(null)
  const [entry, setEntry] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const v = q.data

  // The draft follows the server until somebody starts editing; after a save it follows again.
  useEffect(() => { if (v && !draft) setDraft(v.settings) }, [v, draft])
  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!v || !draft) return <p className="text-[13px] text-muted">…</p>

  const dirty = JSON.stringify(draft) !== JSON.stringify(v.settings)
  const edit = (p: Partial<BlockSettings>) => { setMsg(''); setDraft({ ...draft, ...p }) }
  const num = (s: string) => Math.max(0, Math.floor(Number(s) || 0))

  async function save() {
    setBusy(true)
    setErr('')
    try {
      await api.put<BlockView>(`/api/v1/servers/${serverId}/block`, draft)
      setDraft(null)
      setMsg(t('prot.saved'))
      q.reload()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  async function unblock(ip: string) {
    setErr('')
    try {
      await api.post(`/api/v1/servers/${serverId}/block/unblock`, { ip })
      q.reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  function addEntry() {
    const x = entry.trim()
    if (!x || draft!.whitelist.includes(x)) return
    edit({ whitelist: [...draft!.whitelist, x] })
    setEntry('')
  }

  const st = v.state
  const mode = st?.mode ?? v.settings.mode
  const canUnblock = v.can_edit && v.online
  const ro = !v.can_edit
  return (
    <div className="space-y-4">
      {!v.supported && <Notice>{t('prot.unsupported')}</Notice>}
      {v.supported && draft.mode === 'block' && !v.can_block && <Notice>{t('prot.noPermission')}</Notice>}
      {v.supported && !v.online && <Notice>{t('prot.offline')}</Notice>}
      {st?.error && <Notice>{st.error}</Notice>}
      {err && <p role="alert" className="text-[13px] text-red">{err}</p>}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Tile label={t('prot.mode')} value={t(`prot.mode.${mode}` as 'prot.mode.off')} />
        <Tile label={t('prot.active')} value={st?.active.length ?? 0} />
        <Tile label={t('prot.total')} value={st?.total ?? 0} />
        <Tile label={t('prot.would')} value={st?.would.length ?? 0} />
      </div>

      <Card title={t('prot.settings')}>
        <div className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-3 text-[13px]">
          <span className="text-muted">{t('prot.mode')}</span>
          <div role="radiogroup" aria-label={t('prot.mode')} className="flex flex-wrap gap-2">
            {MODES.map((m) => (
              <button key={m} type="button" role="radio" aria-checked={draft.mode === m} disabled={ro} onClick={() => edit({ mode: m })}
                className={`h-8 rounded-control border px-3 text-[13px] ${draft.mode === m ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'} disabled:cursor-not-allowed disabled:opacity-60`}>{t(`prot.mode.${m}` as 'prot.mode.off')}</button>
            ))}
          </div>
          <span className="text-muted">{t('prot.rule')}</span>
          <span className="flex flex-wrap items-center gap-2">
            {t('prot.rule.a')}
            <input aria-label={t('prot.rule.b')} type="number" min={2} max={1000} className={`${inputCls} w-20`} value={draft.threshold} disabled={ro} onChange={(e) => edit({ threshold: num(e.target.value) })} />
            {t('prot.rule.b')}
            <input aria-label={t('prot.rule.c')} type="number" min={1} max={1440} className={`${inputCls} w-20`} value={draft.window_min} disabled={ro} onChange={(e) => edit({ window_min: num(e.target.value) })} />
            {t('prot.rule.c')}
          </span>
          <span className="text-muted">{t('prot.ttl')}</span>
          <span className="flex flex-wrap items-center gap-2">
            <input aria-label={t('prot.ttl')} type="number" min={0} max={8760} className={`${inputCls} w-24`} value={draft.ttl_hours} disabled={ro} onChange={(e) => edit({ ttl_hours: num(e.target.value) })} />
            {t('prot.ttl.h')}
          </span>
        </div>
        {!ro && (
          <div className="mt-4 flex items-center gap-3">
            <PrimaryButton onClick={() => void save()} disabled={busy || !dirty}>{t('prot.save')}</PrimaryButton>
            {msg && <span role="status" className="text-[13px] text-green">{msg}</span>}
          </div>
        )}
        {ro && <p className="mt-3 text-xs text-muted">{t('prot.readonly')}</p>}
      </Card>

      <Card title={t('prot.whitelist')} note={t('prot.whitelist.hint')}>
        <div className="flex flex-wrap gap-2">
          {draft.whitelist.map((w) => (
            <span key={w} className="inline-flex items-center gap-1.5 rounded-full border border-cyan/40 px-2.5 py-1 font-mono text-xs text-cyan">
              {w}
              {!ro && <button type="button" aria-label={t('prot.whitelist.remove', { ip: w })} onClick={() => edit({ whitelist: draft.whitelist.filter((x) => x !== w) })}><X size={13} aria-hidden /></button>}
            </span>
          ))}
        </div>
        {!ro && (
          <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); addEntry() }}>
            <input aria-label={t('prot.whitelist')} className={`${inputCls} flex-1`} value={entry} placeholder={t('prot.whitelist.ph')} onChange={(e) => setEntry(e.target.value)} />
            <GhostButton type="submit">{t('prot.whitelist.add')}</GhostButton>
          </form>
        )}
      </Card>

      <Card title={t('prot.blocked')}>
        {st && st.active.length > 0
          ? <EntryTable rows={st.active} action={canUnblock ? unblock : undefined} label={t('prot.unblock')} windowMin={st.window_min} />
          : <p className="text-[13px] text-muted">{t('prot.blocked.empty')}</p>}
      </Card>

      {st && st.would.length > 0 && (
        <Card title={t('prot.wouldList')}>
          <EntryTable rows={st.would} action={canUnblock ? unblock : undefined} label={t('prot.exclude')} windowMin={st.window_min} />
        </Card>
      )}
    </div>
  )
}
