import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from './ui'
import { DangerButton, Field, GhostButton, PrimaryButton, inputCls } from './Modal'

interface Prefs { off?: string[]; no_resolved?: boolean; quiet_on?: boolean; quiet_from?: string; quiet_to?: string; remind_hours?: number }
interface Channel {
  id: string; kind: string; name: string; chat_hint: string; enabled: boolean; on_alerts: boolean
  digest_hour: number | null; digest_tz: string; last_ok_at: string | null; last_error: string | null
  prefs: Prefs; commands: boolean; muted_until: string | null
}
interface Group { id: string; kinds: string[] }

const REMIND = [0, 1, 3, 6, 12, 24] as const

/** The fine tuning of one channel: what is announced, when, and what the bot answers. */
function Tuning({ ch, groups, critical, onDone }: { ch: Channel; groups: Group[]; critical: string[]; onDone: () => void }) {
  const [off, setOff] = useState<string[]>(ch.prefs.off ?? [])
  const [resolved, setResolved] = useState(!ch.prefs.no_resolved)
  const [quiet, setQuiet] = useState(!!ch.prefs.quiet_on)
  const [from, setFrom] = useState(ch.prefs.quiet_from || '23:00')
  const [to, setTo] = useState(ch.prefs.quiet_to || '08:00')
  const [remind, setRemind] = useState(ch.prefs.remind_hours ?? 0)
  const [commands, setCommands] = useState(ch.commands)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const toggle = (id: string) => setOff((o) => (o.includes(id) ? o.filter((x) => x !== id) : [...o, id]))

  async function save() {
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      const prefs: Prefs = { off, no_resolved: !resolved, quiet_on: quiet, remind_hours: remind }
      if (quiet) { prefs.quiet_from = from; prefs.quiet_to = to }
      await api.patch(`/api/v1/notify/channels/${ch.id}`, { prefs, commands })
      setMsg(t('ntf.tune.saved'))
      onDone()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  async function mute(hours: number) {
    setErr('')
    try {
      await api.patch(`/api/v1/notify/channels/${ch.id}`, { mute_hours: hours })
      onDone()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <div className="mt-3 w-full space-y-4 rounded-control border border-line bg-elevated/40 p-3">
      <fieldset>
        <legend className="mb-1 text-[13px] font-medium">{t('ntf.tune.groups')}</legend>
        <p className="mb-2 text-xs text-muted">{t('ntf.tune.groups.hint')}</p>
        <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
          {groups.map((g) => (
            <label key={g.id} className="flex items-start gap-2 text-[13px]">
              <input type="checkbox" className="mt-0.5" checked={!off.includes(g.id)} onChange={() => toggle(g.id)} />
              <span>{t(`ntf.g.${g.id}` as MsgKey)}{g.kinds.some((k) => critical.includes(k)) && <span className="ml-1 text-xs text-amber" title={t('ntf.tune.critical')}>●</span>}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={resolved} onChange={(e) => setResolved(e.target.checked)} />{t('ntf.tune.resolved')}</label>
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <label className="flex items-center gap-2"><input type="checkbox" checked={quiet} onChange={(e) => setQuiet(e.target.checked)} />{t('ntf.tune.quiet')}</label>
        {quiet && (
          <>
            <input type="time" aria-label={t('ntf.tune.from')} className={`${inputCls} w-28`} value={from} onChange={(e) => setFrom(e.target.value)} />
            <span className="text-muted">—</span>
            <input type="time" aria-label={t('ntf.tune.to')} className={`${inputCls} w-28`} value={to} onChange={(e) => setTo(e.target.value)} />
          </>
        )}
      </div>
      {quiet && <p className="-mt-2 text-xs text-muted">{t('ntf.tune.quiet.hint', { tz: ch.digest_tz })}</p>}
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <label htmlFor={`rem-${ch.id}`}>{t('ntf.tune.remind')}</label>
        <select id={`rem-${ch.id}`} className={`${inputCls} w-40`} value={remind} onChange={(e) => setRemind(Number(e.target.value))}>
          {REMIND.map((h) => <option key={h} value={h}>{h === 0 ? t('ntf.tune.remind.never') : t('ntf.tune.remind.every', { h })}</option>)}
        </select>
      </div>
      <label className="flex items-start gap-2 text-[13px]"><input type="checkbox" className="mt-0.5" checked={commands} onChange={(e) => setCommands(e.target.checked)} /><span>{t('ntf.tune.commands')}<span className="block text-xs text-muted">{t('ntf.tune.commands.hint')}</span></span></label>
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <span className="text-muted">{ch.muted_until ? t('ntf.tune.mutedUntil', { at: formatDateTime(ch.muted_until, 'local') }) : t('ntf.tune.mute')}</span>
        {[1, 8, 24].map((h) => <GhostButton key={h} onClick={() => void mute(h)}>{t('ntf.tune.mute.h', { h })}</GhostButton>)}
        {ch.muted_until && <GhostButton onClick={() => void mute(0)}>{t('ntf.tune.unmute')}</GhostButton>}
      </div>
      {msg && <p role="status" className="text-[13px] text-green">{msg}</p>}
      {err && <p role="alert" className="text-[13px] text-red">{err}</p>}
      <PrimaryButton onClick={() => void save()} disabled={busy}>{t('ntf.tune.save')}</PrimaryButton>
    </div>
  )
}
interface ChatItem { id: string; title: string }

const TZS = ['UTC', 'Europe/Moscow', 'Asia/Yekaterinburg']
const HOURS = Array.from({ length: 24 }, (_, i) => i)

function AddChannel({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState('Telegram')
  const [token, setToken] = useState('')
  const [chat, setChat] = useState('')
  const [chats, setChats] = useState<ChatItem[] | null>(null)
  const [bot, setBot] = useState('')
  const [onAlerts, setOnAlerts] = useState(true)
  const [digest, setDigest] = useState(true)
  const [hour, setHour] = useState(9)
  const [tz, setTz] = useState('Asia/Yekaterinburg')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function find() {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ bot: string; chats: ChatItem[] }>('/api/v1/notify/telegram/discover', { token: token.trim() })
      setBot(r.bot)
      setChats(r.chats)
      if (r.chats[0]) setChat(r.chats[0].id)
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  async function create() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/notify/channels', { name: name.trim(), token: token.trim(), chat_id: chat.trim(), on_alerts: onAlerts, digest_hour: digest ? hour : null, digest_tz: tz })
      setToken('')
      onDone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card title={t('ntf.add.title')} note={t('ntf.add.hint')}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && token.trim() && chat.trim()) void create() }}>
        <Field label={t('ntf.name')} htmlFor="ntf-name"><input id="ntf-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} /></Field>
        <Field label={t('ntf.token')} hint={t('ntf.token.hint')} htmlFor="ntf-token">
          <input id="ntf-token" type="password" autoComplete="off" className={`${inputCls} font-mono`} value={token} onChange={(e) => setToken(e.target.value)} spellCheck={false} />
        </Field>
        <div className="flex flex-wrap items-center gap-3">
          <GhostButton onClick={() => void find()} disabled={busy || !token.trim()}>{t('ntf.find')}</GhostButton>
          {bot && <span className="text-[13px] text-muted">{t('ntf.bot', { name: bot })}</span>}
        </div>
        {chats && chats.length === 0 && <p className="text-[13px] text-amber">{t('ntf.nochats', { name: bot })}</p>}
        {chats && chats.length > 0 && (
          <Field label={t('ntf.chat')} htmlFor="ntf-chat">
            <select id="ntf-chat" className={inputCls} value={chat} onChange={(e) => setChat(e.target.value)}>
              {chats.map((c) => <option key={c.id} value={c.id}>{c.title} · {c.id}</option>)}
            </select>
          </Field>
        )}
        {!chats && <Field label={t('ntf.chatId')} hint={t('ntf.chatId.hint')} htmlFor="ntf-chatid"><input id="ntf-chatid" className={`${inputCls} font-mono`} value={chat} onChange={(e) => setChat(e.target.value)} inputMode="numeric" /></Field>}
        <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={onAlerts} onChange={(e) => setOnAlerts(e.target.checked)} />{t('ntf.onAlerts')}</label>
        <div className="flex flex-wrap items-center gap-3 text-[13px]">
          <label className="flex items-center gap-2"><input type="checkbox" checked={digest} onChange={(e) => setDigest(e.target.checked)} />{t('ntf.digest')}</label>
          {digest && (
            <>
              <select aria-label={t('ntf.hour')} className={inputCls + ' w-24'} value={hour} onChange={(e) => setHour(Number(e.target.value))}>{HOURS.map((h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}</select>
              <select aria-label={t('ntf.tz')} className={inputCls + ' w-56'} value={tz} onChange={(e) => setTz(e.target.value)}>{TZS.map((z) => <option key={z} value={z}>{z}</option>)}</select>
            </>
          )}
        </div>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <PrimaryButton type="submit" disabled={busy || !token.trim() || !chat.trim()}>{t('ntf.create')}</PrimaryButton>
      </form>
    </Card>
  )
}

export function NotifyTab() {
  const { data, error, reload } = useLoad((s) => api.get<{ channels: Channel[]; max: number; groups: Group[]; critical: string[] }>('/api/v1/notify/channels', s), [], 30_000)
  const [tuning, setTuning] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  async function act(fn: () => Promise<unknown>, ok = '') {
    setErr('')
    setMsg('')
    try {
      await fn()
      setMsg(ok)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return null
  return (
    <div className="space-y-4">
      <Card title={t('ntf.title')} note={t('ntf.note')}>
        {data.channels.length === 0 && <p className="text-[13px] text-muted">{t('ntf.none')}</p>}
        <ul className="divide-y divide-line text-[13px]">
          {data.channels.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <span>
                <span className="font-medium">{c.name}</span> <span className="text-xs text-muted">Telegram {c.chat_hint}</span>
                <span className="mt-1 block text-xs text-muted">
                  {c.on_alerts ? t('ntf.row.alerts') : t('ntf.row.noAlerts')}
                  {' · '}{c.digest_hour === null ? t('ntf.row.noDigest') : t('ntf.row.digest', { h: String(c.digest_hour).padStart(2, '0'), tz: c.digest_tz })}
                  {c.last_ok_at && <> {' · '}{t('ntf.row.ok', { at: formatDateTime(c.last_ok_at, 'local') })}</>}
                </span>
                {c.last_error && <span className="block text-xs text-red">{t('ntf.row.error', { code: c.last_error })}</span>}
              </span>
              <span className="flex flex-wrap items-center gap-2">
                <Chip tone={c.enabled ? 'green' : 'muted'}>{c.enabled ? t('ntf.on') : t('ntf.off')}</Chip>
                <GhostButton onClick={() => setTuning(tuning === c.id ? '' : c.id)} aria-expanded={tuning === c.id}>{t('ntf.tune')}</GhostButton>
                <GhostButton onClick={() => void act(() => api.post(`/api/v1/notify/channels/${c.id}/test`), t('ntf.sent'))}>{t('ntf.test')}</GhostButton>
                <GhostButton onClick={() => void act(() => api.patch(`/api/v1/notify/channels/${c.id}`, { enabled: !c.enabled }))}>{c.enabled ? t('ntf.disable') : t('ntf.enable')}</GhostButton>
                <DangerButton onClick={() => void act(() => api.del(`/api/v1/notify/channels/${c.id}`))}>{t('ntf.delete')}</DangerButton>
              </span>
              {tuning === c.id && <Tuning ch={c} groups={data.groups} critical={data.critical} onDone={reload} />}
            </li>
          ))}
        </ul>
        {msg && <p role="status" className="mt-2 text-[13px] text-green">{msg}</p>}
        {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
      </Card>
      <Card title={t('ntf.cmds.title')} note={t('ntf.cmds.note')}>
        <ul className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-2">
          {(['stats', 'servers', 'alerts', 'bans', 'certs', 'pay', 'awg', 'users', 'dns', 'mute', 'unmute', 'help'] as const).map((c) => <li key={c}><code className="text-cyan">/{c}</code> <span className="text-muted">{t(`ntf.cmd.${c}` as MsgKey)}</span></li>)}
        </ul>
      </Card>
      {data.channels.length < data.max && <AddChannel onDone={reload} />}
    </div>
  )
}
