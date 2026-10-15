import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from './ui'
import { DangerButton, Field, GhostButton, PrimaryButton, inputCls } from './Modal'

interface Channel {
  id: string; kind: string; name: string; chat_hint: string; enabled: boolean; on_alerts: boolean
  digest_hour: number | null; digest_tz: string; last_ok_at: string | null; last_error: string | null
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
  const { data, error, reload } = useLoad((s) => api.get<{ channels: Channel[]; max: number }>('/api/v1/notify/channels', s), [], 30_000)
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
                <GhostButton onClick={() => void act(() => api.post(`/api/v1/notify/channels/${c.id}/test`), t('ntf.sent'))}>{t('ntf.test')}</GhostButton>
                <GhostButton onClick={() => void act(() => api.patch(`/api/v1/notify/channels/${c.id}`, { enabled: !c.enabled }))}>{c.enabled ? t('ntf.disable') : t('ntf.enable')}</GhostButton>
                <DangerButton onClick={() => void act(() => api.del(`/api/v1/notify/channels/${c.id}`))}>{t('ntf.delete')}</DangerButton>
              </span>
            </li>
          ))}
        </ul>
        {msg && <p role="status" className="mt-2 text-[13px] text-green">{msg}</p>}
        {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
      </Card>
      {data.channels.length < data.max && <AddChannel onDone={reload} />}
    </div>
  )
}
