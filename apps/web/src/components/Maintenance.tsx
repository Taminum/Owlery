import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { Card } from './ui'
import { GhostButton, inputCls } from './Modal'

const CHOICES: { hours: number; key: 'mnt.h1' | 'mnt.h4' | 'mnt.h24' }[] = [
  { hours: 1, key: 'mnt.h1' }, { hours: 4, key: 'mnt.h4' }, { hours: 24, key: 'mnt.h24' },
]

/** The yellow strip over a machine's tabs while its maintenance window is open. */
export function MaintenanceBanner({ until, note, canEdit, serverId, onChange }: { until: string; note?: string; canEdit: boolean; serverId: string; onChange: () => void }) {
  const [busy, setBusy] = useState(false)
  async function end() {
    setBusy(true)
    try { await api.del(`/api/v1/servers/${serverId}/maintenance`); onChange() } finally { setBusy(false) }
  }
  return (
    <div role="status" className="flex flex-wrap items-center gap-3 rounded-card border border-amber/45 bg-amber/10 px-4 py-2.5 text-[13px]">
      <span className="font-semibold text-amber">{t('mnt.active')}</span>
      <span className="text-muted">{t('mnt.until', { at: formatDateTime(until, 'local') })}{note ? ` («${note}»)` : ''}</span>
      {canEdit && <GhostButton className="ml-auto !h-7 !px-3 !text-xs" disabled={busy} onClick={() => void end()}>{t('mnt.end')}</GhostButton>}
    </div>
  )
}

/** Opens a maintenance window for the machine: its alerts stay quiet until it ends, and come back by themselves if the cause is still there. */
export function Maintenance({ serverId, canEdit, until, note, onChange }: { serverId: string; canEdit: boolean; until?: string; note?: string; onChange: () => void }) {
  const [text, setText] = useState('')
  const [hours, setHours] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  async function start(h: number) {
    setBusy(true)
    setErr('')
    try {
      await api.put(`/api/v1/servers/${serverId}/maintenance`, { hours: h, note: text.trim() })
      setHours('')
      onChange()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  const custom = Math.floor(Number(hours))
  const customOk = custom >= 1 && custom <= 168
  return (
    <Card title={t('mnt.title')} note={t('mnt.hint')}>
      {until && <p className="mb-3 text-[13px] text-amber">{t('mnt.until', { at: formatDateTime(until, 'local') })}{note ? ` («${note}»)` : ''}</p>}
      {err && <p role="alert" className="mb-2 text-[13px] text-red">{err}</p>}
      {canEdit ? (
        <div className="space-y-3">
          <input className={inputCls} maxLength={200} aria-label={t('mnt.note')} placeholder={t('mnt.note')} value={text} onChange={(e) => setText(e.target.value)} />
          <div className="flex flex-wrap items-center gap-2">
            {CHOICES.map((c) => <GhostButton key={c.hours} disabled={busy} onClick={() => void start(c.hours)}>{t(c.key)}</GhostButton>)}
            <input type="number" min={1} max={168} aria-label={t('mnt.custom')} placeholder={t('mnt.custom')} className={`${inputCls} !w-36`} value={hours} onChange={(e) => setHours(e.target.value)} />
            <GhostButton disabled={busy || !customOk} onClick={() => void start(custom)}>{t('mnt.start')}</GhostButton>
          </div>
        </div>
      ) : <p className="text-xs text-muted">{t('mnt.readonly')}</p>}
    </Card>
  )
}
