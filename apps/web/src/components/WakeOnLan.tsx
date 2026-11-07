import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'
import { Card } from './ui'
import { GhostButton } from './Modal'

type Nic = { name: string; mac: string; ips?: string[] }
type View = { enabled: boolean; mac?: string; nics: Nic[]; machine_online: boolean; can_ask: boolean; helpers: number; can_edit: boolean }

/** Wake-on-LAN for a machine: the switch asks the machine's own agent for its network cards, so an address is kept only while it is on. */
export function WakeOnLan({ serverId, onChange }: { serverId: string; onChange: () => void }) {
  const q = useLoad((sig) => api.get<View>(`/api/v1/servers/${serverId}/wol`, sig), [serverId])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const v = q.data
  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!v) return null
  if (!v.can_edit && !v.enabled) return null

  async function put(body: { enabled: boolean; mac?: string }) {
    setBusy(true)
    setErr('')
    try {
      await api.put<View>(`/api/v1/servers/${serverId}/wol`, body)
      q.reload()
      onChange()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  const lacks = !v.enabled && (!v.can_ask || !v.machine_online)
  return (
    <Card title={t('wol.title')} note={t('wol.hint')}>
      {err && <p role="alert" className="mb-2 text-[13px] text-red">{err}</p>}
      <label className="flex items-center gap-2.5 text-[14px]">
        <input type="checkbox" checked={v.enabled} disabled={!v.can_edit || busy || lacks} onChange={(e) => void put({ enabled: e.target.checked })} />
        {t('wol.allow')}
      </label>
      {lacks && v.can_edit && <p className="mt-2 text-xs text-muted">{t(v.can_ask ? 'wol.needOn' : 'wol.needNew')}</p>}
      {v.enabled && (
        <div className="mt-3">
          <p className="mb-1 text-xs text-muted">{t('wol.which')}</p>
          <div role="radiogroup" aria-label={t('wol.which')} className="space-y-1.5">
            {v.nics.map((n) => (
              <label key={n.mac} className={`flex flex-wrap items-center gap-3 rounded-control border px-3 py-1.5 text-[13px] ${n.mac === v.mac ? 'border-cyan bg-elevated' : 'border-line'}`}>
                <input type="radio" name="wol-nic" checked={n.mac === v.mac} disabled={!v.can_edit || busy} onChange={() => void put({ enabled: true, mac: n.mac })} />
                <span className="font-medium">{n.name}</span>
                <span className="font-mono text-xs">{n.mac}</span>
                <span className="text-xs text-muted">{(n.ips ?? []).join(', ')}</span>
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted">{t('wol.helpers', { n: v.helpers })}</p>
          {v.can_edit && !v.machine_online && <div className="mt-3"><WakeButton serverId={serverId} onDone={onChange} /></div>}
        </div>
      )}
    </Card>
  )
}

/** Sends the signal that switches the machine on, and says what came of it next to the button. */
export function WakeButton({ serverId, onDone, small }: { serverId: string; onDone?: () => void; small?: boolean }) {
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null)
  return (
    <span className="inline-flex items-center gap-2">
      <GhostButton disabled={busy} className={small ? '!h-6 !rounded-[9px] !px-2.5 !text-xs' : ''}
        onClick={(e) => {
          e.preventDefault() // inside a link in the list
          e.stopPropagation()
          setBusy(true)
          setNote(null)
          api.post(`/api/v1/servers/${serverId}/wake`)
            .then(() => { setNote({ ok: true, text: t('wol.sent') }); onDone?.() })
            .catch((x) => setNote({ ok: false, text: errorText(x) }))
            .finally(() => setBusy(false))
        }}>
        ⏻ {t('wol.wake')}
      </GhostButton>
      {note && <span role={note.ok ? 'status' : 'alert'} className={`text-xs ${note.ok ? 'text-green' : 'text-red'}`}>{note.text}</span>}
    </span>
  )
}
