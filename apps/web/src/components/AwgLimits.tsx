import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatBytes, formatDateTime } from '../lib/format'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

export interface LimitInfo {
  expires_at: string | null
  traffic_limit_bytes: number | null
  used_bytes: number
  auto_revoked?: string
}

const GIB = 1024 ** 3

/** What a device's limits are, in one short line under its name. */
export function LimitLine({ p, tz }: { p: LimitInfo; tz: string }) {
  const parts: string[] = []
  if (p.expires_at) parts.push(t('awgl.until', { when: formatDateTime(p.expires_at, tz) }))
  if (p.traffic_limit_bytes) parts.push(t('awgl.used', { used: formatBytes(p.used_bytes), limit: formatBytes(p.traffic_limit_bytes) }))
  if (p.auto_revoked) parts.push(t(`awgl.auto.${p.auto_revoked}` as 'awgl.auto.expired'))
  if (parts.length === 0) return null
  return <div className={`text-xs ${p.auto_revoked ? 'text-amber' : 'text-muted'}`}>{parts.join(' · ')}</div>
}

function toLocalInput(iso: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** Sets or clears a device's expiry and traffic allowance. The warning is the point of the window: when time or
 *  allowance runs out the device is revoked on the server and has to be created again. */
export function DeviceLimits({ peerId, label, current, onClose, onDone }: { peerId: string; label: string; current: LimitInfo; onClose: () => void; onDone: () => void }) {
  const [until, setUntil] = useState(toLocalInput(current.expires_at))
  const [gib, setGib] = useState(current.traffic_limit_bytes ? String(Math.round((current.traffic_limit_bytes / GIB) * 100) / 100) : '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const g = gib.trim() === '' ? null : Number(gib.replace(',', '.'))
  const gOk = g === null || (Number.isFinite(g) && g >= 0.01 && g <= 100000)

  async function save() {
    setBusy(true)
    setError('')
    try {
      await api.put(`/api/v1/awg/peers/${peerId}/limits`, {
        expires_at: until ? new Date(until).toISOString() : null,
        traffic_limit_bytes: g === null ? null : Math.round(g * GIB),
      })
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('awgl.title', { name: label })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (gOk && !busy) void save() }}>
        <p role="note" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{t('awgl.warn')}</p>
        <Field label={t('awgl.until.label')} hint={t('awgl.until.hint')} htmlFor="awgl-until">
          <input id="awgl-until" type="datetime-local" className={inputCls} value={until} onChange={(e) => setUntil(e.target.value)} />
        </Field>
        <Field label={t('awgl.gib.label')} hint={t('awgl.gib.hint')} htmlFor="awgl-gib">
          <input id="awgl-gib" className={inputCls} value={gib} onChange={(e) => setGib(e.target.value)} inputMode="decimal" placeholder="—" />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !gOk}>{t('awgl.save')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}
