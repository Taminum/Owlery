import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import type { ServerAlert, ServerNode, ServerRole, VPS } from '../lib/types'
import { Chip } from './ui'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'
import type { Host } from './HostView'

// A machine of the fleet as the servers API returns it.
export interface Server extends VPS {
  status: 'ok' | 'warn' | 'bad' | 'unknown'
  reason: '' | 'offline' | 'critical' | 'alerts' | 'no_agent'
  host: Host | null
  nodes: ServerNode[]
  alerts_open: number
  alerts_critical: number
  alerts?: ServerAlert[]
}

export const ROLES: ServerRole[] = ['entry', 'exit', 'panel', 'service', 'workstation', 'home', 'hypervisor', 'router']

const STATUS_TONE = { ok: 'green', warn: 'amber', bad: 'red', unknown: 'muted' } as const

export function StatusChip({ s }: { s: Server }) {
  return (
    <span title={s.reason ? t(`srv.reason.${s.reason}` as MsgKey) : undefined}>
      <Chip tone={STATUS_TONE[s.status]}>{t(`srv.status.${s.status}` as MsgKey)}</Chip>
    </span>
  )
}

export function StatusDot({ s }: { s: Server }) {
  const color = { ok: 'bg-green', warn: 'bg-amber', bad: 'bg-red', unknown: 'bg-muted' }[s.status]
  return <span className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${color}`} aria-hidden />
}

export function RoleChips({ roles }: { roles?: ServerRole[] }) {
  if (!roles?.length) return null
  return (
    <span className="flex flex-wrap gap-1">
      {roles.map((r) => <span key={r} className="rounded-full border border-line px-2 py-0.5 text-[11px] text-muted">{t(`srv.role.${r}` as MsgKey)}</span>)}
    </span>
  )
}

/** How long an alert lasted (or has lasted), in words. */
export function durationText(fromIso: string, toIso: string | null): string {
  const min = Math.max(1, Math.round(((toIso ? new Date(toIso).getTime() : Date.now()) - new Date(fromIso).getTime()) / 60000))
  if (min < 60) return t('srv.min', { n: min })
  const h = Math.floor(min / 60)
  if (h < 24) return t('srv.hours', { h, m: min % 60 })
  return t('srv.days', { d: Math.floor(h / 24), h: h % 24 })
}

/** Where the machine is, in one line: city and country, or nothing. */
export function placeText(s: VPS): string {
  return [s.city, s.country].filter(Boolean).join(', ')
}

export function InventoryDialog({ s, onClose, onDone }: { s: Server; onClose: () => void; onDone: () => void }) {
  const [roles, setRoles] = useState<ServerRole[]>(s.roles ?? [])
  const [os, setOS] = useState(s.os ?? '')
  const [provider, setProvider] = useState(s.provider ?? '')
  const [country, setCountry] = useState(s.country ?? '')
  const [city, setCity] = useState(s.city ?? '')
  const [group, setGroup] = useState(s.group ?? '')
  const [tags, setTags] = useState((s.tags ?? []).join(', '))
  const [purchased, setPurchased] = useState(s.purchased_on ? s.purchased_on.slice(0, 10) : '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const toggle = (r: ServerRole) => setRoles(roles.includes(r) ? roles.filter((x) => x !== r) : ROLES.filter((x) => x === r || roles.includes(x)))
  async function save() {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/security/vps/${s.id}`, {
        inventory: { roles, os, provider, country, city, group, purchased_on: purchased, tags: tags.split(',').map((x) => x.trim()).filter(Boolean) },
      })
      onDone()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('srv.inv.title', { name: s.name })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy) void save() }}>
        <fieldset>
          <legend className="mb-2 text-[13px] text-muted">{t('srv.inv.roles')}</legend>
          <div className="flex flex-wrap gap-2">
            {ROLES.map((r) => (
              <button key={r} type="button" aria-pressed={roles.includes(r)} onClick={() => toggle(r)}
                className={`h-8 rounded-full border px-3 text-[12px] ${roles.includes(r) ? 'border-cyan bg-cyan/15 text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(`srv.role.${r}` as MsgKey)}</button>
            ))}
          </div>
        </fieldset>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t('srv.inv.os')} hint={t('srv.inv.osHint')} htmlFor="inv-os"><input id="inv-os" className={inputCls} value={os} onChange={(e) => setOS(e.target.value)} maxLength={80} /></Field>
          <Field label={t('srv.inv.provider')} htmlFor="inv-prov"><input id="inv-prov" className={inputCls} value={provider} onChange={(e) => setProvider(e.target.value)} maxLength={80} /></Field>
          <Field label={t('srv.inv.country')} htmlFor="inv-country"><input id="inv-country" className={inputCls} value={country} onChange={(e) => setCountry(e.target.value)} maxLength={60} /></Field>
          <Field label={t('srv.inv.city')} htmlFor="inv-city"><input id="inv-city" className={inputCls} value={city} onChange={(e) => setCity(e.target.value)} maxLength={60} /></Field>
          <Field label={t('srv.inv.group')} hint={t('srv.inv.groupHint')} htmlFor="inv-group"><input id="inv-group" className={inputCls} value={group} onChange={(e) => setGroup(e.target.value)} maxLength={60} /></Field>
          <Field label={t('srv.inv.purchased')} htmlFor="inv-date"><input id="inv-date" type="date" className={inputCls} value={purchased} onChange={(e) => setPurchased(e.target.value)} /></Field>
        </div>
        <Field label={t('srv.inv.tags')} hint={t('srv.inv.tagsHint')} htmlFor="inv-tags"><input id="inv-tags" className={inputCls} value={tags} onChange={(e) => setTags(e.target.value)} /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy}>{t('srv.inv.save')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}
