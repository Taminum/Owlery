import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import type { VPS } from '../lib/types'
import { AgentSetupDialog } from './AgentSetup'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

type OS = 'linux' | 'windows'

/**
 * Adding a machine in one go: its name and where it can be reached, then at once its agent with the command that
 * installs it. The machine is created first, so closing the dialog on the second step leaves a machine that still
 * shows on the fleet page and can be given its agent from its own card.
 */
export function AddServer({ onClose }: { onClose: () => void }) {
  const nav = useNavigate()
  const [name, setName] = useState('')
  const [addrs, setAddrs] = useState('')
  const [os, setOS] = useState<OS>('linux')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [made, setMade] = useState<{ id: string; token: string } | null>(null)

  async function create() {
    setBusy(true)
    setError('')
    try {
      const v = await api.post<VPS>('/api/v1/security/vps', { name: name.trim(), addresses: addrs.split('\n').map((x) => x.trim()).filter(Boolean) })
      try {
        const r = await api.post<{ token: string }>(`/api/v1/security/vps/${v.id}/agent`)
        setMade({ id: v.id, token: r.token })
      } catch (e) {
        // The machine exists; only its agent failed. Say so and go to its card, where the agent can be made again.
        nav(`/servers/${v.id}`)
        throw e
      }
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }

  if (made) {
    return <AgentSetupDialog mode="install" token={made.token} initial={{ shell: true, web: true, desk: os === 'windows', scr: false, adm: false, probe: false }} initialOS={os}
      onClose={() => { onClose(); nav(`/servers/${made.id}`) }} />
  }
  return (
    <Modal title={t('add.title')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && name.trim()) void create() }}>
        <Field label={t('sec.name')} htmlFor="add-name"><input id="add-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} data-autofocus placeholder="exit-3" /></Field>
        <Field label={t('add.os')} htmlFor="add-os">
          <select id="add-os" className={inputCls} value={os} onChange={(e) => setOS(e.target.value as OS)}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
          </select>
        </Field>
        <Field label={t('sec.addresses')} hint={t('add.addrHint')} htmlFor="add-addrs">
          <textarea id="add-addrs" className={`${inputCls} h-20 py-2 font-mono text-[13px]`} value={addrs} onChange={(e) => setAddrs(e.target.value)} spellCheck={false} />
        </Field>
        <p className="text-xs text-muted">{t('add.next')}</p>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !name.trim()}>{t('add.go')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}
