import { useState } from 'react'
import { t } from '../i18n'
import { api, postBlob } from '../lib/api'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'
import { GhostButton, Field, Modal, PrimaryButton, inputCls } from './Modal'

const NAMES = ['amnezia-awg', 'amnezia-awg2', 'amnezia-awg3', 'amnezia-awg4', 'amnezia-awg5']
const MIN_PASS = 10

interface Host { id: string; node_name: string; online: boolean; container_admin: boolean; containers: string[] }

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

function freeName(h: Host | undefined): string {
  return NAMES.find((n) => !h?.containers.includes(n)) ?? ''
}

function Done({ name, onClose }: { name: string; onClose: () => void }) {
  return (
    <Modal title={t('awgc.done.title')} onClose={onClose}>
      <p className="text-[13px]">{t('awgb.done', { name })}</p>
      <div className="mt-4 flex justify-end"><PrimaryButton onClick={onClose}>{t('awg.new.done')}</PrimaryButton></div>
    </Modal>
  )
}

/** An encrypted copy of one container. The file is produced once and kept nowhere on the server. */
export function BackupContainer({ instanceId, container, onClose }: { instanceId: string; container: string; onClose: () => void }) {
  const [pass, setPass] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  const valid = pass.length >= MIN_PASS && pass === again

  async function go() {
    setBusy(true)
    setError('')
    try {
      const blob = await postBlob(`/api/v1/awg/instances/${instanceId}/backup`, { passphrase: pass })
      save(blob, `${container}-backup.rsawg`)
      setPass('')
      setAgain('')
      setDone(true)
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={t('awgb.backup.title', { name: container })} onClose={onClose} busy={busy}>
      {done ? (
        <div className="space-y-4">
          <p className="text-[13px]">{t('awgb.backup.done')}</p>
          <div className="flex justify-end"><PrimaryButton onClick={onClose}>{t('awg.new.done')}</PrimaryButton></div>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void go() }}>
          <p className="text-[13px] text-muted">{t('awgb.backup.hint')}</p>
          <Field label={t('awgb.pass')} htmlFor="awgb-pass"><input id="awgb-pass" type="password" className={inputCls} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" /></Field>
          <Field label={t('awgb.pass2')} htmlFor="awgb-pass2"><input id="awgb-pass2" type="password" className={inputCls} value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" /></Field>
          {again !== '' && pass !== again && <p className="text-[13px] text-amber">{t('awgb.pass.mismatch')}</p>}
          {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
          <div className="flex justify-end gap-3">
            <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
            <PrimaryButton type="submit" disabled={!valid || busy}>{t('awgb.backup.go')}</PrimaryButton>
          </div>
        </form>
      )}
    </Modal>
  )
}

/** Moves a container's configuration to another host, through the server, without keeping it. */
export function TransferContainer({ instanceId, container, onClose, onDone }: { instanceId: string; container: string; onClose: () => void; onDone: () => void }) {
  const { data } = useLoad((s) => api.get<{ hosts: Host[] }>('/api/v1/awg/hosts', s), [])
  const hosts = (data?.hosts ?? []).filter((h) => h.online && h.container_admin)
  const [hostId, setHostId] = useState('')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk] = useState('')
  const host = hosts.find((h) => h.id === hostId) ?? hosts[0]
  const chosen = name || freeName(host)

  async function go() {
    if (!host) return
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/awg/instances/${instanceId}/transfer`, { host_id: host.id, container: chosen })
      setOk(chosen)
      onDone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (ok) return <Done name={ok} onClose={onClose} />
  return (
    <Modal title={t('awgb.transfer.title', { name: container })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (host && chosen && !busy) void go() }}>
        <p className="text-[13px] text-muted">{t('awgb.transfer.hint')}</p>
        <p role="note" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px]">{t('awgb.transfer.warn')}</p>
        <Field label={t('awgb.host')} htmlFor="awgb-host">
          <select id="awgb-host" className={inputCls} value={host?.id ?? ''} onChange={(e) => { setHostId(e.target.value); setName('') }}>
            {hosts.map((h) => <option key={h.id} value={h.id}>{h.node_name}</option>)}
          </select>
        </Field>
        <Field label={t('awgc.name')} htmlFor="awgb-name">
          <select id="awgb-name" className={inputCls} value={chosen} onChange={(e) => setName(e.target.value)}>
            {NAMES.map((n) => <option key={n} value={n} disabled={!!host?.containers.includes(n)}>{n}{host?.containers.includes(n) ? ` (${t('awgc.taken')})` : ''}</option>)}
          </select>
        </Field>
        {busy && <p role="status" className="text-[13px] text-amber">{t('awgb.restore.busy')}</p>}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!host || !chosen || busy}>{t('awgb.transfer.go')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

function toBase64(buf: ArrayBuffer): string {
  let s = ''
  const b = new Uint8Array(buf)
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(s)
}

/** Creates a container on a host from a backup file and its passphrase. */
export function RestoreContainer({ host, onClose, onDone }: { host: Host; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [pass, setPass] = useState('')
  const [name, setName] = useState(freeName(host))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk] = useState('')
  const valid = !!file && file.size < 400_000 && pass.length > 0 && NAMES.includes(name)

  async function go() {
    if (!file) return
    setBusy(true)
    setError('')
    try {
      const backup = toBase64(await file.arrayBuffer())
      await api.post(`/api/v1/awg/hosts/${host.id}/restore`, { container: name, passphrase: pass, backup })
      setPass('')
      setOk(name)
      onDone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (ok) return <Done name={ok} onClose={onClose} />
  return (
    <Modal title={t('awgb.restore.title', { host: host.node_name })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void go() }}>
        <p className="text-[13px] text-muted">{t('awgb.restore.hint')}</p>
        <Field label={t('awgb.file')} htmlFor="awgb-file"><input id="awgb-file" type="file" accept=".rsawg" className={inputCls} onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></Field>
        <Field label={t('awgb.pass.short')} htmlFor="awgb-rpass"><input id="awgb-rpass" type="password" className={inputCls} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></Field>
        <Field label={t('awgc.name')} htmlFor="awgb-rname">
          <select id="awgb-rname" className={inputCls} value={name} onChange={(e) => setName(e.target.value)}>
            {NAMES.map((n) => <option key={n} value={n} disabled={host.containers.includes(n)}>{n}{host.containers.includes(n) ? ` (${t('awgc.taken')})` : ''}</option>)}
          </select>
        </Field>
        {busy && <p role="status" className="text-[13px] text-amber">{t('awgb.restore.busy')}</p>}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{t('awgb.restore.go')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}
