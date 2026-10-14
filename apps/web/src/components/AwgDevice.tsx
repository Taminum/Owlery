import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { Check, Copy, Download } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

interface Created { name: string; key_short: string; tunnel_ip: string; config: string; filename: string }

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$/

/** The configuration of a new device, shown once. It holds the device's private key, so it lives only in this
 *  component's state: nothing is written to storage, and closing the window forgets it. */
function Issued({ made, onClose }: { made: Created; onClose: () => void }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [copied, setCopied] = useState(false)
  const [qrFailed, setQrFailed] = useState(false)

  useEffect(() => {
    if (!canvas.current) return
    QRCode.toCanvas(canvas.current, made.config, { errorCorrectionLevel: 'L', margin: 2, width: 280 }).catch(() => setQrFailed(true))
  }, [made.config])

  function download() {
    const url = URL.createObjectURL(new Blob([made.config], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = made.filename
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <Modal title={t('awg.new.ready', { name: made.name })} onClose={onClose} wide>
      <div className="space-y-4">
        <p role="alert" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{t('awg.new.once')}</p>
        <div className="flex flex-wrap gap-4">
          <div className="min-w-0 flex-1 space-y-2">
            <div className="text-[13px] text-muted">{t('awg.new.address', { ip: made.tunnel_ip })}</div>
            <textarea readOnly aria-label={t('awg.new.config')} value={made.config} rows={12} onFocus={(e) => e.currentTarget.select()}
              className="w-full rounded-control border border-line bg-canvas p-3 font-mono text-[12px] leading-5" />
            <div className="flex flex-wrap gap-2">
              <GhostButton onClick={() => void navigator.clipboard?.writeText(made.config).then(() => setCopied(true))}>
                <span className="inline-flex items-center gap-2">{copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}{copied ? t('agents.copied') : t('agents.copy')}</span>
              </GhostButton>
              <GhostButton onClick={download}><span className="inline-flex items-center gap-2"><Download size={15} aria-hidden />{t('awg.new.download')}</span></GhostButton>
            </div>
          </div>
          <div className="space-y-2">
            {qrFailed ? <p className="text-[13px] text-muted">{t('awg.new.noQr')}</p> : <canvas ref={canvas} aria-label={t('awg.new.qr')} className="rounded-control bg-white" />}
            <p className="max-w-[280px] text-xs leading-5 text-muted">{t('awg.new.qrNote')}</p>
          </div>
        </div>
        <div className="flex justify-end"><PrimaryButton onClick={onClose}>{t('awg.new.done')}</PrimaryButton></div>
      </div>
    </Modal>
  )
}

export function AddDevice({ instanceId, container, onClose, onDone }: { instanceId: string; container: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [made, setMade] = useState<Created | null>(null)
  const valid = NAME_RE.test(name.trim())

  async function create() {
    setBusy(true)
    setError('')
    try {
      setMade(await api.post<Created>(`/api/v1/awg/instances/${instanceId}/peers`, { name: name.trim() }))
      onDone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (made) return <Issued made={made} onClose={onClose} />
  return (
    <Modal title={t('awg.new.title')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void create() }}>
        <p className="text-[13px] text-muted">{t('awg.new.intro', { container })}</p>
        <Field label={t('awg.new.name')} hint={t('awg.new.nameHint')} htmlFor="awg-new-name">
          <input id="awg-new-name" data-autofocus className={inputCls} value={name} maxLength={40} autoComplete="off" onChange={(e) => setName(e.target.value)} />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton type="button" onClick={onClose}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{busy ? t('awg.new.creating') : t('awg.new.create')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export function RevokeDevice({ peerId, label, onClose, onDone }: { peerId: string; label: string; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function revoke() {
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/awg/peers/${peerId}/revoke`, {})
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('awg.revoke.title', { name: label })} onClose={onClose} busy={busy}>
      <div className="space-y-4">
        <p className="text-[13px] leading-5">{t('awg.revoke.text')}</p>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose}>{t('common.cancel')}</GhostButton>
          <DangerButton disabled={busy} onClick={() => void revoke()}>{busy ? t('awg.revoke.doing') : t('awg.revoke.do')}</DangerButton>
        </div>
      </div>
    </Modal>
  )
}

export function RenameDevice({ peerId, label, onClose, onDone }: { peerId: string; label: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(label)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const valid = NAME_RE.test(name.trim())
  async function save() {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/awg/peers/${peerId}`, { label: name.trim() })
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('awg.rename.title')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void save() }}>
        <Field label={t('awg.new.name')} hint={t('awg.rename.hint')} htmlFor="awg-rename">
          <input id="awg-rename" data-autofocus className={inputCls} value={name} maxLength={40} autoComplete="off" onChange={(e) => setName(e.target.value)} />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton type="button" onClick={onClose}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{t('common.save')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}
