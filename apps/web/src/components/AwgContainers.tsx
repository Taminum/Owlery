import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from './ui'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

interface Host { id: string; node_name: string; online: boolean; container_admin: boolean; containers: string[] }

const NAMES = ['amnezia-awg', 'amnezia-awg2', 'amnezia-awg3', 'amnezia-awg4', 'amnezia-awg5']
const SUBNET_RE = /^10\.(\d{1,3})\.(\d{1,3})\.0\/24$/

/** The next container name the official client's pattern allows that this host does not have yet. */
function freeName(h: Host): string {
  return NAMES.find((n) => !h.containers.includes(n)) ?? ''
}

function Install({ host, onClose, onDone }: { host: Host; onClose: () => void; onDone: () => void }) {
  const [container, setContainer] = useState(freeName(host))
  const [port, setPort] = useState(() => String(40000 + Math.floor(Math.random() * 20000)))
  const [subnet, setSubnet] = useState('10.8.1.0/24')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk] = useState('')
  const p = Number(port)
  const sm = SUBNET_RE.exec(subnet)
  const valid = NAMES.includes(container) && Number.isInteger(p) && p >= 1024 && p <= 65535 && !!sm && Number(sm[1]) <= 255 && Number(sm[2]) <= 255

  async function go() {
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/awg/hosts/${host.id}/containers`, { container, port: p, subnet })
      setOk(container)
      onDone()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (ok) {
    return (
      <Modal title={t('awgc.done.title')} onClose={onClose}>
        <p className="text-[13px]">{t('awgc.done', { name: ok })}</p>
        <div className="mt-4 flex justify-end"><PrimaryButton onClick={onClose}>{t('awg.new.done')}</PrimaryButton></div>
      </Modal>
    )
  }
  return (
    <Modal title={t('awgc.install.title', { host: host.node_name })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void go() }}>
        <p className="text-[13px] text-muted">{t('awgc.install.hint')}</p>
        <Field label={t('awgc.name')} htmlFor="awgc-name">
          <select id="awgc-name" className={inputCls} value={container} onChange={(e) => setContainer(e.target.value)}>
            {NAMES.map((n) => <option key={n} value={n} disabled={host.containers.includes(n)}>{n}{host.containers.includes(n) ? ` (${t('awgc.taken')})` : ''}</option>)}
          </select>
        </Field>
        <Field label={t('awgc.port')} hint={t('awgc.port.hint')} htmlFor="awgc-port"><input id="awgc-port" className={inputCls} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></Field>
        <Field label={t('awgc.subnet')} hint={t('awgc.subnet.hint')} htmlFor="awgc-subnet"><input id="awgc-subnet" className={`${inputCls} font-mono`} value={subnet} onChange={(e) => setSubnet(e.target.value)} spellCheck={false} /></Field>
        {busy && <p role="status" className="text-[13px] text-amber">{t('awgc.busy')}</p>}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{t('awgc.install.go')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

/** Hosts and the one operation that creates a container on them. Shown to the owner only. */
export function AwgHosts({ onChanged }: { onChanged: () => void }) {
  const { data, error, reload } = useLoad((s) => api.get<{ hosts: Host[] }>('/api/v1/awg/hosts', s), [], 30_000)
  const [installing, setInstalling] = useState<Host | null>(null)
  if (error || !data || data.hosts.length === 0) return null
  const done = () => { reload(); onChanged() }
  return (
    <>
      <Card title={t('awgc.title')} note={t('awgc.note')}>
        <ul className="divide-y divide-line text-[13px]">
          {data.hosts.map((h) => (
            <li key={h.id} className="flex flex-wrap items-center justify-between gap-3 py-2">
              <span>
                <span className="font-medium">{h.node_name}</span>
                <span className="ml-2 text-xs text-muted">{h.containers.length > 0 ? h.containers.join(', ') : t('awgc.noContainers')}</span>
              </span>
              <span className="flex items-center gap-3">
                <Chip tone={h.online ? 'green' : 'muted'}>{h.online ? t('awgc.online') : t('awgc.offline')}</Chip>
                {h.container_admin
                  ? <GhostButton onClick={() => setInstalling(h)} disabled={!h.online}>{t('awgc.install')}</GhostButton>
                  : <span className="text-xs text-muted" title={t('awgc.off.hint')}>{t('awgc.off')}</span>}
              </span>
            </li>
          ))}
        </ul>
      </Card>
      {installing && <Install host={installing} onClose={() => setInstalling(null)} onDone={done} />}
    </>
  )
}

/** Removing a whole container deletes every device in it, so the container's own name must be typed back. */
export function RemoveContainer({ instanceId, container, onClose, onDone }: { instanceId: string; container: string; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function go() {
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/awg/instances/${instanceId}/remove`, { confirm: typed })
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('awgc.remove.title', { name: container })} onClose={onClose} busy={busy}>
      <div className="space-y-4">
        <p role="alert" className="rounded-control border border-red/40 bg-red/10 px-3 py-2 text-[13px] text-red">{t('awgc.remove.warn', { name: container })}</p>
        <Field label={t('awgc.remove.type', { name: container })} htmlFor="awgc-confirm">
          <input id="awgc-confirm" className={`${inputCls} font-mono`} value={typed} onChange={(e) => setTyped(e.target.value)} spellCheck={false} autoComplete="off" />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <DangerButton onClick={() => void go()} disabled={busy || typed !== container}>{t('awgc.remove.go')}</DangerButton>
        </div>
      </div>
    </Modal>
  )
}
