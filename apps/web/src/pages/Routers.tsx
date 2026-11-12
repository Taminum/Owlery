import { useState } from 'react'
import { Plus } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api, ApiError } from '../lib/api'
import { formatBytes, formatDateTime, formatRate } from '../lib/format'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Skeleton } from '../components/ui'
import { DangerButton, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { DataTable } from '../components/DataTable'
import { PageHead } from '../components/Analyzer'
import { durationText } from '../components/ServerParts'

interface Iface { name: string; rx: number; tx: number; up: boolean; rx_bps: number; tx_bps: number }
interface Client { ip: string; mac: string; host?: string }
interface Device {
  id: string; name: string; online: boolean; last_seen: string | null
  view: { board: string; version: string; uptime: number; cpu: number; mem_free: number; mem_total: number; temp?: number; stats_at?: string; ifaces: Iface[]; clients: Client[] }
}

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-control border border-line bg-elevated px-3 py-2.5">
      <div className="text-xs text-muted">{label}</div>
      <div className="tnum mt-0.5 text-[22px] font-medium">{value}</div>
    </div>
  )
}

function why(e: unknown): string {
  if (e instanceof ApiError && (e.code === 'name_taken' || e.code === 'invalid_name')) return t(`rt.err.${e.code}` as MsgKey)
  return t('rt.err.other')
}

function RenameDialog({ d, onClose, onDone }: { d: Device; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(d.name)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/net-devices/${d.id}`, { name: name.trim() })
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('rt.renameTitle')} onClose={onClose} busy={busy}>
      <label htmlFor="rt-rename" className="mb-1.5 block text-[13px] font-medium">{t('rt.name')}</label>
      <input id="rt-rename" data-autofocus className={inputCls} value={name} maxLength={60} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && void save()} />
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={save} disabled={busy || !name.trim() || name.trim() === d.name}>{t('rt.save')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function DeviceCard({ d, tz, onRename, onRemove }: { d: Device; tz: string; onRename: () => void; onRemove: () => void }) {
  const v = d.view
  const memPct = v.mem_total > 0 ? Math.round(((v.mem_total - v.mem_free) * 100) / v.mem_total) : null
  const [now] = useState(() => Date.now())
  const sub = [v.board, v.version && `RouterOS ${v.version}`].filter(Boolean).join(', ')
  return (
    <Card title={d.name} note={sub} right={<div className="flex gap-2"><GhostButton size="s" onClick={onRename}>{t('rt.rename')}</GhostButton><GhostButton size="s" onClick={onRemove}>{t('rt.remove')}</GhostButton></div>}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-[13px]">
          {d.last_seen === null ? <Chip tone="amber">{t('rt.never')}</Chip>
            : d.online ? <Chip tone="green">{t('rt.online')}</Chip>
            : <Chip tone="red">{t('rt.offline')}</Chip>}
          {d.last_seen && !d.online && <span className="text-muted">{formatDateTime(d.last_seen, tz)}</span>}
          {d.online && v.uptime > 0 && <span className="text-muted">{t('rt.up', { d: durationText(new Date(now - v.uptime * 1000).toISOString(), null) })}</span>}
        </div>
        {v.stats_at && (
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
            <Tile label={t('rt.cpu')} value={`${Math.round(v.cpu)}%`} />
            <Tile label={t('rt.mem')} value={memPct === null ? '—' : `${memPct}%`} />
            {v.temp !== undefined && <Tile label={t('rt.temp')} value={`${Math.round(v.temp)} °C`} />}
          </div>
        )}
        {v.ifaces.length > 0 && (
          <div>
            <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.ports')}</h3>
            <DataTable caption={t('rt.ports')} rows={v.ifaces} rowKey={(f) => f.name} pageSize={12} columns={[
              { key: 'name', title: t('rt.col.port'), sort: (f) => f.name, cell: (f) => <span className="font-medium">{f.name}</span> },
              { key: 'state', title: t('rt.col.state'), cell: (f) => <Chip tone={f.up ? 'green' : undefined}>{f.up ? t('rt.portUp') : t('rt.portDown')}</Chip> },
              { key: 'speed', title: t('rt.col.speed'), sort: (f) => f.rx_bps + f.tx_bps, descFirst: true, className: 'tnum whitespace-nowrap', cell: (f) => `↓ ${formatRate(f.rx_bps)} · ↑ ${formatRate(f.tx_bps)}` },
              { key: 'rx', title: t('rt.col.rx'), sort: (f) => f.rx, descFirst: true, align: 'right', className: 'tnum', cell: (f) => formatBytes(f.rx) },
              { key: 'tx', title: t('rt.col.tx'), sort: (f) => f.tx, descFirst: true, align: 'right', className: 'tnum', cell: (f) => formatBytes(f.tx) },
            ]} />
          </div>
        )}
        <div>
          <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.clients')} <span className="font-normal text-muted">{t('rt.clientsN', { n: v.clients.length })}</span></h3>
          {v.clients.length === 0 ? <p className="text-[13px] text-muted">{t('rt.noClients')}</p> : (
            <DataTable caption={t('rt.clients')} rows={v.clients} rowKey={(c) => c.mac} pageSize={12} columns={[
              { key: 'name', title: t('rt.col.name'), sort: (c) => c.host ?? '', cell: (c) => c.host || '—' },
              { key: 'ip', title: t('rt.col.ip'), className: 'tnum', sort: (c) => c.ip, cell: (c) => c.ip },
              { key: 'mac', title: t('rt.col.mac'), className: 'font-mono text-xs', cell: (c) => c.mac },
            ]} />
          )}
        </div>
      </div>
    </Card>
  )
}

interface Made { token: string; script: string; device: { name: string } }

function NewDialog({ onClose, onMade }: { onClose: () => void; onMade: () => void }) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [made, setMade] = useState<Made | null>(null)
  const [copied, setCopied] = useState('')
  const create = async () => {
    setBusy(true)
    setError('')
    try {
      setMade(await api.post<Made>('/api/v1/net-devices', { name: name.trim() }))
      onMade()
    } catch (e) {
      setError(why(e))
    } finally {
      setBusy(false)
    }
  }
  const copy = (key: string, text: string) => { void navigator.clipboard?.writeText(text); setCopied(key) }
  if (made) {
    const cmd = '/system scheduler add name=owlery interval=1m on-event="/system script run owlery"'
    return (
      <Modal title={t('rt.created', { name: made.device.name })} onClose={onClose} wide>
        <div className="space-y-3 text-[13px]">
          <p className="text-muted">{t('rt.tokenOnce')}</p>
          <p>{t('rt.step1')}</p>
          <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-control bg-canvas p-3 font-mono text-xs leading-5">{made.script}</pre>
          <GhostButton size="m" onClick={() => copy('script', made.script)}>{copied === 'script' ? t('rt.copied') : t('rt.copy')}</GhostButton>
          <p>{t('rt.step2')}</p>
          <pre className="whitespace-pre-wrap break-all rounded-control bg-canvas p-3 font-mono text-xs leading-5">{cmd}</pre>
          <GhostButton size="m" onClick={() => copy('cmd', cmd)}>{copied === 'cmd' ? t('rt.copied') : t('rt.copy')}</GhostButton>
          <p className="text-muted">{t('rt.step3')}</p>
          <div className="pt-1"><PrimaryButton size="m" onClick={onClose}>{t('rt.done')}</PrimaryButton></div>
        </div>
      </Modal>
    )
  }
  return (
    <Modal title={t('rt.newTitle')} onClose={onClose} busy={busy}>
      <label htmlFor="rt-name" className="mb-1.5 block text-[13px] font-medium">{t('rt.name')}</label>
      <input id="rt-name" data-autofocus className={inputCls} value={name} maxLength={60} placeholder={t('rt.namePh')} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && void create()} />
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={create} disabled={busy || !name.trim()}>{t('rt.create')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

export default function Routers() {
  const { filters } = useApp()
  const { data, error, reload } = useLoad((s) => api.get<{ devices: Device[] }>('/api/v1/net-devices', s), [], 30_000)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Device | null>(null)
  const [renaming, setRenaming] = useState<Device | null>(null)
  const [busy, setBusy] = useState(false)
  const remove = async () => {
    if (!removing) return
    setBusy(true)
    try {
      await api.del(`/api/v1/net-devices/${removing.id}`)
      setRemoving(null)
      reload()
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-5">
      <PageHead title={t('rt.title')} subtitle={t('rt.subtitle')} right={<PrimaryButton size="m" onClick={() => setAdding(true)}><Plus size={14} aria-hidden className="mr-1 inline" />{t('rt.add')}</PrimaryButton>} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <Skeleton className="h-40" />}
      {data && data.devices.length === 0 && <p className="text-[13px] text-muted">{t('rt.empty')}</p>}
      {data?.devices.map((d) => <DeviceCard key={d.id} d={d} tz={filters.tz} onRename={() => setRenaming(d)} onRemove={() => setRemoving(d)} />)}
      {renaming && <RenameDialog d={renaming} onClose={() => setRenaming(null)} onDone={reload} />}
      {adding && <NewDialog onClose={() => setAdding(false)} onMade={reload} />}
      {removing && (
        <Modal title={t('rt.removeTitle', { name: removing.name })} onClose={() => setRemoving(null)} busy={busy}>
          <p className="text-[13px] text-muted">{t('rt.removeNote')}</p>
          <div className="mt-4 flex gap-2">
            <DangerButton size="m" onClick={remove} disabled={busy}>{t('rt.remove')}</DangerButton>
            <GhostButton size="m" onClick={() => setRemoving(null)} disabled={busy}>{t('common.cancel')}</GhostButton>
          </div>
        </Modal>
      )}
    </div>
  )
}
