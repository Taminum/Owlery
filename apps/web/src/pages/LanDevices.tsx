import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/format'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import { Chip, Segmented, Skeleton } from '../components/ui'
import { GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { DataTable } from '../components/DataTable'
import { PageHead } from '../components/Analyzer'

interface Dev { mac: string; ip: string; host?: string; name?: string; source: string; first_seen: string; last_seen: string; confirmed: boolean; seen: boolean }
type Filter = 'all' | 'seen' | 'new' | 'gone'

const label = (d: Dev) => d.name || d.host || ''

function Tile({ text, value, warn }: { text: string; value: number; warn?: boolean }) {
  return (
    <div className={`rounded-control border px-3 py-2.5 ${warn ? 'border-amber/40 bg-amber/10' : 'border-line bg-elevated'}`}>
      <div className="text-xs text-muted">{text}</div>
      <div className="tnum mt-0.5 text-[22px] font-medium">{value}</div>
    </div>
  )
}

function NameDialog({ d, onClose, onDone }: { d: Dev; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(label(d))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/lan-devices/${encodeURIComponent(d.mac)}`, { name: name.trim() })
      onDone()
      onClose()
    } catch {
      setError(t('lan.err'))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('lan.dialog')} onClose={onClose} busy={busy}>
      <p className="mb-3 text-[13px] text-muted">{t('lan.dialogNote', { mac: d.mac })}</p>
      <label htmlFor="lan-name" className="mb-1.5 block text-[13px] font-medium">{t('lan.name')}</label>
      <input id="lan-name" data-autofocus className={inputCls} value={name} maxLength={60} placeholder={t('lan.namePh')} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void save()} />
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={save} disabled={busy}>{t('lan.save')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

export default function LanDevices() {
  const { filters } = useApp()
  const { data, error, reload } = useLoad((s) => api.get<{ devices: Dev[] }>('/api/v1/lan-devices', s), [], 30_000)
  const [filter, setFilter] = useState<Filter>('all')
  const [editing, setEditing] = useState<Dev | null>(null)
  const [now] = useState(() => Date.now())
  const all = data?.devices ?? []
  const fresh = all.filter((d) => !d.confirmed)
  const rows = all.filter((d) => (filter === 'seen' ? d.seen : filter === 'new' ? !d.confirmed : filter === 'gone' ? !d.seen : true))
  const gone = (d: Dev) => {
    const days = Math.floor((now - new Date(d.last_seen).getTime()) / 86_400_000)
    return t('lan.lastSeen', { t: days >= 1 ? `${days} дн. назад` : formatDateTime(d.last_seen, filters.tz) })
  }
  return (
    <div className="space-y-5">
      <PageHead title={t('lan.title')} subtitle={t('lan.subtitle')} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <Skeleton className="h-40" />}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
            <Tile text={t('lan.total')} value={all.length} />
            <Tile text={t('lan.seen')} value={all.filter((d) => d.seen).length} />
            <Tile text={t('lan.new')} value={fresh.length} warn={fresh.length > 0} />
          </div>
          <Segmented label={t('lan.filter')} value={filter} onChange={setFilter} options={[
            { value: 'all', label: t('lan.f.all') }, { value: 'seen', label: t('lan.f.seen') },
            { value: 'new', label: t('lan.f.new') }, { value: 'gone', label: t('lan.f.gone') },
          ]} />
          {all.length === 0 ? <p className="text-[13px] text-muted">{t('lan.empty')}</p>
            : rows.length === 0 ? <p className="text-[13px] text-muted">{t('lan.emptyFilter')}</p> : (
              <DataTable caption={t('lan.title')} rows={rows} rowKey={(d) => d.mac} pageSize={25} columns={[
                { key: 'name', title: t('lan.col.name'), sort: (d) => label(d), cell: (d) => (label(d)
                  ? <span className={d.seen ? '' : 'text-muted'}>{label(d)}{!d.confirmed && <Chip tone="amber">{t('lan.nameNew')}</Chip>}</span>
                  : <span className="text-muted">— {!d.confirmed && <Chip tone="amber">{t('lan.nameNew')}</Chip>}</span>) },
                { key: 'ip', title: t('lan.col.ip'), className: 'tnum', sort: (d) => d.ip, cell: (d) => d.ip },
                { key: 'mac', title: t('lan.col.mac'), className: 'font-mono text-xs', cell: (d) => d.mac },
                { key: 'src', title: t('lan.col.source'), sort: (d) => d.source, cell: (d) => d.source || '—' },
                { key: 'state', title: t('lan.col.state'), sort: (d) => d.last_seen, descFirst: true, cell: (d) => (d.seen ? <Chip tone="green">{t('lan.seenNow')}</Chip> : <span className="text-muted">{gone(d)}</span>) },
                { key: 'act', title: '', align: 'right', cell: (d) => <GhostButton size="s" onClick={() => setEditing(d)}>{d.confirmed ? t('lan.rename') : t('lan.confirm')}</GhostButton> },
              ]} />
            )}
          <p className="text-xs text-muted">{t('lan.note')}</p>
        </>
      )}
      {editing && <NameDialog d={editing} onClose={() => setEditing(null)} onDone={reload} />}
    </div>
  )
}
