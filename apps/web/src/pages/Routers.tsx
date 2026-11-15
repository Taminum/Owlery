import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Plus } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api, ApiError } from '../lib/api'
import { formatBytes, formatDateTime, formatRate } from '../lib/format'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip, Segmented, Skeleton } from '../components/ui'
import { DangerButton, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { DataTable } from '../components/DataTable'
import { PageHead } from '../components/Analyzer'
import { durationText } from '../components/ServerParts'

interface Iface { name: string; rx: number; tx: number; up: boolean; rx_bps: number; tx_bps: number }
interface TopSrc { ip: string; n: number }
interface NatRule { chain: string; action: string; packets: number; bytes: number; dst_port?: string; to_addr?: string; to_ports?: string; comment?: string; ref?: string; off?: boolean }
interface Client { ip: string; mac: string; host?: string }
interface Blocked { mac: string; ip?: string; host?: string }
interface Reserve { mac: string; ip: string }
interface Act { title: string; note: string; label: string; danger?: boolean; method: 'post' | 'put' | 'del'; path: string; body?: unknown }
interface Command { id: number; kind: string; a1?: string; state: 'waiting' | 'sent' | 'done' | 'failed'; note?: string }
interface Device {
  commands?: Command[]
  group?: string
  id: string; name: string; kind?: string; url?: string; new_forwards?: NatRule[]; pull_error?: string; parent_id?: string | null; online: boolean; last_seen: string | null
  view: { board: string; version: string; uptime: number; cpu: number; mem_free: number; mem_total: number; temp?: number; stats_at?: string; ifaces: Iface[]; clients: Client[]; conn?: number; conn_max?: number; top?: TopSrc[]; nat?: NatRule[]; internet?: boolean; control?: boolean; blocked?: Blocked[]; reserved?: Reserve[] }
}

function Tile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-control border border-line bg-elevated px-3 py-2.5">
      <div className="text-xs text-muted">{label}</div>
      <div className="tnum mt-0.5 text-[22px] font-medium">{value}</div>
      {sub && <div className="tnum text-xs text-muted">{sub}</div>}
    </div>
  )
}

function why(e: unknown): string {
  if (e instanceof ApiError && ['name_taken', 'invalid_name', 'invalid_url', 'invalid_credentials', 'router_auth', 'router_unreachable', 'router_unexpected', 'forbidden', 'rejected', 'unknown_host', 'port_taken', 'missing', 'invalid_forward'].includes(e.code)) return t(`rt.err.${e.code}` as MsgKey)
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

function PasswordDialog({ d, onClose, onDone }: { d: Device; onClose: () => void; onDone: () => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/net-devices/${d.id}`, { password })
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('rt.passTitle', { name: d.name })} onClose={onClose} busy={busy}>
      <label htmlFor="rt-newpass" className="mb-1.5 block text-[13px] font-medium">{t('rt.newPass')}</label>
      <input id="rt-newpass" type="password" autoComplete="new-password" data-autofocus className={inputCls} value={password} maxLength={128} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && password && void save()} />
      {busy && <p className="mt-2 text-xs text-muted">{t('rt.checking')}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={save} disabled={busy || !password}>{t('rt.save')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function ForwardDialog({ d, onClose, onDone }: { d: Device; onClose: () => void; onDone: () => void }) {
  const [protocol, setProtocol] = useState('tcp')
  const [port, setPort] = useState('')
  const [toAddr, setToAddr] = useState(d.view.clients[0]?.ip ?? '')
  const [toPort, setToPort] = useState('')
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const num = (s: string) => (/^\d{1,5}$/.test(s.trim()) ? Number(s) : 0)
  const valid = num(port) >= 1 && num(port) <= 65535 && toAddr !== '' && (toPort.trim() === '' || (num(toPort) >= 1 && num(toPort) <= 65535))
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/net-devices/${d.id}/forwards`, { protocol, port: num(port), to_addr: toAddr, to_port: toPort.trim() === '' ? 0 : num(toPort), comment: comment.trim() })
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('rt.fwTitle', { name: d.name })} onClose={onClose} busy={busy}>
      <div className="space-y-3">
        <div className="flex gap-3">
          <div>
            <label htmlFor="fw-proto" className="mb-1.5 block text-[13px] font-medium">{t('rt.fwProto')}</label>
            <select id="fw-proto" className={inputCls} value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          <div className="flex-1">
            <label htmlFor="fw-port" className="mb-1.5 block text-[13px] font-medium">{t('rt.fwPort')}</label>
            <input id="fw-port" inputMode="numeric" className={inputCls} value={port} maxLength={5} data-autofocus onChange={(e) => setPort(e.target.value)} />
          </div>
        </div>
        <div>
          <label htmlFor="fw-to" className="mb-1.5 block text-[13px] font-medium">{t('rt.fwTo')}</label>
          <select id="fw-to" className={inputCls} value={toAddr} onChange={(e) => setToAddr(e.target.value)}>
            {d.view.clients.map((c) => <option key={c.mac} value={c.ip}>{c.ip}{c.host ? ` · ${c.host}` : ''}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="fw-toport" className="mb-1.5 block text-[13px] font-medium">{t('rt.fwToPort')}</label>
          <input id="fw-toport" inputMode="numeric" className={inputCls} value={toPort} maxLength={5} placeholder={port} onChange={(e) => setToPort(e.target.value)} />
        </div>
        <div>
          <label htmlFor="fw-note" className="mb-1.5 block text-[13px] font-medium">{t('rt.fwNote')}</label>
          <input id="fw-note" className={inputCls} value={comment} maxLength={80} onChange={(e) => setComment(e.target.value)} />
        </div>
        <p className="text-xs text-muted">{t('rt.fwHint')}</p>
      </div>
      {busy && <p className="mt-2 text-xs text-muted">{t('rt.fwBusy')}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={save} disabled={busy || !valid}>{t('rt.fwOpen')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function DeleteForwardDialog({ d, rule, onClose, onDone }: { d: Device; rule: NatRule; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const go = async () => {
    setBusy(true)
    setError('')
    try {
      await api.del(`/api/v1/net-devices/${d.id}/forwards/${rule.ref}`)
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  const what = `${rule.action}: ${rule.dst_port ? `:${rule.dst_port} → ` : ''}${rule.to_addr ?? ''}${rule.to_ports ? `:${rule.to_ports}` : ''}${rule.comment ? ` (${rule.comment})` : ''}`
  return (
    <Modal title={t('rt.fwDelTitle')} onClose={onClose} busy={busy}>
      <p className="text-[13px]">{what}</p>
      <p className="mt-2 text-[13px] text-muted">{t('rt.fwDelNote')}</p>
      {busy && <p className="mt-2 text-xs text-muted">{t('rt.fwBusy')}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <DangerButton size="m" onClick={go} disabled={busy}>{t('rt.fwDel')}</DangerButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function ActionDialog({ act, onClose, onDone }: { act: Act; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const go = async () => {
    setBusy(true)
    setError('')
    try {
      if (act.method === 'post') await api.post(act.path, act.body ?? {})
      else if (act.method === 'put') await api.put(act.path, act.body ?? {})
      else await api.del(act.path)
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  const Btn = act.danger ? DangerButton : PrimaryButton
  return (
    <Modal title={act.title} onClose={onClose} busy={busy}>
      <p className="text-[13px] text-muted">{act.note}</p>
      {busy && <p className="mt-2 text-xs text-muted">{t('rt.fwBusy')}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <Btn size="m" onClick={go} disabled={busy}>{act.label}</Btn>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function DeviceCard({ d, tz, others, onParent, onRename, onRemove, onPassword, onGroup, onConfirmFw, onReload }: { d: Device; tz: string; others: Device[]; onParent: (parent: string) => void; onRename: () => void; onRemove: () => void; onPassword: () => void; onGroup: () => void; onConfirmFw: () => void; onReload: () => void }) {
  const v = d.view
  const [fwOpen, setFwOpen] = useState(false)
  const [fwDel, setFwDel] = useState<NatRule | null>(null)
  const [act, setAct] = useState<Act | null>(null)
  const [rotating, setRotating] = useState(false)
  const [fresh, setFresh] = useState<Made | null>(null)
  const direct = d.kind === 'keenetic'
  const canAct = direct || !!d.view.control
  // One change: straight at a Keenetic, and for the others put in the queue the router asks for once a minute.
  const mk = (kind: 'block' | 'unblock' | 'reserve' | 'unreserve' | 'reboot', mac: string, a: Omit<Act, 'method' | 'path' | 'body'>): Act => {
    if (!direct) return { ...a, note: `${a.note} ${t('rt.queueNote')}`, method: 'post', path: `${dev0}/commands`, body: { kind, mac } }
    if (kind === 'reboot') return { ...a, method: 'post', path: `${dev0}/reboot` }
    if (kind === 'block') return { ...a, method: 'post', path: `${dev0}/clients/${mac}/block` }
    if (kind === 'unblock') return { ...a, method: 'del', path: `${dev0}/clients/${mac}/block` }
    if (kind === 'reserve') return { ...a, method: 'put', path: `${dev0}/clients/${mac}/reserve` }
    return { ...a, method: 'del', path: `${dev0}/clients/${mac}/reserve` }
  }
  const reservedBy = new Map((d.view.reserved ?? []).map((x) => [x.mac, x.ip]))
  const dev = `/api/v1/net-devices/${d.id}`
  const dev0 = dev
  const memPct = v.mem_total > 0 ? Math.round(((v.mem_total - v.mem_free) * 100) / v.mem_total) : null
  const [now] = useState(() => Date.now())
  const [showDown, setShowDown] = useState(false)
  const upPorts = v.ifaces.filter((f) => f.up)
  const downCount = v.ifaces.length - upPorts.length
  // Ports without a cable fold away; if nothing is plugged in, show them all rather than an empty table.
  const ports = showDown || upPorts.length === 0 ? v.ifaces : upPorts
  const names = new Map(v.clients.filter((c) => c.host).map((c) => [c.ip, c.host as string]))
  const sub = [v.board, v.version && (d.kind === 'openwrt' ? v.version : d.kind === 'keenetic' ? `KeeneticOS ${v.version}` : `RouterOS ${v.version}`)].filter(Boolean).join(', ')
  return (
    <Card title={d.name} note={sub} right={<div className="flex gap-2">{canAct && <GhostButton size="s" onClick={() => setAct(mk('reboot', '', { title: t('rt.rebootTitle', { name: d.name }), note: t('rt.rebootNote'), label: t('rt.reboot'), danger: true }))}>{t('rt.reboot')}</GhostButton>}{!canAct && <GhostButton size="s" onClick={() => setRotating(true)}>{t('rt.enable')}</GhostButton>}{d.kind === 'keenetic' && <GhostButton size="s" onClick={onPassword}>{t('rt.changePass')}</GhostButton>}<GhostButton size="s" onClick={onGroup}>{t('rt.group')}</GhostButton><GhostButton size="s" onClick={onRename}>{t('rt.rename')}</GhostButton><GhostButton size="s" onClick={onRemove}>{t('rt.remove')}</GhostButton></div>}>
      <div className="space-y-4">
        {rotating && <RotateDialog d={d} onClose={() => setRotating(false)} onMade={(m) => { setRotating(false); setFresh(m); onReload() }} />}
        {fresh && <ScriptDialog made={fresh} replace onClose={() => setFresh(null)} />}
        {act && <ActionDialog act={act} onClose={() => setAct(null)} onDone={onReload} />}
        {fwOpen && <ForwardDialog d={d} onClose={() => setFwOpen(false)} onDone={onReload} />}
        {fwDel && <DeleteForwardDialog d={d} rule={fwDel} onClose={() => setFwDel(null)} onDone={onReload} />}
        {(d.new_forwards?.length ?? 0) > 0 && (
          <div role="alert" className="rounded-lg border border-red/40 bg-red/10 p-3 text-[13px]">
            <div className="mb-1 font-medium">{t('rt.newFw')}</div>
            <ul className="mb-2 space-y-0.5 tnum">
              {d.new_forwards?.map((n) => <li key={`${n.action}|${n.dst_port}|${n.to_addr}|${n.to_ports}`}>{n.action}: {n.dst_port ? `:${n.dst_port} → ` : ''}{n.to_addr ?? ''}{n.to_ports ? `:${n.to_ports}` : ''}{n.comment ? ` (${n.comment})` : ''}</li>)}
            </ul>
            <GhostButton size="s" onClick={onConfirmFw}>{t('rt.newFwOk')}</GhostButton>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2 text-[13px]">
          <label className="flex items-center gap-1.5 text-muted">
            {t('rt.parent')}
            <select className={`${inputCls} !h-7 !w-auto !py-0`} value={d.parent_id ?? ''} onChange={(e) => onParent(e.target.value)} aria-label={t('rt.parent')}>
              <option value="">{t('rt.parentNone')}</option>
              {others.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </label>
          {d.last_seen === null ? <Chip tone="amber">{t('rt.never')}</Chip>
            : d.online ? <Chip tone="green">{t('rt.online')}</Chip>
            : <Chip tone="red">{t('rt.offline')}</Chip>}
          {d.last_seen && !d.online && <span className="text-muted">{formatDateTime(d.last_seen, tz)}</span>}
          {d.view.internet === false && <Chip tone="red">{t('rt.noInternet')}</Chip>}
          {d.pull_error && <Chip tone="red">{t(`rt.pullErr.${d.pull_error}` as MsgKey)}</Chip>}
          {d.url && <span className="text-muted">{t('rt.pulled', { url: d.url.replace(/^https:\/\//, '') })}</span>}
          {d.online && v.uptime > 0 && <span className="text-muted">{t('rt.up', { d: durationText(new Date(now - v.uptime * 1000).toISOString(), null) })}</span>}
        </div>
        {v.stats_at && (
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
            <Tile label={t('rt.cpu')} value={`${Math.round(v.cpu)}%`} />
            <Tile label={t('rt.mem')} value={memPct === null ? '—' : `${memPct}%`} sub={v.mem_total > 0 ? t('rt.memOf', { free: formatBytes(v.mem_free), total: formatBytes(v.mem_total) }) : undefined} />
            {v.conn !== undefined && <Tile label={t('rt.conn')} value={String(v.conn)} sub={v.conn_max ? t('rt.connOf', { max: v.conn_max }) : undefined} />}
            {v.temp !== undefined && <Tile label={t('rt.temp')} value={`${Math.round(v.temp)} °C`} />}
          </div>
        )}
        {v.ifaces.length > 0 && (
          <div>
            <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.ports')}</h3>
            <DataTable caption={t('rt.ports')} rows={ports} rowKey={(f) => f.name} pageSize={12} columns={[
              { key: 'name', title: t('rt.col.port'), sort: (f) => f.name, cell: (f) => <span className="font-medium">{f.name}</span> },
              { key: 'state', title: t('rt.col.state'), cell: (f) => <Chip tone={f.up ? 'green' : undefined}>{f.up ? t('rt.portUp') : t('rt.portDown')}</Chip> },
              { key: 'speed', title: t('rt.col.speed'), sort: (f) => f.rx_bps + f.tx_bps, descFirst: true, className: 'tnum whitespace-nowrap', cell: (f) => `↓ ${formatRate(f.rx_bps)} · ↑ ${formatRate(f.tx_bps)}` },
              { key: 'rx', title: t('rt.col.rx'), sort: (f) => f.rx, descFirst: true, align: 'right', className: 'tnum', cell: (f) => formatBytes(f.rx) },
              { key: 'tx', title: t('rt.col.tx'), sort: (f) => f.tx, descFirst: true, align: 'right', className: 'tnum', cell: (f) => formatBytes(f.tx) },
            ]} />
            {upPorts.length > 0 && downCount > 0 && (
              <button type="button" className="mt-2 text-[13px] text-muted underline-offset-2 hover:underline" onClick={() => setShowDown((x) => !x)}>
                {showDown ? t('rt.hideDown') : t('rt.showDown', { n: downCount })}
              </button>
            )}
          </div>
        )}
        {(v.top?.length ?? 0) > 0 && (
          <div>
            <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.top')}</h3>
            <DataTable caption={t('rt.top')} rows={v.top ?? []} rowKey={(x) => x.ip} pageSize={10} columns={[
              { key: 'ip', title: t('rt.col.ip'), className: 'tnum', sort: (x) => x.ip, cell: (x) => <span>{x.ip}{names.get(x.ip) ? <span className="ml-2 text-muted">{names.get(x.ip)}</span> : null}</span> },
              { key: 'n', title: t('rt.col.conns'), align: 'right', className: 'tnum', sort: (x) => x.n, descFirst: true, cell: (x) => x.n },
            ]} />
            <p className="mt-1.5 text-xs text-muted">{t('rt.topNote')}</p>
          </div>
        )}
        {((v.nat?.length ?? 0) > 0 || d.kind === 'keenetic') && (
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <h3 className="text-[13px] font-medium">{t('rt.nat')}</h3>
              {d.kind === 'keenetic' && <GhostButton size="s" onClick={() => setFwOpen(true)}>{t('rt.fwOpen')}</GhostButton>}
            </div>
            <DataTable caption={t('rt.nat')} rows={v.nat ?? []} rowKey={(x) => `${x.chain}|${x.action}|${x.dst_port ?? ''}|${x.to_addr ?? ''}|${x.comment ?? ''}`} pageSize={12} columns={[
              { key: 'rule', title: t('rt.col.rule'), cell: (x) => <span className="font-medium">{x.chain} · {x.action}{x.off ? <span className="ml-2 font-normal text-muted">{t('rt.fwIsOff')}</span> : null}</span> },
              { key: 'to', title: t('rt.col.to'), className: 'tnum', cell: (x) => (x.dst_port || x.to_addr || x.to_ports ? `${x.dst_port ? `:${x.dst_port} → ` : ''}${x.to_addr ?? ''}${x.to_ports ? `:${x.to_ports}` : ''}` : '—') },
              { key: 'pk', title: t('rt.col.hits'), align: 'right', className: 'tnum', sort: (x) => x.packets, descFirst: true, cell: (x) => (x.packets < 0 ? '—' : x.packets) },
              { key: 'by', title: t('rt.col.bytes'), align: 'right', className: 'tnum', sort: (x) => x.bytes, descFirst: true, cell: (x) => (x.bytes < 0 ? '—' : formatBytes(x.bytes)) },
              { key: 'cm', title: t('rt.col.note'), cell: (x) => x.comment || '—' },
              ...(d.kind === 'keenetic' ? [{ key: 'del', title: '', align: 'right' as const, cell: (x: NatRule) => (x.ref ? <span className="flex justify-end gap-2"><GhostButton size="s" onClick={() => setAct({ title: t(x.off ? 'rt.fwOnTitle' : 'rt.fwOffTitle'), note: t(x.off ? 'rt.fwOnNote' : 'rt.fwOffNote'), label: t(x.off ? 'rt.fwOn' : 'rt.fwOff'), method: 'post', path: `${dev}/forwards/${x.ref}/switch`, body: { off: !x.off } })}>{t(x.off ? 'rt.fwOn' : 'rt.fwOff')}</GhostButton><GhostButton size="s" onClick={() => setFwDel(x)}>{t('rt.fwDel')}</GhostButton></span> : null) }] : []),
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
              ...(canAct ? [{ key: 'act', title: '', align: 'right' as const, cell: (c: Client) => <span className="flex justify-end gap-2">{reservedBy.has(c.mac) && <Chip>{t('rt.kept')}</Chip>}<GhostButton size="s" onClick={() => setAct(reservedBy.has(c.mac) ? mk('unreserve', c.mac, { title: t('rt.unkeepTitle'), note: t('rt.unkeepNote'), label: t('rt.unkeep') }) : mk('reserve', c.mac, { title: t('rt.keepTitle'), note: t('rt.keepNote', { ip: c.ip }), label: t('rt.keep') }))}>{t(reservedBy.has(c.mac) ? 'rt.unkeep' : 'rt.keep')}</GhostButton><GhostButton size="s" onClick={() => setAct(mk('block', c.mac, { title: t('rt.blockTitle', { name: c.host || c.ip }), note: t('rt.blockNote'), label: t('rt.block'), danger: true }))}>{t('rt.block')}</GhostButton></span> }] : []),
            ]} />
          )}
        </div>
        {(d.commands?.length ?? 0) > 0 && (
          <div>
            <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.commands')}</h3>
            <ul className="space-y-1 text-[13px]">
              {d.commands?.map((c) => (
                <li key={c.id} className="flex items-center gap-2">
                  <Chip tone={c.state === 'done' ? 'green' : c.state === 'failed' ? 'red' : 'amber'}>{t(`rt.cmdState.${c.state}` as MsgKey)}</Chip>
                  <span>{t(`rt.cmd.${c.kind}` as MsgKey)}{c.a1 ? <span className="ml-1.5 font-mono text-xs text-muted">{c.a1}</span> : null}{c.state === 'failed' && c.note ? <span className="ml-1.5 text-muted">({c.note})</span> : null}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {(v.blocked?.length ?? 0) > 0 && (
          <div>
            <h3 className="mb-1.5 text-[13px] font-medium">{t('rt.blocked')}</h3>
            <ul className="space-y-1 text-[13px]">
              {v.blocked?.map((b) => (
                <li key={b.mac} className="flex items-center justify-between gap-2">
                  <span><span className="font-mono text-xs">{b.mac}</span>{b.host || b.ip ? <span className="ml-2 text-muted">{[b.host, b.ip].filter(Boolean).join(', ')}</span> : null}</span>
                  {canAct && <GhostButton size="s" onClick={() => setAct(mk('unblock', b.mac, { title: t('rt.unblockTitle'), note: t('rt.unblockNote'), label: t('rt.unblock') }))}>{t('rt.unblock')}</GhostButton>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Card>
  )
}

interface Made { token: string; script: string; device: { name: string; kind?: string } }

function ScriptDialog({ made, replace, onClose }: { made: Made; replace?: boolean; onClose: () => void }) {
  const [copied, setCopied] = useState('')
  const copy = (key: string, text: string) => { void navigator.clipboard?.writeText(text); setCopied(key) }
  const cmd = '/system scheduler add name=owlery interval=1m on-event="/system script run owlery"'
  const ow = made.device.kind === 'openwrt'
  return (
    <Modal title={t(replace ? 'rt.rotTitle' : 'rt.created', { name: made.device.name })} onClose={onClose} wide>
      <div className="space-y-3 text-[13px]">
        <p className="text-muted">{t('rt.tokenOnce')}</p>
        <p>{t(ow ? 'rt.owStep1' : replace ? 'rt.rotStep' : 'rt.step1')}</p>
        <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-control bg-canvas p-3 font-mono text-xs leading-5">{made.script}</pre>
        <GhostButton size="m" onClick={() => copy('script', made.script)}>{copied === 'script' ? t('rt.copied') : t('rt.copy')}</GhostButton>
        {!ow && !replace && (
          <>
            <p>{t('rt.step2')}</p>
            <pre className="whitespace-pre-wrap break-all rounded-control bg-canvas p-3 font-mono text-xs leading-5">{cmd}</pre>
            <GhostButton size="m" onClick={() => copy('cmd', cmd)}>{copied === 'cmd' ? t('rt.copied') : t('rt.copy')}</GhostButton>
          </>
        )}
        <p className="text-muted">{t(ow ? 'rt.owStep2' : 'rt.step3')}</p>
        <div className="pt-1"><PrimaryButton size="m" onClick={onClose}>{t('rt.done')}</PrimaryButton></div>
      </div>
    </Modal>
  )
}

function RotateDialog({ d, onClose, onMade }: { d: Device; onClose: () => void; onMade: (m: Made) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const go = async () => {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ token: string; script: string }>(`/api/v1/net-devices/${d.id}/rotate`, {})
      onMade({ token: r.token, script: r.script, device: { name: d.name, kind: d.kind } })
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('rt.enableTitle', { name: d.name })} onClose={onClose} busy={busy}>
      <p className="text-[13px] text-muted">{t('rt.enableNote')}</p>
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={go} disabled={busy}>{t('rt.enable')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

function NewDialog({ onClose, onMade }: { onClose: () => void; onMade: () => void }) {
  const [name, setName] = useState('')
  const [kind, setKind] = useState('mikrotik')
  const [url, setUrl] = useState('')
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [made, setMade] = useState<Made | null>(null)
  const create = async () => {
    setBusy(true)
    setError('')
    try {
      if (kind === 'keenetic') {
        await api.post('/api/v1/net-devices', { name: name.trim(), kind, url: url.trim(), login: login.trim(), password })
        onMade()
        onClose()
        return
      }
      setMade(await api.post<Made>('/api/v1/net-devices', { name: name.trim(), kind }))
      onMade()
    } catch (e) {
      setError(why(e))
    } finally {
      setBusy(false)
    }
  }
  if (made) return <ScriptDialog made={made} onClose={onClose} />
  return (
    <Modal title={t('rt.newTitle')} onClose={onClose} busy={busy}>
      <label htmlFor="rt-kind" className="mb-1.5 block text-[13px] font-medium">{t('rt.kind')}</label>
      <select id="rt-kind" className={`${inputCls} mb-3`} value={kind} onChange={(e) => setKind(e.target.value)}>
        <option value="mikrotik">MikroTik (RouterOS)</option>
        <option value="openwrt">OpenWrt</option>
        <option value="keenetic">{t('rt.kind.keenetic')}</option>
      </select>
      <label htmlFor="rt-name" className="mb-1.5 block text-[13px] font-medium">{t('rt.name')}</label>
      <input id="rt-name" data-autofocus className={inputCls} value={name} maxLength={60} placeholder={t('rt.namePh')} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && void create()} />
      {kind === 'keenetic' && (
        <div className="mt-3 space-y-3">
          <div>
            <label htmlFor="rt-url" className="mb-1.5 block text-[13px] font-medium">{t('rt.url')}</label>
            <input id="rt-url" className={inputCls} value={url} maxLength={255} placeholder={t('rt.urlPh')} autoComplete="off" onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div>
            <label htmlFor="rt-login" className="mb-1.5 block text-[13px] font-medium">{t('rt.login')}</label>
            <input id="rt-login" className={inputCls} value={login} maxLength={64} autoComplete="off" onChange={(e) => setLogin(e.target.value)} />
          </div>
          <div>
            <label htmlFor="rt-pass" className="mb-1.5 block text-[13px] font-medium">{t('rt.password')}</label>
            <input id="rt-pass" type="password" className={inputCls} value={password} maxLength={128} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
          </div>
          <p className="text-xs text-muted">{t('rt.kHint')}</p>
        </div>
      )}
      {busy && kind === 'keenetic' && <p className="mt-2 text-xs text-muted">{t('rt.checking')}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={create} disabled={busy || !name.trim() || (kind === 'keenetic' && (!url.trim() || !login.trim() || !password))}>{t('rt.create')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

const problem = (d: Device) => !d.online || !!d.pull_error || d.view.internet === false || (d.new_forwards?.length ?? 0) > 0

function RouterTile({ d }: { d: Device }) {
  const v = d.view
  const memPct = v.mem_total > 0 ? Math.round(((v.mem_total - v.mem_free) * 100) / v.mem_total) : null
  const kind = d.kind === 'openwrt' ? 'OpenWrt' : d.kind === 'keenetic' ? 'Keenetic' : 'MikroTik'
  return (
    <Link to={`/routers/${d.id}`} className="block rounded-card border border-line bg-surface p-3.5 hover:border-cyan/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[15px] font-medium">{d.name}</div>
          <div className="truncate text-xs text-muted">{[kind, d.group].filter(Boolean).join(' · ')}</div>
        </div>
        {d.online ? <Chip tone="green">{t('rt.online')}</Chip> : <Chip tone="red">{t('rt.offline')}</Chip>}
      </div>
      <div className="tnum mt-3 grid grid-cols-3 gap-2 text-xs">
        <div><div className="text-muted">{t('rt.cpu')}</div><div className="text-[15px]">{d.online ? `${Math.round(v.cpu)}%` : '—'}</div></div>
        <div><div className="text-muted">{t('rt.mem')}</div><div className="text-[15px]">{d.online && memPct !== null ? `${memPct}%` : '—'}</div></div>
        <div><div className="text-muted">{t('rt.tileClients')}</div><div className="text-[15px]">{v.clients.length}</div></div>
      </div>
      <div className="mt-3 flex min-h-[26px] flex-wrap items-center gap-1.5">
        {d.pull_error && <Chip tone="red">{t(`rt.pullErr.${d.pull_error}` as MsgKey)}</Chip>}
        {v.internet === false && <Chip tone="red">{t('rt.noInternet')}</Chip>}
        {(d.new_forwards?.length ?? 0) > 0 && <Chip tone="red">{t('rt.newFwN', { n: d.new_forwards?.length ?? 0 })}</Chip>}
        {!d.pull_error && v.internet !== false && (d.new_forwards?.length ?? 0) === 0 && <span className="text-xs text-muted">{t('rt.allFine')}</span>}
      </div>
    </Link>
  )
}

function GroupDialog({ d, groups, onClose, onDone }: { d: Device; groups: string[]; onClose: () => void; onDone: () => void }) {
  const [group, setGroup] = useState(d.group ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const save = async () => {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/net-devices/${d.id}`, { group: group.trim() })
      onDone()
      onClose()
    } catch (e) {
      setError(why(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('rt.groupTitle', { name: d.name })} onClose={onClose} busy={busy}>
      <label htmlFor="rt-group" className="mb-1.5 block text-[13px] font-medium">{t('rt.group')}</label>
      <input id="rt-group" list="rt-groups" data-autofocus className={inputCls} value={group} maxLength={40} placeholder={t('rt.groupPh')} onChange={(e) => setGroup(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void save()} />
      <datalist id="rt-groups">{groups.map((g) => <option key={g} value={g} />)}</datalist>
      <p className="mt-2 text-xs text-muted">{t('rt.groupHint')}</p>
      {error && <p role="alert" className="mt-2 text-xs text-red">{error}</p>}
      <div className="mt-4 flex gap-2">
        <PrimaryButton size="m" onClick={save} disabled={busy}>{t('rt.save')}</PrimaryButton>
        <GhostButton size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
      </div>
    </Modal>
  )
}

export default function Routers() {
  const { filters } = useApp()
  const { id } = useParams()
  const nav = useNavigate()
  const { data, error, reload } = useLoad((s) => api.get<{ devices: Device[] }>('/api/v1/net-devices', s), [], 30_000)
  const [groupFilter, setGroupFilter] = useState('')
  const [only, setOnly] = useState<'all' | 'problems'>('all')
  const [kindFilter, setKindFilter] = useState('')
  const [grouping, setGrouping] = useState<Device | null>(null)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Device | null>(null)
  const [renaming, setRenaming] = useState<Device | null>(null)
  const [passwording, setPasswording] = useState<Device | null>(null)
  const [busy, setBusy] = useState(false)
  const [parentError, setParentError] = useState('')
  const setParent = async (id: string, parent: string) => {
    setParentError('')
    try {
      await api.patch(`/api/v1/net-devices/${id}`, { parent_id: parent })
    } catch {
      setParentError(t('rt.parentErr'))
    }
    reload()
  }
  const confirmFw = async (id: string) => {
    try {
      await api.post(`/api/v1/net-devices/${id}/forwards/confirm`, {})
    } catch {
      /* the list reloads below and shows what is still open */
    }
    reload()
  }
  const remove = async () => {
    if (!removing) return
    setBusy(true)
    try {
      await api.del(`/api/v1/net-devices/${removing.id}`)
      setRemoving(null)
      if (id) nav('/routers')
      reload()
    } finally {
      setBusy(false)
    }
  }
  const all = data?.devices ?? []
  const groups = [...new Set(all.map((d) => d.group).filter((g): g is string => !!g))].sort((a, b) => a.localeCompare(b, 'ru'))
  const kinds = [...new Set(all.map((d) => d.kind ?? 'mikrotik'))].sort()
  const shown = all
    .filter((d) => (kindFilter === '' ? true : (d.kind ?? 'mikrotik') === kindFilter))
    .filter((d) => (groupFilter === '' ? true : groupFilter === '\u0000' ? !d.group : d.group === groupFilter))
    .filter((d) => (only === 'problems' ? problem(d) : true))
    .sort((a, b) => Number(problem(b)) - Number(problem(a)) || a.name.localeCompare(b.name, 'ru'))
  const one = id ? all.find((d) => d.id === id) : undefined
  return (
    <div className="space-y-5">
      <PageHead title={t('rt.title')} subtitle={t('rt.subtitle')} right={<PrimaryButton size="m" onClick={() => setAdding(true)}><Plus size={14} aria-hidden className="mr-1 inline" />{t('rt.add')}</PrimaryButton>} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {parentError && <p role="alert" className="text-[13px] text-red">{parentError}</p>}
      {!data && !error && <Skeleton className="h-40" />}
      {data && all.length === 0 && <p className="text-[13px] text-muted">{t('rt.empty')}</p>}
      {id && data && (
        <div className="space-y-3">
          <Link to="/routers" className="inline-flex items-center gap-1.5 text-[13px] text-muted hover:text-fg"><ArrowLeft size={14} aria-hidden />{t('rt.back')}</Link>
          {one ? <DeviceCard d={one} tz={filters.tz} others={all.filter((o) => o.id !== one.id)} onParent={(p) => void setParent(one.id, p)} onRename={() => setRenaming(one)} onRemove={() => setRemoving(one)} onPassword={() => setPasswording(one)} onGroup={() => setGrouping(one)} onConfirmFw={() => void confirmFw(one.id)} onReload={reload} /> : <p className="text-[13px] text-muted">{t('rt.notFound')}</p>}
        </div>
      )}
      {!id && data && all.length > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            {groups.length > 0 && (
              <Segmented label={t('rt.groups')} value={groupFilter} onChange={setGroupFilter} options={[
                { value: '', label: t('rt.f.all') },
                ...groups.map((g) => ({ value: g, label: g })),
                { value: '\u0000', label: t('rt.f.noGroup') },
              ]} />
            )}
            {kinds.length > 1 && (
              <Segmented label={t('rt.brands')} value={kindFilter} onChange={setKindFilter} options={[
                { value: '', label: t('rt.f.all') },
                ...kinds.map((k) => ({ value: k, label: k === 'openwrt' ? 'OpenWrt' : k === 'keenetic' ? 'Keenetic' : 'MikroTik' })),
              ]} />
            )}
            <Segmented label={t('rt.state')} value={only} onChange={setOnly} options={[{ value: 'all', label: t('rt.f.all') }, { value: 'problems', label: t('rt.f.problems') }]} />
          </div>
          {shown.length === 0 ? <p className="text-[13px] text-muted">{t('rt.emptyFilter')}</p> : (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {shown.map((d) => <RouterTile key={d.id} d={d} />)}
            </div>
          )}
        </>
      )}
      {grouping && <GroupDialog d={grouping} groups={groups} onClose={() => setGrouping(null)} onDone={reload} />}
      {passwording && <PasswordDialog d={passwording} onClose={() => setPasswording(null)} onDone={reload} />}
      {renaming && <RenameDialog d={renaming} onClose={() => setRenaming(null)} onDone={reload} />}
      {adding && <NewDialog onClose={() => setAdding(false)} onMade={reload} />}
      {removing && (
        <Modal title={t('rt.removeTitle', { name: removing.name })} onClose={() => setRemoving(null)} busy={busy}>
          <p className="text-[13px] text-muted">{t(removing.kind === 'keenetic' ? 'rt.removeNoteK' : 'rt.removeNote')}</p>
          <div className="mt-4 flex gap-2">
            <DangerButton size="m" onClick={remove} disabled={busy}>{t('rt.remove')}</DangerButton>
            <GhostButton size="m" onClick={() => setRemoving(null)} disabled={busy}>{t('common.cancel')}</GhostButton>
          </div>
        </Modal>
      )}
    </div>
  )
}
