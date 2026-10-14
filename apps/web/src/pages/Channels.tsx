import { useState } from 'react'
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Plus, Trash2 } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { can, useAuth } from '../lib/auth'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { useApp } from '../lib/context'
import { errorText } from '../lib/errors'
import { formatDateTime, formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { ProbeTarget, ProbesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'

const STATE = { up: ['ch.up', 'green'], down: ['ch.down', 'red'], unknown: ['ch.unknown', 'muted'] } as const
const ERR: Record<string, string> = { timeout: 'ch.err.timeout', refused: 'ch.err.refused', dns: 'ch.err.dns', tls: 'ch.err.tls', unreachable: 'ch.err.unreachable', blocked_address: 'ch.err.blocked' }

function Ms({ v }: { v: number | null }) {
  return <span className="tnum">{v == null ? '—' : `${formatInt(v)} мс`}</span>
}

function Card1({ c, tz, canEdit, onDelete }: { c: ProbeTarget; tz: string; canEdit: boolean; onDelete: () => void }) {
  const look = useLook()
  const [label, tone] = STATE[c.state]
  const data = c.series.map((p) => ({ ts: p.ts * 1000, ms: p.ms, bad: p.failed > 0 ? (p.ms ?? 0) : null }))
  return (
    <Card title={c.name} note={`${c.mode === 'tls' ? 'TLS' : 'TCP'} · ${c.host}:${c.port}${c.sni ? ` · SNI ${c.sni}` : ''} · ${c.panel_name}`}
      right={canEdit ? <button type="button" onClick={onDelete} aria-label={`${t('ch.delete')}: ${c.name}`} className="grid h-8 w-8 place-items-center rounded-control text-muted hover:bg-elevated hover:text-red"><Trash2 size={15} aria-hidden /></button> : undefined}>
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <Chip tone={tone}>{t(label)}</Chip>
        {c.state === 'down' && c.last_error && <span className="text-red">{t((ERR[c.last_error] ?? 'ch.err.unreachable') as 'ch.err.timeout')}</span>}
        {c.last_at && <span className="tnum text-muted">{t('ch.last')}: {formatDateTime(c.last_at, tz)}</span>}
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-4">
        <div><dt className="text-xs text-muted">{t('ch.connect')}</dt><dd className="text-[18px] font-semibold"><Ms v={c.p50_connect_ms} /></dd></div>
        <div><dt className="text-xs text-muted">{t('ch.tls')}</dt><dd className="text-[18px] font-semibold"><Ms v={c.p50_tls_ms} /></dd></div>
        <div><dt className="text-xs text-muted">{t('ch.loss')}</dt><dd className={`tnum text-[18px] font-semibold ${c.loss_pct > 0 ? 'text-amber' : ''}`}>{c.samples_1h ? `${c.loss_pct.toFixed(c.loss_pct % 1 ? 1 : 0).replace('.', ',')}%` : '—'}</dd></div>
        <div><dt className="text-xs text-muted">{t('ch.samples')}</dt><dd className="tnum text-[18px] font-semibold">{formatInt(c.samples_1h)}</dd></div>
      </dl>
      <div className="mt-3 h-[110px]" role="img" aria-label={`${t('ch.chart')}: ${c.name}`}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={10} tickLine={false} axisLine={false} tickCount={5}
              tickFormatter={(v: number) => new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz === 'local' ? undefined : tz }).format(new Date(v))} />
            <YAxis stroke={C.muted} fontSize={10} tickLine={false} axisLine={false} width={40} tickFormatter={(v: number) => `${v}`} />
            <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v) / 1000, tz)} formatter={(v) => `${v} мс`} />
            <Area {...look(data.length)} dataKey="ms" name={t('ch.ms')} stroke={C.cyan} fill={C.cyan} fillOpacity={0.2} connectNulls isAnimationActive={false} />
            <Area {...look(data.length)} dataKey="bad" name={t('ch.lossPoints')} stroke={C.red} fill={C.red} fillOpacity={0.35} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}

function AddDialog({ panels, onClose, onDone }: { panels: { id: string; name: string }[]; onClose: () => void; onDone: () => void }) {
  const [panel, setPanel] = useState(panels[0]?.id ?? '')
  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [mode, setMode] = useState<'tls' | 'tcp'>('tls')
  const [sni, setSni] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function save() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/probes', { panel_id: panel, name: name.trim(), host: host.trim(), port: Number(port), mode, sni: sni.trim() })
      onDone()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  const valid = panel && name.trim() && host.trim() && Number(port) >= 1 && Number(port) <= 65535
  return (
    <Modal title={t('ch.add')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && valid) void save() }}>
        <p className="text-[13px] text-muted">{t('ch.addHint')}</p>
        {panels.length > 1 && (
          <Field label={t('ch.panel')} htmlFor="ch-panel">
            <select id="ch-panel" className={inputCls} value={panel} onChange={(e) => setPanel(e.target.value)}>{panels.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
          </Field>
        )}
        <Field label={t('ch.name')} htmlFor="ch-name"><input id="ch-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} data-autofocus /></Field>
        <div className="grid grid-cols-[1fr_110px] gap-3">
          <Field label={t('ch.host')} htmlFor="ch-host"><input id="ch-host" className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" spellCheck={false} placeholder="fi.example.com" /></Field>
          <Field label={t('ch.port')} htmlFor="ch-port"><input id="ch-port" className={inputCls} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></Field>
        </div>
        <Field label={t('ch.mode')} htmlFor="ch-mode">
          <select id="ch-mode" className={inputCls} value={mode} onChange={(e) => setMode(e.target.value as 'tls' | 'tcp')}>
            <option value="tls">{t('ch.mode.tls')}</option>
            <option value="tcp">{t('ch.mode.tcp')}</option>
          </select>
        </Field>
        {mode === 'tls' && <Field label={t('ch.sni')} hint={t('ch.sniHint')} htmlFor="ch-sni"><input id="ch-sni" className={inputCls} value={sni} onChange={(e) => setSni(e.target.value)} spellCheck={false} /></Field>}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !valid}>{t('ch.addSubmit')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export default function Channels() {
  const { filters, panels } = useApp()
  const { state } = useAuth()
  const q = filters.panels.length ? `?panel_ids=${filters.panels.join(',')}` : ''
  const { data, error, reload } = useLoad((s) => api.get<ProbesResponse>(`/api/v1/probes${q}`, s), [q], 30_000)
  const [adding, setAdding] = useState(false)
  const [err, setErr] = useState('')
  const me = state.status === 'authed' ? state.me : null
  const editable = me ? panels.filter((p) => !p.demo && can(me, p.id, 'admin')) : []
  const canEditPanel = (id: string) => !!me && can(me, id, 'admin')

  async function remove(c: ProbeTarget) {
    setErr('')
    try {
      await api.del(`/api/v1/probes/${c.id}`)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }

  return (
    <div className="space-y-4">
      <PageHead title={t('ch.title')} subtitle={t('ch.subtitle')}
        right={editable.length > 0 ? <PrimaryButton onClick={() => setAdding(true)}><span className="inline-flex items-center gap-2"><Plus size={16} aria-hidden />{t('ch.add')}</span></PrimaryButton> : undefined} />
      {(error || err) && <p role="alert" className="text-[13px] text-red">{error || err}</p>}
      {!data && !error && <TableSkeleton />}
      {data && data.targets.length === 0 && (
        <div role="status" className="rounded-card border border-line bg-surface px-6 py-12 text-center">
          <h2 className="text-lg font-semibold">{t('ch.none')}</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-[13px] leading-5 text-muted">{t('ch.noneText')}</p>
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        {data?.targets.map((c) => <Card1 key={c.id} c={c} tz={filters.tz} canEdit={canEditPanel(c.panel_id)} onDelete={() => void remove(c)} />)}
      </div>
      {adding && <AddDialog panels={editable} onClose={() => setAdding(false)} onDone={() => { setAdding(false); reload() }} />}
    </div>
  )
}
