import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Plus, Unlink } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { can, useAuth } from '../lib/auth'
import { useApp } from '../lib/context'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { VPS, VPSList } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'

const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean)

function VPSDialog({ vps, onClose, onDone }: { vps?: VPS; onClose: () => void; onDone: (v: VPS) => void }) {
  const [name, setName] = useState(vps?.name ?? '')
  const [note, setNote] = useState(vps?.note ?? '')
  const [addrs, setAddrs] = useState(vps?.addresses.map((a) => a.address).join('\n') ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function save() {
    setBusy(true)
    setError('')
    try {
      const body = { name: name.trim(), note: note.trim(), addresses: lines(addrs) }
      const v = vps ? await api.patch<VPS>(`/api/v1/security/vps/${vps.id}`, body) : await api.post<VPS>('/api/v1/security/vps', body)
      onDone(v)
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={vps ? t('sec.save') : t('sec.add')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && name.trim()) void save() }}>
        <Field label={t('sec.name')} htmlFor="sec-name"><input id="sec-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} data-autofocus /></Field>
        <Field label={t('sec.addresses')} hint={t('sec.addressesHint')} htmlFor="sec-addrs">
          <textarea id="sec-addrs" className={`${inputCls} h-28 py-2 font-mono text-[13px]`} value={addrs} onChange={(e) => setAddrs(e.target.value)} spellCheck={false} />
        </Field>
        <Field label={t('sec.note')} htmlFor="sec-note"><input id="sec-note" className={inputCls} value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !name.trim()}>{vps ? t('sec.save') : t('sec.addSubmit')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export default function Security() {
  const nav = useNavigate()
  const { data, error } = useLoad((s) => api.get<VPSList>('/api/v1/security/vps', s), [], 30_000)
  const [adding, setAdding] = useState(false)
  return (
    <div className="space-y-4">
      <PageHead title={t('sec.title')} subtitle={t('sec.subtitle')}
        right={data?.can_create ? <PrimaryButton onClick={() => setAdding(true)}><span className="inline-flex items-center gap-2"><Plus size={16} aria-hidden />{t('sec.add')}</span></PrimaryButton> : undefined} />
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && data.items.length === 0 && (
        <div role="status" className="rounded-card border border-line bg-surface px-6 py-12 text-center">
          <h2 className="text-lg font-semibold">{t('sec.none')}</h2>
          <p className="mx-auto mt-2 max-w-md text-[13px] text-muted">{data.can_create ? t('sec.noneHint') : t('sec.noneViewer')}</p>
        </div>
      )}
      {data && data.items.length > 0 && (
        <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.items.map((v) => (
            <li key={v.id}>
              <Link to={`/security/${v.id}`} className="block rounded-card border border-line bg-surface p-4 hover:border-blue/60">
                <div className="flex items-start justify-between gap-3">
                  <h2 className="text-[16px] font-semibold">{v.name}</h2>
                  <Chip tone={v.enabled ? 'green' : 'muted'}>{v.enabled ? t('sec.enabled') : t('sec.disabled')}</Chip>
                </div>
                <p className="mt-2 break-words font-mono text-[12px] text-muted">{v.addresses.map((a) => a.address).join(' · ') || '—'}</p>
                <p className="mt-3 text-[12px] text-muted">{t('sec.links')}: {v.links.length} · {t('sec.collectors')}: {t('sec.unknown')}</p>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {adding && <VPSDialog onClose={() => setAdding(false)} onDone={(v) => nav(`/security/${v.id}`)} />}
    </div>
  )
}

export function SecurityDetail() {
  const { id = '' } = useParams()
  const nav = useNavigate()
  const { panels } = useApp()
  const { state } = useAuth()
  const me = state.status === 'authed' ? state.me : null
  const { data: v, error, reload } = useLoad((s) => api.get<VPS>(`/api/v1/security/vps/${id}`, s), [id])
  const [editing, setEditing] = useState(false)
  const [err, setErr] = useState('')
  const [panel, setPanel] = useState('')
  const [node, setNode] = useState('')
  const [confirm, setConfirm] = useState(false)

  const linkable = me ? panels.filter((p) => !p.demo && can(me, p.id, 'admin')) : []
  const panelId = panel || linkable[0]?.id || ''
  const panelOf = (pid: string) => panels.find((p) => p.id === pid)
  const act = async (fn: () => Promise<unknown>) => {
    setErr('')
    try {
      await fn()
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }

  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!v) return <TableSkeleton />
  return (
    <div className="space-y-4">
      <Link to="/security" className="inline-flex items-center gap-2 text-[13px] text-muted hover:text-fg"><ArrowLeft size={15} aria-hidden />{t('sec.back')}</Link>
      <PageHead title={v.name} subtitle={v.note || t('sec.checker')}
        right={v.can_edit ? <GhostButton onClick={() => setEditing(true)}>{t('sec.save')}</GhostButton> : undefined} />
      {err && <p role="alert" className="text-[13px] text-red">{err}</p>}
      {!v.can_edit && <p className="text-[13px] text-muted">{t('sec.readonly')}</p>}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={t('sec.addresses')} note={`${t('sec.enabled')}: ${v.enabled ? '✓' : '—'}`}>
          {v.addresses.length === 0 ? <p className="text-[13px] text-muted">—</p> : (
            <ul className="space-y-1 font-mono text-[13px]">{v.addresses.map((a) => <li key={a.address}>{a.address} <span className="text-muted">({a.kind})</span></li>)}</ul>
          )}
        </Card>

        <Card title={t('sec.links')}>
          {v.links.length === 0 && <p className="text-[13px] text-muted">{t('sec.linksNone')}</p>}
          <ul className="space-y-2">
            {v.links.map((l) => {
              const p = panelOf(l.panel_id)
              const n = p?.nodes.find((x) => x.id === l.node_id)
              const canUnlink = !!me && can(me, l.panel_id, 'admin')
              return (
                <li key={l.id} className="flex items-center justify-between gap-3 text-[13px]">
                  <span>{p?.name ?? l.panel_id} · {l.node_id ? `${t('sec.linkNode')} ${n?.name ?? l.node_id}` : t('sec.linkPanel')}
                    <span className="ml-2 text-xs text-muted">{formatDateTime(l.created_at, 'local')}</span></span>
                  {canUnlink && <button type="button" aria-label={`${t('sec.unlink')}: ${p?.name ?? ''}`} className="grid h-8 w-8 place-items-center rounded-control text-muted hover:bg-elevated hover:text-red"
                    onClick={() => void act(() => api.del(`/api/v1/security/vps/${v.id}/links/${l.id}`))}><Unlink size={15} aria-hidden /></button>}
                </li>
              )
            })}
          </ul>
          {linkable.length > 0 && (
            <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); void act(() => api.post(`/api/v1/security/vps/${v.id}/links`, { panel_id: panelId, node_id: node })).then(() => setNode('')) }}>
              <Field label={t('sec.linkPanelLabel')} htmlFor="sec-lp">
                <select id="sec-lp" className={inputCls} value={panelId} onChange={(e) => { setPanel(e.target.value); setNode('') }}>{linkable.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
              </Field>
              <Field label={t('sec.linkNodeLabel')} htmlFor="sec-ln">
                <select id="sec-ln" className={inputCls} value={node} onChange={(e) => setNode(e.target.value)}>
                  <option value="">{t('sec.linkAll')}</option>
                  {(panelOf(panelId)?.nodes ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                </select>
              </Field>
              <PrimaryButton type="submit">{t('sec.linkAdd')}</PrimaryButton>
            </form>
          )}
        </Card>
      </div>

      <Card title={t('sec.collectors')} note={t('sec.collectorsHint')}>
        <ul className="grid gap-3 text-[13px] sm:grid-cols-2 lg:grid-cols-4">
          {(['sec.fail2ban', 'sec.ports', 'sec.tls', 'sec.firewall'] as const).map((k) => (
            <li key={k} className="flex items-center justify-between rounded-control border border-line px-3 py-2">
              <span>{t(k)}</span><Chip>{t('sec.agentRequired')}</Chip>
            </li>
          ))}
        </ul>
      </Card>

      {me?.account.is_owner && (
        <div>
          <DangerButton onClick={() => setConfirm(true)}>{t('sec.archive')}</DangerButton>
        </div>
      )}
      {confirm && (
        <Modal title={t('sec.archive')} onClose={() => setConfirm(false)}>
          <p className="text-[13px] text-muted">{t('sec.archiveConfirm')}</p>
          <div className="mt-4 flex justify-end gap-3">
            <GhostButton onClick={() => setConfirm(false)}>{t('common.cancel')}</GhostButton>
            <DangerButton onClick={() => void api.del(`/api/v1/security/vps/${v.id}`).then(() => nav('/security')).catch((e) => { setConfirm(false); setErr(errorText(e)) })}>{t('sec.archive')}</DangerButton>
          </div>
        </Modal>
      )}
      {editing && <VPSDialog vps={v} onClose={() => setEditing(false)} onDone={() => { setEditing(false); reload() }} />}
    </div>
  )
}
