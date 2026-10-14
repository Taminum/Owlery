import { useState } from 'react'
import { AlertTriangle, CircleCheck, CircleSlash, FlaskConical, Hourglass, Plus, Server } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { can, useAuth } from '../lib/auth'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import { errorText } from '../lib/errors'
import { formatDateTime, formatInt, plural } from '../lib/format'
import type { Capabilities, PanelDTO, ProbeSummary } from '../lib/types'
import { Card, Chip, Skeleton } from '../components/ui'
import { GhostButton, PrimaryButton } from '../components/Modal'
import { Wizard } from '../components/Wizard'
import { AgentsDialog } from '../components/AgentsDialog'
import { DeleteDialog, ProbeResultDialog, RotateDialog, RunsDialog, SettingsDialog } from '../components/PanelDialogs'

type Dialog =
  | { kind: 'wizard' }
  | { kind: 'rotate' | 'delete' | 'settings' | 'runs' | 'agents'; panel: PanelDTO }
  | { kind: 'probe'; panel: PanelDTO; summary: ProbeSummary }
  | null

const statusChip = (p: PanelDTO) => {
  if (p.demo) return <Chip icon={FlaskConical} tone="amber">{t('panels.demoBadge')}</Chip>
  switch (p.status) {
    case 'active': return <Chip icon={CircleCheck} tone="green">{t('panels.status.active')}</Chip>
    case 'error': return <Chip icon={AlertTriangle} tone="red">{t('panels.status.error')}</Chip>
    case 'disabled': return <Chip icon={CircleSlash}>{t('panels.status.disabled')}</Chip>
    default: return <Chip icon={Hourglass} tone="amber">{t('panels.status.pending')}</Chip>
  }
}

const syncLabel = (s: string | null): string => {
  if (!s) return t('panels.never')
  const key = `panels.sync.${s}` as MsgKey
  const text = t(key)
  return text === undefined || (text as string) === 'undefined' ? s : text
}

export default function Panels() {
  const { me } = useAuthedMe()
  const { filters, reloadScope } = useApp()
  const list = useLoad((signal) => api.get<{ panels: PanelDTO[]; can_create: boolean; custom_ca_available: boolean }>('/api/v1/panels', signal), [], 15000)
  const panels = list.data?.panels ?? null
  const canCreate = list.data?.can_create ?? false
  const caAvailable = list.data?.custom_ca_available ?? false
  const error = list.error
  const load = list.reload
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)
  const [busy, setBusy] = useState<string>('')

  const changed = () => {
    load()
    reloadScope()
  }

  async function act(p: PanelDTO, name: string, fn: () => Promise<void>) {
    setBusy(`${p.id}:${name}`)
    setNotice(null)
    try {
      await fn()
    } catch (e) {
      setNotice({ ok: false, text: errorText(e) })
    } finally {
      setBusy('')
    }
  }

  const test = (p: PanelDTO) => act(p, 'test', async () => {
    const summary = await api.post<ProbeSummary>(`/api/v1/panels/${p.id}/test`)
    setDialog({ kind: 'probe', panel: p, summary })
    load()
  })
  const sync = (p: PanelDTO) => act(p, 'sync', async () => {
    await api.post(`/api/v1/panels/${p.id}/sync`)
    setNotice({ ok: true, text: t('panels.syncStarted') })
    setTimeout(load, 2500)
  })
  const toggle = (p: PanelDTO) => act(p, 'toggle', async () => {
    await api.post(`/api/v1/panels/${p.id}/${p.status === 'disabled' ? 'enable' : 'disable'}`)
    changed()
  })

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[22px] font-semibold leading-8">{t('panels.title')}</h1>
          <p className="mt-1 max-w-2xl text-[13px] text-muted">{t('panels.subtitle')}</p>
        </div>
        {canCreate && <PrimaryButton onClick={() => setDialog({ kind: 'wizard' })}><span className="inline-flex items-center gap-2"><Plus size={16} aria-hidden />{t('panels.add')}</span></PrimaryButton>}
      </header>

      <div aria-live="polite">
        {notice && <p role={notice.ok ? 'status' : 'alert'} className={`rounded-control border px-3 py-2 text-[13px] ${notice.ok ? 'border-green/40 bg-green/10 text-green' : 'border-red/40 bg-red/10 text-red'}`}>{notice.text}</p>}
        {error && <p role="alert" className="rounded-control border border-red/40 bg-red/10 px-3 py-2 text-[13px] text-red">{error}</p>}
      </div>

      {!panels && !error && <div className="grid gap-4 xl:grid-cols-2"><Skeleton className="h-[260px]" /><Skeleton className="h-[260px]" /></div>}
      {panels && panels.length === 0 && (
        <Card><div className="py-8 text-center"><Server className="mx-auto mb-3 text-muted" size={28} aria-hidden />
          <p className="font-medium">{t('panels.empty')}</p>
          <p className="mx-auto mt-1 max-w-md text-[13px] text-muted">{canCreate ? t('panels.emptyHint') : t('panels.emptyViewer')}</p>
        </div></Card>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        {panels?.map((p) => {
          const tz = filters.tz
          const canOperate = can(me, p.id, 'operate')
          const canAdmin = can(me, p.id, 'admin')
          const caps = Object.entries(p.capabilities ?? {}) as [keyof Capabilities, boolean][]
          return (
            <Card key={p.id} className="flex flex-col">
              <div className="mb-3 flex flex-wrap items-center gap-2.5">
                <h2 className="text-[16px] font-semibold">{p.name}</h2>
                {statusChip(p)}
                <span className="text-xs text-muted">{t(`role.${p.role || 'viewer'}` as MsgKey)}</span>
              </div>
              {p.demo ? <p className="text-[13px] text-muted">{t('panels.demoNote')}</p> : (
                <dl className="grid gap-x-4 gap-y-1.5 text-[13px] sm:grid-cols-[150px_1fr]">
                  <dt className="text-muted">{t('panels.url')}</dt><dd className="break-all">{p.base_url}</dd>
                  <dt className="text-muted">{t('panels.token')}</dt><dd>{p.token === 'configured' ? t('panels.tokenConfigured') : t('panels.tokenNone')}</dd>
                  <dt className="text-muted">{t('panels.version')}</dt><dd>{p.api_version ?? '—'}</dd>
                  <dt className="text-muted">{t('panels.lastSync')}</dt>
                  <dd>{p.last_sync_at ? <>{formatDateTime(p.last_sync_at, tz)} · {syncLabel(p.last_sync_status)}</> : syncLabel(p.last_sync_status)}
                    {p.next_sync_at && p.status === 'active' && <span className="block text-xs text-muted">{t('panels.nextSync', { t: formatDateTime(p.next_sync_at, tz) })}</span>}</dd>
                  {p.consecutive_failures > 0 && (<><dt className="text-muted" /><dd className="text-xs text-amber">{t('panels.failures', { n: p.consecutive_failures })}{p.circuit_open_until && ` · ${t('panels.circuit', { t: formatDateTime(p.circuit_open_until, tz) })}`}</dd></>)}
                </dl>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-[13px]">
                <span><span className="tnum text-[18px] font-semibold">{formatInt(p.node_count)}</span> <span className="text-muted">{plural(p.node_count, 'нода', 'ноды', 'нод')}</span></span>
                <span><span className="tnum text-[18px] font-semibold">{formatInt(p.user_count)}</span> <span className="text-muted">{plural(p.user_count, 'пользователь', 'пользователя', 'пользователей')}</span></span>
                {!p.demo && caps.length > 0 && (
                  <span className="flex flex-wrap gap-1.5" aria-label={t('panels.capabilities')}>
                    {caps.map(([k, v]) => <Chip key={k} tone={v ? 'green' : 'muted'} icon={v ? CircleCheck : CircleSlash}>{t(`panels.cap.${k}` as MsgKey)}</Chip>)}
                  </span>
                )}
              </div>
              {!p.demo && (
                <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3">
                  {canOperate && <GhostButton className="!h-9 !px-3 !text-[13px]" disabled={!!busy} onClick={() => void test(p)}>{busy === `${p.id}:test` ? '…' : t('panels.action.test')}</GhostButton>}
                  {canOperate && p.status !== 'disabled' && <GhostButton className="!h-9 !px-3 !text-[13px]" disabled={!!busy} onClick={() => void sync(p)}>{t('panels.action.sync')}</GhostButton>}
                  {canOperate && <GhostButton className="!h-9 !px-3 !text-[13px]" onClick={() => setDialog({ kind: 'runs', panel: p })}>{t('panels.action.runs')}</GhostButton>}
                  {canOperate && <GhostButton className="!h-9 !px-3 !text-[13px]" onClick={() => setDialog({ kind: 'agents', panel: p })}>{t('agents.action')}</GhostButton>}
                  {canAdmin && <GhostButton className="!h-9 !px-3 !text-[13px]" onClick={() => setDialog({ kind: 'rotate', panel: p })}>{t('panels.action.token')}</GhostButton>}
                  {canAdmin && <GhostButton className="!h-9 !px-3 !text-[13px]" onClick={() => setDialog({ kind: 'settings', panel: p })}>{t('panels.action.settings')}</GhostButton>}
                  {canAdmin && <GhostButton className="!h-9 !px-3 !text-[13px]" disabled={!!busy} onClick={() => void toggle(p)}>{p.status === 'disabled' ? t('panels.action.enable') : t('panels.action.disable')}</GhostButton>}
                  {me.account.is_owner && <GhostButton className="!h-9 !border-red/50 !px-3 !text-[13px] !text-red" onClick={() => setDialog({ kind: 'delete', panel: p })}>{t('panels.action.remove')}</GhostButton>}
                </div>
              )}
            </Card>
          )
        })}
      </div>

      {dialog?.kind === 'wizard' && <Wizard customCAAvailable={caAvailable} onClose={() => setDialog(null)} onSaved={changed} />}
      {dialog?.kind === 'rotate' && <RotateDialog panel={dialog.panel} onClose={() => setDialog(null)} onDone={() => { setNotice({ ok: true, text: t('rotate.done') }); changed() }} />}
      {dialog?.kind === 'delete' && <DeleteDialog panel={dialog.panel} onClose={() => setDialog(null)} onDone={changed} />}
      {dialog?.kind === 'settings' && <SettingsDialog panel={dialog.panel} customCAAvailable={caAvailable} onClose={() => setDialog(null)} onDone={() => { setNotice({ ok: true, text: t('settingsDlg.saved') }); changed() }} />}
      {dialog?.kind === 'agents' && <AgentsDialog panel={dialog.panel} tz={filters.tz} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'runs' && <RunsDialog panel={dialog.panel} tz={filters.tz} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'probe' && <ProbeResultDialog panel={dialog.panel} summary={dialog.summary} onClose={() => setDialog(null)} />}
    </div>
  )
}

function useAuthedMe() {
  const { state } = useAuth()
  if (state.status !== 'authed') throw new Error('not signed in')
  return { me: state.me }
}
