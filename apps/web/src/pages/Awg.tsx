import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useApp } from '../lib/context'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { useAuth } from '../lib/auth'
import { Card, Chip, RowMenu } from '../components/ui'
import { PageHead } from '../components/Analyzer'
import { Drawer } from '../components/Drawer'
import { controlCls } from '../components/Popover'
import { AddDevice, RenameDevice, RevokeDevice } from '../components/AwgDevice'
import { AwgHosts, RemoveContainer } from '../components/AwgContainers'
import { BackupContainer, TransferContainer } from '../components/AwgBackup'
import { DeviceLimits, LimitLine } from '../components/AwgLimits'
import { GhostButton } from '../components/Modal'
import { Pair, PeerDetail, TONE, ago, type Peer } from '../components/AwgPeer'

interface Instance {
  id: string; panel_id: string; host?: string; container: string; interface: string; port?: number; variant?: string; mode: string
  last_report: string; report_fresh: boolean; counters_since: string | null; legacy_at?: string | null; peers: Peer[]
}
interface AwgResponse { instances: Instance[]; period: string }
const PERIODS = ['1h', '24h', '7d', '30d'] as const
export default function Awg() {
  const { filters } = useApp()
  const tz = filters.tz
  const [period, setPeriod] = useState<(typeof PERIODS)[number]>('24h')
  const [open, setOpen] = useState<{ peer: Peer; panel: string } | null>(null)
  const [adding, setAdding] = useState<Instance | null>(null)
  const [removingServer, setRemovingServer] = useState<Instance | null>(null)
  const [backingUp, setBackingUp] = useState<Instance | null>(null)
  const [transferring, setTransferring] = useState<Instance | null>(null)
  const [revoking, setRevoking] = useState<Peer | null>(null)
  const [limiting, setLimiting] = useState<Peer | null>(null)
  const [renaming, setRenaming] = useState<Peer | null>(null)
  const q = useLoad((s) => api.get<AwgResponse>(`/api/v1/awg?period=${period}`, s), [period], 30_000)
  const { state: auth } = useAuth()
  const canForget = auth.status === 'authed' && auth.me.account.is_owner
  async function forget(p: Peer) {
    try {
      await api.del(`/api/v1/awg/peers/${p.id}`)
    } catch {
      /* the list below is reloaded either way: a failed removal shows up as the row still being there */
    }
    q.reload()
  }
  const day = (iso: string | null) => (iso ? formatDateTime(iso, tz) : '—')

  function lastSeen(p: Peer) {
    if (!p.last_seen_at) return <span className="text-muted">{t('awg.never')}</span>
    return <span>{p.last_seen_source === 'live' ? ago(p.last_seen_at) : day(p.last_seen_at)}</span>
  }

  return (
    <div className="space-y-5">
      <PageHead title={t('awg.title')} subtitle={t('awg.subtitle')}
        right={
          <label className="flex items-center gap-2 text-[13px] text-muted">
            {t('awg.period')}
            <select className={controlCls} value={period} onChange={(e) => setPeriod(e.target.value as (typeof PERIODS)[number])}>
              {PERIODS.map((p) => <option key={p} value={p}>{t(`awg.p.${p}` as MsgKey)}</option>)}
            </select>
          </label>
        } />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {q.data && q.data.instances.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('awg.empty')}</p>}
      {canForget && <AwgHosts onChanged={() => q.reload()} />}
      {q.data?.instances.map((in_) => (
        <Card key={in_.id}
          right={canForget && in_.mode === 'managed' ? (
            <div className="flex flex-wrap items-center gap-2">
              <GhostButton onClick={() => setAdding(in_)}>{t('awg.add')}</GhostButton>
              {/^amnezia-awg\d{0,2}$/.test(in_.container) && <GhostButton onClick={() => setBackingUp(in_)}>{t('awgb.backup')}</GhostButton>}
              {/^amnezia-awg\d{0,2}$/.test(in_.container) && <GhostButton onClick={() => setTransferring(in_)}>{t('awgb.transfer')}</GhostButton>}
              {/^amnezia-awg\d{0,2}$/.test(in_.container) && <GhostButton onClick={() => setRemovingServer(in_)}>{t('awgc.remove')}</GhostButton>}
            </div>
          ) : undefined}
          title={`${in_.host ? `${in_.host.replace(/^awg-/, '')} · ` : ''}${in_.container} · ${in_.interface}`}
          note={[in_.port ? t('awg.port', { n: in_.port }) : '', in_.variant ? t('awg.variant', { v: in_.variant }) : '', t(`awg.mode.${in_.mode}` as MsgKey), t('awg.report', { when: ago(in_.last_report) })].filter(Boolean).join(' · ')}>
          {!in_.report_fresh && <p role="status" className="mb-3 text-[13px] text-amber">{t('awg.noReport')}</p>}
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{`${in_.container} ${in_.interface}`}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.peer')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.ip')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.state')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.lastSeen')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.range')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('awg.col.total')}</th>
                {canForget && <th scope="col" className="px-2 py-2"><span className="sr-only">{t('awg.actions')}</span></th>}
              </tr></thead>
              <tbody>
                {in_.peers.map((p) => (
                  <tr key={p.id} className={`border-t border-line/60 ${p.gone ? 'opacity-60' : ''}`}>
                    <td className="px-2 py-2">
                      <button type="button" onClick={() => setOpen({ peer: p, panel: in_.panel_id })} className="font-medium underline-offset-2 hover:text-cyan hover:underline">{p.label}</button>
                      {p.gone && <span className="ml-2 text-xs text-muted">{t('awg.gone')}</span>}
                      <LimitLine p={p} tz={tz} />
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-muted">{p.tunnel_ip ?? '—'}</td>
                    <td className="px-2 py-2"><Chip tone={TONE[p.state]}>{t(`awg.state.${p.state}` as MsgKey)}</Chip></td>
                    <td className="px-2 py-2 text-muted">{lastSeen(p)}</td>
                    <td className="tnum px-2 py-2">{in_.report_fresh ? <Pair down={p.download_range} up={p.upload_range} /> : <span className="text-muted">—</span>}</td>
                    <td className="tnum px-2 py-2" title={p.total_since ? t('awg.sinceTip', { when: day(p.total_since) }) : undefined}><Pair down={p.total_download} up={p.total_upload} /></td>
                    {canForget && (
                      <td className="whitespace-nowrap px-2 py-2 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {!p.gone && in_.mode === 'managed' && <GhostButton size="s" onClick={() => setLimiting(p)} aria-label={`${t('awgl.limits')}: ${p.label}`}>{t('awgl.limits')}</GhostButton>}
                          {!p.gone && in_.mode !== 'managed' && <GhostButton size="s" onClick={() => setRenaming(p)} aria-label={`${t('awg.rename')}: ${p.label}`}>{t('awg.rename')}</GhostButton>}
                          <RowMenu label={p.label} actions={[
                            { label: t('awg.rename'), onClick: () => setRenaming(p), hidden: p.gone || in_.mode !== 'managed' },
                            { label: t('awg.revoke'), onClick: () => setRevoking(p), danger: true, hidden: p.gone || in_.mode !== 'managed' },
                            { label: t('awg.forget'), onClick: () => void forget(p), danger: true, hidden: !p.gone },
                          ]} />
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 space-y-1 text-xs leading-5 text-muted">
            <p>{in_.counters_since ? t('awg.since.server', { when: day(in_.counters_since) }) : t('awg.since.serverUnknown')}</p>
            <p>{in_.legacy_at ? t('awg.since.total', { legacy: day(in_.legacy_at) }) : t('awg.since.totalOwn')}</p>
          </div>
        </Card>
      ))}
      {q.data && q.data.instances.length > 0 && (
        <div className="space-y-1 text-xs leading-5 text-muted"><p>{t('awg.state.hint')}</p><p>{t('awg.direction')}</p></div>
      )}
      {adding && <AddDevice instanceId={adding.id} container={adding.container} onClose={() => setAdding(null)} onDone={() => q.reload()} />}
      {backingUp && <BackupContainer instanceId={backingUp.id} container={backingUp.container} onClose={() => setBackingUp(null)} />}
      {transferring && <TransferContainer instanceId={transferring.id} container={transferring.container} onClose={() => setTransferring(null)} onDone={() => q.reload()} />}
      {removingServer && <RemoveContainer instanceId={removingServer.id} container={removingServer.container} onClose={() => setRemovingServer(null)} onDone={() => q.reload()} />}
      {revoking && <RevokeDevice peerId={revoking.id} label={revoking.label} onClose={() => setRevoking(null)} onDone={() => q.reload()} />}
      {limiting && <DeviceLimits peerId={limiting.id} label={limiting.label} current={limiting} onClose={() => setLimiting(null)} onDone={() => q.reload()} />}
      {renaming && <RenameDevice peerId={renaming.id} label={renaming.label} onClose={() => setRenaming(null)} onDone={() => q.reload()} />}
      {open && <Drawer title={open.peer.label} onClose={() => setOpen(null)}><PeerDetail peer={open.peer} range={period} panelId={open.panel} /></Drawer>}
    </div>
  )
}
