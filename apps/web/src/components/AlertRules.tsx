import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'
import type { RuleRow, RulesView } from '../lib/types'
import { Card } from './ui'
import { GhostButton, PrimaryButton } from './Modal'

type Edit = { enabled?: boolean; threshold?: number }

// A number field is as wide as its number: the shared field class is full width.
const numCls = 'h-9 w-20 rounded-control border border-line bg-canvas px-2 text-[14px] text-fg focus-visible:border-cyan disabled:opacity-50'

function rowLabel(r: RuleRow): string {
  if (r.kind === 'disk') return t('ar.disk', { mount: r.mount ?? '' })
  return t(`ar.${r.kind}` as 'ar.cpu')
}

/** The "Тревоги" tab of a machine: the thresholds and switches that differ from the defaults, for this machine only. */
export function AlertRules({ serverId, name }: { serverId: string; name: string }) {
  const q = useLoad((sig) => api.get<RulesView>(`/api/v1/servers/${serverId}/alert-rules`, sig), [serverId])
  const [edits, setEdits] = useState<Record<string, Edit>>({})
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const v = q.data
  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!v) return <p className="text-[13px] text-muted">…</p>
  if (v.rows.length === 0) return <p className="text-[13px] text-muted">{t('ar.none')}</p>

  const now = (r: RuleRow) => ({ enabled: edits[r.rule]?.enabled ?? r.enabled, threshold: edits[r.rule]?.threshold ?? r.threshold })
  const differs = (r: RuleRow) => now(r).enabled !== r.default_enabled || now(r).threshold !== r.default_threshold
  const dirty = v.rows.some((r) => now(r).enabled !== r.enabled || now(r).threshold !== r.threshold)
  const set = (r: RuleRow, e: Edit) => { setMsg(''); setEdits({ ...edits, [r.rule]: { ...edits[r.rule], ...e } }) }

  async function save(rows: { rule: string; enabled: boolean; threshold?: number }[]) {
    setBusy(true)
    setErr('')
    try {
      await api.put<RulesView>(`/api/v1/servers/${serverId}/alert-rules`, { rules: rows })
      setEdits({})
      setMsg(t('ar.saved'))
      q.reload()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  // Only what differs from the defaults is kept, so that a later change of a default reaches machines nobody tuned.
  const send = () => save(v.rows.filter(differs).map((r) => {
    const n = now(r)
    return { rule: r.rule, enabled: n.enabled, ...(n.threshold !== r.default_threshold ? { threshold: n.threshold } : {}) }
  }))

  return (
    <Card title={t('ar.title', { name })} right={v.can_edit ? <GhostButton onClick={() => void save([])} disabled={busy || !v.rows.some((r) => r.changed)}>{t('ar.reset')}</GhostButton> : undefined}>
      {err && <p role="alert" className="mb-2 text-[13px] text-red">{err}</p>}
      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr className="text-left text-xs text-muted">
            <th scope="col" className="py-1 font-normal">{t('ar.what')}</th>
            <th scope="col" className="py-1 font-normal">{t('ar.threshold')}</th>
            <th scope="col" className="py-1 font-normal">{t('ar.on')}</th>
          </tr>
        </thead>
        <tbody>
          {v.rows.map((r) => {
            const n = now(r)
            const unit = t(r.kind === 'forecast' ? 'ar.unit.days' : 'ar.unit.pct')
            return (
              <tr key={r.rule} className="border-t border-line/60">
                <td className="py-2">
                  {rowLabel(r)}
                  {differs(r) && <span className="ml-2 text-xs text-cyan">• {t('ar.changed')}</span>}
                  {r.kind === 'disk' && !r.default_enabled && !differs(r) && <span className="ml-2 text-xs text-muted">{t('ar.notWatched')}</span>}
                </td>
                <td>
                  <input type="number" aria-label={`${rowLabel(r)}: ${t('ar.threshold')}`} className={numCls} min={1} max={r.kind === 'forecast' ? 365 : 100}
                    value={n.threshold} disabled={!v.can_edit || !n.enabled} onChange={(e) => set(r, { threshold: Math.max(1, Math.floor(Number(e.target.value) || 1)) })} />
                  <span className="ml-1.5 text-muted">{unit}</span>
                </td>
                <td>
                  <input type="checkbox" aria-label={`${rowLabel(r)}: ${t('ar.on')}`} checked={n.enabled} disabled={!v.can_edit} onChange={(e) => set(r, { enabled: e.target.checked })} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {v.can_edit ? (
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <PrimaryButton onClick={() => void send()} disabled={busy || !dirty}>{t('ar.save')}</PrimaryButton>
          <span className="text-xs text-muted">{t('ar.hint')}</span>
          {msg && <span role="status" className="text-[13px] text-green">{msg}</span>}
        </div>
      ) : <p className="mt-3 text-xs text-muted">{t('ar.readonly')}</p>}
    </Card>
  )
}
