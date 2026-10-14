import { useEffect, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { ApiError, api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import type { PanelDTO, ProbeSummary, SyncRun } from '../lib/types'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'
import { ProbeChecks } from './ProbeChecks'

export function ProbeResultDialog({ panel, summary, onClose }: { panel: PanelDTO; summary: ProbeSummary; onClose: () => void }) {
  return (
    <Modal title={`${panel.name}: ${summary.required_ok ? t('panels.testOk') : t('panels.testFailed')}`} onClose={onClose}>
      <div className="space-y-4">
        <ProbeChecks checks={summary.checks} />
        {summary.api_version && <p className="text-[13px] text-muted">{t('panels.version')}: {summary.api_version} · {t('wizard.discovered', { n: summary.node_count })}</p>}
        <div className="flex justify-end"><PrimaryButton onClick={onClose} data-autofocus>{t('common.close')}</PrimaryButton></div>
      </div>
    </Modal>
  )
}

export function RotateDialog({ panel, onClose, onDone }: { panel: PanelDTO; onClose: () => void; onDone: () => void }) {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [failed, setFailed] = useState<ProbeSummary | null>(null)
  const valid = token.length > 0 && token.length <= 2048 && !/\s/.test(token)

  async function submit() {
    setBusy(true)
    setError('')
    setFailed(null)
    try {
      await api.put(`/api/v1/panels/${panel.id}/token`, { api_token: token })
      setToken('')
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      if (e instanceof ApiError && e.code === 'probe_failed') setFailed(e.details as ProbeSummary)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={`${t('rotate.title')}: ${panel.name}`} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void submit() }}>
        <p className="text-[13px] text-muted">{t('rotate.text')}</p>
        <Field label={t('wizard.token')} hint={t('wizard.tokenHint')} htmlFor="r-token">
          <input id="r-token" className={inputCls} type="password" name="remnascope-new-api-token" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} data-autofocus />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        {failed && <ProbeChecks checks={failed.checks} />}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{busy ? t('wizard.testing') : t('rotate.submit')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export function DeleteDialog({ panel, onClose, onDone }: { panel: PanelDTO; onClose: () => void; onDone: () => void }) {
  const [confirm, setConfirm] = useState('')
  const [retention, setRetention] = useState<'' | 'purge' | 'archive'>('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const ok = confirm === panel.name && retention !== ''

  async function submit() {
    setBusy(true)
    setError('')
    try {
      await api.del(`/api/v1/panels/${panel.id}`, { confirm, retention })
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }

  return (
    <Modal title={t('delete.title', { name: panel.name })} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (ok && !busy) void submit() }}>
        <p className="text-[13px] text-amber">{t('delete.warn')}</p>
        <fieldset className="space-y-2.5">
          <legend className="mb-1 text-[13px] font-medium">{t('delete.retention')}</legend>
          {(['purge', 'archive'] as const).map((v) => (
            <label key={v} className="flex cursor-pointer items-start gap-2.5 text-[13px]">
              <input type="radio" name="retention" className="mt-0.5 accent-cyan" checked={retention === v} onChange={() => setRetention(v)} />
              <span>{t(`delete.${v}` as MsgKey)}</span>
            </label>
          ))}
        </fieldset>
        <Field label={t('delete.confirmLabel')} htmlFor="d-confirm">
          <input id="d-confirm" className={inputCls} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" spellCheck={false} placeholder={panel.name} />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <DangerButton type="submit" disabled={!ok || busy}>{t('delete.submit')}</DangerButton>
        </div>
      </form>
    </Modal>
  )
}

export function SettingsDialog({ panel, customCAAvailable, onClose, onDone }: { panel: PanelDTO; customCAAvailable: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(panel.name)
  const [interval, setInterval_] = useState(panel.sync_interval_seconds)
  const [retention, setRetention] = useState(panel.retention_days)
  const [users, setUsers] = useState(panel.sync_options.users)
  const [stats, setStats] = useState(panel.sync_options.stats)
  const [ca, setCa] = useState(panel.use_custom_ca)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit() {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/panels/${panel.id}`, {
        name: name.trim(), sync_interval_seconds: interval, retention_days: retention,
        sync_options: { nodes: true, users, stats }, use_custom_ca: ca,
      })
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }

  const intervals = Array.from(new Set([60, 300, 900, 3600, interval])).sort((a, b) => a - b)
  return (
    <Modal title={`${t('settingsDlg.title')}: ${panel.name}`} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && name.trim()) void submit() }}>
        <Field label={t('wizard.name')} htmlFor="s-name"><input id="s-name" className={inputCls} value={name} maxLength={64} onChange={(e) => setName(e.target.value)} data-autofocus /></Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t('wizard.interval')} htmlFor="s-interval">
            <select id="s-interval" className={inputCls} value={interval} onChange={(e) => setInterval_(Number(e.target.value))}>
              {intervals.map((i) => <option key={i} value={i}>{[60, 300, 900, 3600].includes(i) ? t(`wizard.interval.${i}` as MsgKey) : `${i} с`}</option>)}
            </select>
          </Field>
          <Field label={t('wizard.retention')} htmlFor="s-ret">
            <input id="s-ret" className={inputCls} type="number" min={1} max={3650} value={retention} onChange={(e) => setRetention(Math.max(1, Math.min(3650, Number(e.target.value) || 1)))} />
          </Field>
        </div>
        <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked disabled /> {t('wizard.collect.nodes')}</label>
        <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked={users} onChange={(e) => setUsers(e.target.checked)} /> {t('wizard.collect.users')}</label>
        <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked={stats} onChange={(e) => setStats(e.target.checked)} /> {t('wizard.collect.stats')}</label>
        {customCAAvailable && <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked={ca} onChange={(e) => setCa(e.target.checked)} /> {t('wizard.customCA')}</label>}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !name.trim()}>{t('common.save')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export function RunsDialog({ panel, tz, onClose }: { panel: PanelDTO; tz: string; onClose: () => void }) {
  const [runs, setRuns] = useState<SyncRun[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const ac = new AbortController()
    api.get<{ runs: SyncRun[] }>(`/api/v1/panels/${panel.id}/sync-runs`, ac.signal)
      .then((r) => setRuns(r.runs))
      .catch((e) => { if ((e as Error).name !== 'AbortError') setError(errorText(e)) })
    return () => ac.abort()
  }, [panel.id])

  return (
    <Modal title={`${t('panels.runs.title')}: ${panel.name}`} onClose={onClose} wide>
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!runs && !error && <p className="text-[13px] text-muted">{t('common.loading')}</p>}
      {runs && runs.length === 0 && <p className="text-[13px] text-muted">{t('panels.runs.empty')}</p>}
      {runs && runs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <caption className="sr-only">{t('panels.runs.title')}</caption>
            <thead><tr className="text-left text-xs text-muted">
              <th scope="col" className="py-2 pr-3 font-medium">{t('panels.runs.when')}</th>
              <th scope="col" className="py-2 pr-3 font-medium">{t('panels.runs.op')}</th>
              <th scope="col" className="py-2 pr-3 font-medium">{t('panels.runs.trigger')}</th>
              <th scope="col" className="py-2 pr-3 font-medium">{t('panels.runs.status')}</th>
              <th scope="col" className="py-2 font-medium">{t('panels.runs.result')}</th>
            </tr></thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id} className="border-t border-line/60">
                  <td className="tnum py-2 pr-3 text-muted">{formatDateTime(r.started_at, tz)}</td>
                  <td className="py-2 pr-3">{t(`panels.runs.${r.operation}` as MsgKey)}</td>
                  <td className="py-2 pr-3 text-muted">{t(`panels.runs.${r.trigger}` as MsgKey)}</td>
                  <td className="py-2 pr-3">{t(`panels.sync.${r.status}` as MsgKey) === 'undefined' ? r.status : t(`panels.sync.${r.status}` as MsgKey)}</td>
                  <td className="tnum py-2 text-muted">
                    {r.error_code ? errorText(new ApiError(0, r.error_code, '')) : `+${r.stats.added ?? 0} ~${r.stats.updated ?? 0} −${r.stats.removed ?? 0}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-4 flex justify-end"><PrimaryButton onClick={onClose} data-autofocus>{t('common.close')}</PrimaryButton></div>
    </Modal>
  )
}
