import { useCallback, useRef, useState } from 'react'
import { CircleCheck, Loader2 } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { ApiError, api } from '../lib/api'
import { errorText } from '../lib/errors'
import type { PanelDTO, ProbeSummary, SyncOptions } from '../lib/types'
import { Chip } from './ui'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'
import { ProbeChecks } from './ProbeChecks'

const STEPS: MsgKey[] = ['wizard.step.connection', 'wizard.step.collection', 'wizard.step.test', 'wizard.step.review']
const INTERVALS = [60, 300, 900, 3600] as const

interface Form {
  name: string
  url: string
  token: string
  customCA: boolean
  options: SyncOptions
  interval: number
  retention: number
}

const initial: Form = { name: '', url: '', token: '', customCA: false, options: { nodes: true, users: true, stats: false }, interval: 300, retention: 30 }

const hasSpace = (s: string) => /\s/.test(s)
const nameOK = (s: string) => s.trim().length >= 1 && s.trim().length <= 64
const urlOK = (s: string) => /^https:\/\/[^\s/?#]+(\/[^\s?#]*)?$/i.test(s.trim())
const tokenOK = (s: string) => s.length > 0 && s.length <= 2048 && !hasSpace(s)

type Probe = { phase: 'idle' | 'running' | 'done' | 'failed'; summary?: ProbeSummary; error?: string }

export function gapsFor(o: SyncOptions, s: ProbeSummary): string[] {
  const gaps: string[] = []
  if (o.users && !s.capabilities.users) gaps.push('users')
  if (o.stats && !(s.capabilities.system_stats && s.capabilities.bandwidth_stats)) gaps.push('stats')
  return gaps
}

export function Wizard({ customCAAvailable, onClose, onSaved }: { customCAAvailable: boolean; onClose: () => void; onSaved: () => void }) {
  const [step, setStep] = useState(0)
  const [f, setF] = useState<Form>(initial)
  const [touched, setTouched] = useState(false)
  const [probe, setProbe] = useState<Probe>({ phase: 'idle' })
  const [allowPartial, setAllowPartial] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [saved, setSaved] = useState<PanelDTO | null>(null)
  const runId = useRef(0)

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => ({ ...p, [k]: v }))

  const run = useCallback(async (form: Form) => {
    const id = ++runId.current
    setProbe({ phase: 'running' })
    try {
      const summary = await api.post<ProbeSummary>('/api/v1/panels/probe', { base_url: form.url.trim(), api_token: form.token, use_custom_ca: form.customCA })
      if (id === runId.current) setProbe({ phase: 'done', summary })
    } catch (e) {
      if (id === runId.current) setProbe({ phase: 'failed', error: errorText(e) })
    }
  }, [])

  const step0Valid = nameOK(f.name) && urlOK(f.url) && tokenOK(f.token)
  const summary = probe.phase === 'done' ? probe.summary : undefined
  const gaps = summary ? gapsFor(f.options, summary) : []
  const canSave = !!summary?.required_ok && (gaps.length === 0 || allowPartial)

  function next() {
    if (step === 0) {
      setTouched(true)
      if (!step0Valid) return
    }
    setStep((s) => s + 1)
    if (step === 1) void run(f) // entering the test step starts the server-side test; nothing is saved by it
  }

  function back() {
    runId.current++ // ignore a probe still in flight
    setStep((s) => Math.max(0, s - 1))
  }

  async function save() {
    setSaving(true)
    setSaveError('')
    try {
      const out = await api.post<{ panel: PanelDTO }>('/api/v1/panels', {
        name: f.name.trim(), base_url: f.url.trim(), api_token: f.token, use_custom_ca: f.customCA,
        sync_options: f.options, sync_interval_seconds: f.interval, retention_days: f.retention, allow_partial: allowPartial,
      })
      setF((p) => ({ ...p, token: '' })) // the token leaves memory as soon as it is saved
      setSaved(out.panel)
      onSaved()
    } catch (e) {
      if (e instanceof ApiError && e.code === 'partial_capabilities') setAllowPartial(false)
      setSaveError(errorText(e))
    } finally {
      setSaving(false)
    }
  }

  function close() {
    runId.current++
    onClose()
  }

  if (saved) {
    return (
      <Modal title={t('wizard.done')} onClose={close}>
        <div className="space-y-4">
          <p className="flex items-start gap-2.5 text-[14px]"><CircleCheck size={20} className="mt-0.5 shrink-0 text-green" aria-hidden /><span><strong className="font-semibold">{saved.name}</strong>. {t('wizard.discovered', { n: saved.node_count || summary?.node_count || 0 })}</span></p>
          <p className="text-[13px] text-muted">{t('wizard.doneText')}</p>
          <div className="flex justify-end"><PrimaryButton onClick={close} data-autofocus>{t('wizard.close')}</PrimaryButton></div>
        </div>
      </Modal>
    )
  }

  return (
    <Modal title={t('wizard.title')} onClose={close} wide busy={saving}>
      <ol className="mb-5 flex flex-wrap gap-x-5 gap-y-2 text-[13px]" aria-label={t('wizard.title')}>
        {STEPS.map((k, i) => (
          <li key={k} aria-current={i === step ? 'step' : undefined} className={`flex items-center gap-2 ${i === step ? 'font-medium text-fg' : 'text-muted'}`}>
            <span className={`grid h-6 w-6 place-items-center rounded-full border text-xs ${i === step ? 'border-cyan text-cyan' : i < step ? 'border-green text-green' : 'border-line'}`}>{i < step ? '✓' : i + 1}</span>
            {t(k)}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <div className="space-y-4">
          <Field label={t('wizard.name')} hint={t('wizard.nameHint')} error={touched && !nameOK(f.name) ? t('wizard.invalidName') : undefined} htmlFor="w-name">
            <input id="w-name" className={inputCls} value={f.name} maxLength={64} onChange={(e) => set('name', e.target.value)} data-autofocus />
          </Field>
          <Field label={t('wizard.url')} hint={t('wizard.urlHint')} error={touched && !urlOK(f.url) ? t('wizard.invalidUrl') : undefined} htmlFor="w-url">
            <input id="w-url" className={inputCls} value={f.url} placeholder="https://panel.example.com" inputMode="url" autoCapitalize="none" spellCheck={false} onChange={(e) => set('url', e.target.value)} />
          </Field>
          <Field label={t('wizard.token')} hint={t('wizard.tokenHint')} error={touched && !tokenOK(f.token) ? t('wizard.invalidToken') : undefined} htmlFor="w-token">
            <input id="w-token" className={inputCls} type="password" name="remnascope-panel-api-token" autoComplete="off" spellCheck={false} value={f.token} onChange={(e) => set('token', e.target.value)} />
          </Field>
          {customCAAvailable && (
            <label className="flex cursor-pointer items-start gap-2.5 text-[13px]">
              <input type="checkbox" className="mt-0.5 accent-cyan" checked={f.customCA} onChange={(e) => set('customCA', e.target.checked)} />
              <span><span className="text-fg">{t('wizard.customCA')}</span><span className="mt-0.5 block text-xs text-muted">{t('wizard.customCAHint')}</span></span>
            </label>
          )}
        </div>
      )}

      {step === 1 && (
        <div className="space-y-4">
          <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked disabled /> {t('wizard.collect.nodes')}</label>
          <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked={f.options.users} onChange={(e) => set('options', { ...f.options, users: e.target.checked })} /> {t('wizard.collect.users')}</label>
          <label className="flex items-center gap-2.5 text-[14px]"><input type="checkbox" className="accent-cyan" checked={f.options.stats} onChange={(e) => set('options', { ...f.options, stats: e.target.checked })} /> {t('wizard.collect.stats')}</label>
          <label className="flex items-center gap-2.5 text-[14px] text-muted"><input type="checkbox" className="accent-cyan" disabled /> {t('wizard.collect.agents')} <Chip>{t('wizard.collect.soon')}</Chip></label>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('wizard.interval')} htmlFor="w-interval">
              <select id="w-interval" className={inputCls} value={f.interval} onChange={(e) => set('interval', Number(e.target.value))}>
                {INTERVALS.map((i) => <option key={i} value={i}>{t(`wizard.interval.${i}` as MsgKey)}</option>)}
              </select>
            </Field>
            <Field label={t('wizard.retention')} htmlFor="w-retention">
              <input id="w-retention" className={inputCls} type="number" min={1} max={3650} value={f.retention} onChange={(e) => set('retention', Math.max(1, Math.min(3650, Number(e.target.value) || 1)))} />
            </Field>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-4" aria-live="polite">
          {probe.phase === 'running' && <p className="flex items-center gap-2 text-[14px] text-muted"><Loader2 size={18} className="animate-spin" aria-hidden /> {t('wizard.testing')}</p>}
          {probe.phase === 'failed' && <p role="alert" className="text-[14px] text-red">{probe.error}</p>}
          {summary && (
            <>
              <ProbeChecks checks={summary.checks} />
              {summary.required_ok
                ? <p className="text-[13px] text-green">{t('wizard.testDone')} · {t('wizard.discovered', { n: summary.node_count })}{summary.api_version ? ` · ${summary.api_version}` : ''}</p>
                : <p role="alert" className="text-[13px] text-red">{t('wizard.blocked')}</p>}
            </>
          )}
          {probe.phase !== 'running' && <GhostButton onClick={() => void run(f)}>{t('wizard.retest')}</GhostButton>}
        </div>
      )}

      {step === 3 && summary && (
        <div className="space-y-4">
          <dl className="grid gap-x-4 gap-y-2 text-[13px] sm:grid-cols-[140px_1fr]">
            <dt className="text-muted">{t('wizard.name')}</dt><dd className="text-fg">{f.name.trim()}</dd>
            <dt className="text-muted">{t('wizard.url')}</dt><dd className="break-all text-fg">{f.url.trim()}</dd>
            <dt className="text-muted">{t('panels.nodes')}</dt>
            <dd className="text-fg">{summary.node_count}{summary.nodes_preview?.length ? `: ${summary.nodes_preview.join(', ')}` : ''}</dd>
            <dt className="text-muted">{t('wizard.interval')}</dt><dd className="text-fg">{t(`wizard.interval.${f.interval}` as MsgKey)}</dd>
            <dt className="text-muted">{t('wizard.retention')}</dt><dd className="text-fg">{f.retention}</dd>
          </dl>
          {gaps.length > 0 && (
            <div role="group" className="space-y-2 rounded-control border border-amber/40 bg-amber/10 p-3">
              <p className="text-[13px] font-medium text-amber">{t('wizard.partialTitle')}</p>
              <p className="text-[13px] text-fg">{t('wizard.partialText', { list: gaps.map((g) => (g === 'users' ? t('panels.cap.users') : t('panels.cap.bandwidth_stats'))).join(', ') })}</p>
              <label className="flex items-center gap-2.5 text-[13px]"><input type="checkbox" className="accent-cyan" checked={allowPartial} onChange={(e) => setAllowPartial(e.target.checked)} /> {t('wizard.partialConfirm')}</label>
            </div>
          )}
          {saveError && <p role="alert" className="text-[13px] text-red">{saveError}</p>}
        </div>
      )}

      <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
        <GhostButton onClick={close} disabled={saving}>{t('wizard.cancel')}</GhostButton>
        <div className="flex gap-3">
          {step > 0 && <GhostButton onClick={back} disabled={saving}>{t('wizard.back')}</GhostButton>}
          {step < 3 && <PrimaryButton onClick={next} disabled={(step === 2 && !summary?.required_ok) || (step === 2 && probe.phase === 'running')}>{t('wizard.next')}</PrimaryButton>}
          {step === 3 && <PrimaryButton onClick={() => void save()} disabled={!canSave || saving}>{saving ? t('wizard.saving') : t('wizard.save')}</PrimaryButton>}
        </div>
      </div>
    </Modal>
  )
}

