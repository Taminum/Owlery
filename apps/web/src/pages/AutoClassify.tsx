import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatInt, formatPct } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { AutoDryRun, AutoModels, AutoQueue, AutoStatus, RulesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { Field, GhostButton, PrimaryButton, inputCls } from '../components/Modal'

type Filter = 'all' | 'invalid' | 'low' | 'undetermined'

const ISSUE: Record<string, string> = {
  missing: 'ac.issue.missing', bad_json: 'ac.issue.badJson', bad_category: 'ac.issue.badCategory', bad_confidence: 'ac.issue.badConfidence',
  bad_item: 'ac.issue.badItem', bad_reply: 'ac.issue.badReply', rate_limited: 'ac.issue.rateLimited', upstream: 'ac.issue.upstream',
  network: 'ac.issue.network', auth: 'ac.issue.auth', no_key: 'ac.issue.noKey', bad_request: 'ac.issue.badRequest', not_processed: 'ac.issue.notProcessed',
}
const issueText = (code: string) => (ISSUE[code] ? t(ISSUE[code] as 'ac.issue.missing') : code)

function Settings({ status, reload }: { status: AutoStatus; reload: () => void }) {
  const models = useLoad((s) => api.get<AutoModels>('/api/v1/autoclassify/models', s), [status.key_present])
  const [model, setModel] = useState(status.settings.model)
  const [batch, setBatch] = useState(String(status.settings.batch_size))
  const [daily, setDaily] = useState(String(status.settings.daily_limit))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const list = models.data?.models ?? []
  const known = !model || list.some((m) => m.name === model)

  async function save() {
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      await api.put('/api/v1/autoclassify/settings', { model, batch_size: Number(batch), daily_limit: Number(daily) })
      setSaved(true)
      reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('ac.settings')}>
      <div className="mb-4 flex items-start gap-3 rounded-control border border-amber/40 bg-amber/10 px-3 py-2.5 text-[13px]">
        <ShieldAlert size={18} aria-hidden className="mt-0.5 shrink-0 text-amber" />
        <div>
          <p className="font-medium text-amber">{t('ac.privacyTitle')}</p>
          <p className="mt-1 text-fg/90">{t('ac.privacySends')}</p>
          <p className="mt-1 text-muted">{t('ac.privacyNever')}</p>
        </div>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-3 text-[13px]">
        <span className="text-muted">{t('ac.key')}:</span>
        {status.key_present ? <Chip tone="green">{t('ac.keyPresent')}</Chip> : <Chip tone="amber">{t('ac.keyMissing')}</Chip>}
        {!status.key_present && <span className="text-muted">{t('ac.keyHow')}</span>}
        {models.data?.error === 'auth' && <span role="alert" className="text-red">{t('ac.keyRefused')}</span>}
        {models.data?.error === 'rate_limited' && <span className="text-amber">{t('ac.modelsLimited')}</span>}
        {models.data?.error === 'unavailable' && <span className="text-amber">{t('ac.modelsUnavailable')}</span>}
      </div>
      <form className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" onSubmit={(e) => { e.preventDefault(); if (!busy) void save() }}>
        <Field label={t('ac.model')} htmlFor="ac-model" hint={t('ac.modelHint')}>
          <select id="ac-model" className={inputCls} value={model} onChange={(e) => setModel(e.target.value)}>
            <option value="">{t('ac.modelNone')}</option>
            {!known && <option value={model}>{model}</option>}
            {list.map((m) => <option key={m.name} value={m.name}>{m.name}{m.display_name ? ` · ${m.display_name}` : ''}</option>)}
          </select>
        </Field>
        <Field label={t('ac.batch')} hint={t('ac.batchHint')} htmlFor="ac-batch"><input id="ac-batch" className={inputCls} inputMode="numeric" value={batch} onChange={(e) => setBatch(e.target.value)} /></Field>
        <Field label={t('ac.daily')} hint={t('ac.dailyHint')} htmlFor="ac-daily"><input id="ac-daily" className={inputCls} inputMode="numeric" value={daily} onChange={(e) => setDaily(e.target.value)} /></Field>
        <div className="flex items-end gap-2">
          <PrimaryButton type="submit" disabled={busy}>{t('ac.save')}</PrimaryButton>
          <GhostButton onClick={() => models.reload()} title={t('ac.refreshModels')}>{t('ac.refreshModels')}</GhostButton>
        </div>
      </form>
      {error && <p role="alert" className="mt-3 text-[13px] text-red">{error}</p>}
      {saved && <p role="status" className="mt-3 text-[13px] text-green">{t('ac.saved')}</p>}
    </Card>
  )
}

const STATES = ['pending', 'running', 'retry', 'done', 'undetermined', 'failed', 'skipped'] as const

function Queue({ status, reload }: { status: AutoStatus; reload: () => void }) {
  const q: AutoQueue | undefined = status.queue
  const on = status.settings.enabled
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const ready = status.key_present && !!status.settings.model

  async function call(fn: () => Promise<unknown>) {
    setBusy(true)
    setError('')
    try {
      await fn()
      reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  const toggle = () => call(() => api.put('/api/v1/autoclassify/enabled', { enabled: !on, confirmed }))
  const backfill = () => call(() => api.post('/api/v1/autoclassify/backfill', {}))
  const waiting = (q?.counts.pending ?? 0) + (q?.counts.retry ?? 0)

  return (
    <Card title={t('ac.queue')} note={t('ac.queueNote')}
      right={<Chip tone={on ? 'green' : 'muted'}>{on ? t('ac.on') : t('ac.off')}</Chip>}>
      <div className="space-y-4 text-[13px]">
        {!on && (
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-0.5" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>{t('ac.confirm')}</span>
          </label>
        )}
        <div className="flex flex-wrap items-center gap-3">
          <PrimaryButton disabled={busy || (!on && (!confirmed || !ready))} onClick={() => void toggle()}>{on ? t('ac.turnOff') : t('ac.turnOn')}</PrimaryButton>
          {!on && !ready && <span className="text-muted">{t('ac.needModel')}</span>}
          {on && <span className="text-muted">{t('ac.turnOffNote')}</span>}
        </div>
        {q && (
          <>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div><dt className="text-xs text-muted">{t('ac.q.waiting')}</dt><dd className="tnum text-[22px] font-bold">{formatInt(waiting)}</dd></div>
              <div><dt className="text-xs text-muted">{t('ac.q.rules')}</dt><dd className="tnum text-[22px] font-bold text-green">{formatInt(q.auto_rules)}</dd></div>
              <div><dt className="text-xs text-muted">{t('ac.q.today')}</dt><dd className="tnum text-[22px] font-bold">{formatInt(q.spent_today)} / {formatInt(status.settings.daily_limit)}</dd></div>
              <div><dt className="text-xs text-muted">{t('ac.q.failed')}</dt><dd className={`tnum text-[22px] font-bold ${q.counts.failed ? 'text-red' : ''}`}>{formatInt(q.counts.failed ?? 0)}</dd></div>
            </dl>
            <ul className="flex flex-wrap gap-2 text-xs">
              {STATES.map((s) => <li key={s}><Chip tone="muted">{t(`ac.q.s.${s}` as 'ac.q.s.done')}: {formatInt(q.counts[s] ?? 0)}</Chip></li>)}
            </ul>
            <p className="text-muted">
              {q.last_success_at ? t('ac.q.lastOk', { when: new Date(q.last_success_at).toLocaleString('ru-RU') }) : t('ac.q.neverOk')}
              {q.last_error_code && <span className="ml-2 text-red">{t('ac.q.lastErr', { what: issueText(q.last_error_code) })}</span>}
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <GhostButton disabled={busy || !on || q.backfill === 'running'} onClick={() => void backfill()}>
                {q.backfill === 'running' ? t('ac.backfill.running') : t('ac.backfill.start')}
              </GhostButton>
              <span className="text-muted">{q.backfill === 'done' ? t('ac.backfill.done') : t('ac.backfill.note')}</span>
            </div>
          </>
        )}
        {error && <p role="alert" className="text-red">{error}</p>}
      </div>
    </Card>
  )
}

function RowFix({ site, current, cats }: { site: string; current: string; cats: string[] }) {
  const [cat, setCat] = useState(current)
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'err'>('idle')
  async function apply() {
    setState('busy')
    try {
      await api.post('/api/v1/rules', { pattern: site, category: cat.trim(), service: '' })
      setState('done')
    } catch {
      setState('err')
    }
  }
  return (
    <div className="flex items-center gap-1.5">
      <input list="ac-cats" value={cat} onChange={(e) => { setCat(e.target.value); setState('idle') }} aria-label={`${t('sites.category')}: ${site}`}
        className="h-8 w-40 rounded-control border border-line bg-transparent px-2 text-[13px]" />
      <datalist id="ac-cats">{cats.map((c) => <option key={c} value={c} />)}</datalist>
      <button type="button" disabled={state === 'busy' || !cat.trim() || state === 'done'} onClick={() => void apply()}
        className="h-8 rounded-control border border-line px-2.5 text-[13px] text-muted hover:text-fg disabled:opacity-50">
        {state === 'done' ? '✓' : state === 'err' ? '!' : 'Применить'}
      </button>
    </div>
  )
}

function DryRun({ status, reload }: { status: AutoStatus; reload: () => void }) {
  const running = status.running
  const { data, error, reload: reloadRun } = useLoad((s) => api.get<AutoDryRun>('/api/v1/autoclassify/dryrun', s), [status.latest_run?.id, running], running ? 3000 : 0)
  const [filter, setFilter] = useState<Filter>('all')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function start() {
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/v1/autoclassify/dryrun', {})
      reload()
      reloadRun()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  const { data: rulesData } = useLoad((sg) => api.get<RulesResponse>('/api/v1/rules', sg), [])
  const ruleCats = rulesData?.categories ?? []
  const items = (data?.items ?? []).filter((i) => {
    switch (filter) {
      case 'invalid': return !i.valid
      case 'low': return i.valid && !i.undetermined && i.confidence < 0.6
      case 'undetermined': return i.valid && i.undetermined
      default: return true
    }
  })
  const s = data?.summary
  const run = data?.run
  const cats = s ? Object.entries(s.by_category).sort((a, b) => b[1] - a[1]) : []
  const FILTERS: [Filter, string][] = [['all', 'ac.f.all'], ['invalid', 'ac.f.invalid'], ['low', 'ac.f.low'], ['undetermined', 'ac.f.undetermined']]

  return (
    <Card title={t('ac.dryrun')} note={t('ac.dryrunNote')}
      right={<PrimaryButton disabled={busy || running || !status.key_present || !status.settings.model} onClick={() => void start()}>{running ? t('ac.running') : t('ac.start')}</PrimaryButton>}>
      {!status.settings.model && <p className="mb-3 text-[13px] text-muted">{t('ac.needModel')}</p>}
      {(err || error) && <p role="alert" className="mb-3 text-[13px] text-red">{err || error}</p>}
      {!run && !running && <p className="py-6 text-center text-[13px] text-muted">{t('ac.noRun')}</p>}
      {run && s && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 text-[13px] text-muted">
            <Chip tone={run.state === 'done' ? 'green' : run.state === 'running' ? 'amber' : 'red'}>{t(`ac.state.${run.state}` as 'ac.state.done')}</Chip>
            <span className="tnum">{t('ac.model')}: {run.model}</span>
            <span className="tnum">{t('ac.requests')}: {formatInt(run.requests)}</span>
            <span className="tnum">{t('ac.tokens')}: {formatInt(run.tokens_in)} → {formatInt(run.tokens_out)}</span>
            {run.error_code && <span className="text-red">{issueText(run.error_code)}</span>}
          </div>
          <dl className="grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-5">
            <div><dt className="text-xs text-muted">{t('ac.sum.total')}</dt><dd className="tnum text-[22px] font-bold">{formatInt(s.total)}</dd></div>
            <div><dt className="text-xs text-muted">{t('ac.sum.valid')}</dt><dd className="tnum text-[22px] font-bold text-green">{s.total ? formatPct((s.valid / s.total) * 100) : '—'}</dd></div>
            <div><dt className="text-xs text-muted">{t('ac.sum.low')}</dt><dd className="tnum text-[22px] font-bold text-amber">{formatInt(s.low_confidence)}</dd></div>
            <div><dt className="text-xs text-muted">{t('ac.sum.undetermined')}</dt><dd className="tnum text-[22px] font-bold">{formatInt(s.undetermined)}</dd></div>
            <div><dt className="text-xs text-muted">{t('ac.sum.invalid')}</dt><dd className={`tnum text-[22px] font-bold ${s.invalid ? 'text-red' : ''}`}>{formatInt(s.invalid)}</dd></div>
          </dl>
          {cats.length > 0 && (
            <div>
              <h3 className="mb-1.5 text-[13px] font-medium">{t('ac.byCategory')}</h3>
              <ul className="flex flex-wrap gap-2 text-xs">{cats.map(([c, n]) => <li key={c}><Chip tone="muted">{c}: {n}</Chip></li>)}</ul>
            </div>
          )}
          <div role="group" aria-label={t('ac.filter')} className="flex flex-wrap gap-2">
            {FILTERS.map(([f, k]) => (
              <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}
                className={`h-8 rounded-control border px-3 text-[13px] ${filter === f ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(k as 'ac.f.all')}</button>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('ac.dryrun')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('sites.site')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('sites.category')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('rules.service')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('ac.confidence')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('ac.reason')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="px-2 py-2 font-medium">Изменить</th>
              </tr></thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.site} className="border-t border-line/60 align-top">
                    <td className="px-2 py-2 font-medium">{i.site}<div className="text-xs text-muted">{i.picked_by === 'top' ? t('ac.pickedTop') : t('ac.pickedRandom')}</div></td>
                    <td className="px-2 py-2">
                      {!i.valid ? <span className="text-red">{issueText(i.issue ?? '')}</span>
                        : i.undetermined ? <span className="text-muted">{t('ac.undetermined')}</span>
                        : <>{i.category}{i.confidence < 0.6 && <span className="ml-2 text-xs text-amber">{t('ac.guess')}</span>}</>}
                    </td>
                    <td className="px-2 py-2 text-muted">{i.service || '—'}</td>
                    <td className="tnum px-2 py-2 text-right">{i.valid ? `${Math.round(i.confidence * 100)}%` : '—'}</td>
                    <td className="max-w-[360px] px-2 py-2 text-muted">{i.reason}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatInt(i.connections)}</td>
                    <td className="px-2 py-2"><RowFix site={i.site} current={i.valid && !i.undetermined ? i.category ?? '' : ''} cats={ruleCats} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs leading-5 text-muted">{t('ac.confidenceNote')}</p>
        </div>
      )}
    </Card>
  )
}

export default function AutoClassify() {
  const { data, error, reload } = useLoad((s) => api.get<AutoStatus>('/api/v1/autoclassify', s), [], 5000)
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <p className="text-[13px] text-muted">{t('state.loading')}</p>
  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">{t('ac.intro')}</p>
      <Settings key={`${data.settings.model}|${data.settings.batch_size}|${data.settings.daily_limit}`} status={data} reload={reload} />
      <Queue status={data} reload={reload} />
      <DryRun status={data} reload={reload} />
    </div>
  )
}
