import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { JournalEvent, SecSettings, VPSList } from '../lib/types'
import { Card, Chip } from './ui'
import { EventLink } from './SecurityPanels'
import { Field, GhostButton, inputCls } from './Modal'

const CATEGORIES = ['fail2ban', 'sockets', 'firewall', 'ports', 'tls'] as const
const SEVERITIES = ['info', 'warning', 'critical'] as const

interface Page { items: JournalEvent[]; more: boolean }

// A datetime-local value is the viewer's local time; the API takes an instant.
const toISO = (v: string) => (v ? new Date(v).toISOString() : '')

function Params() {
  const { data } = useLoad((s) => api.get<SecSettings>('/api/v1/security/settings', s), [])
  if (!data) return null
  return (
    <Card title={t('sec.j.params')}>
      <p className="text-[13px] text-muted">{t('sec.j.paramsText', { agent: data.agent_interval_seconds, stale: data.stale_after_seconds, ports: data.port_check_minutes, tls: data.tls_check_hours, warn: data.tls_warn_days.join('/'), ret: data.retention_days })}</p>
      {!data.vantage.independent && <p role="note" className="mt-2 text-[13px] text-amber">{t('sec.ext.vantage')}</p>}
    </Card>
  )
}

/** Events of every server the viewer can see, with filters and a cursor, newest first. */
export function Journal() {
  const servers = useLoad((s) => api.get<VPSList>('/api/v1/security/vps', s), [])
  const [vps, setVps] = useState('')
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [q, setQ] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [debounced, setDebounced] = useState('')
  useEffect(() => {
    const id = window.setTimeout(() => setDebounced(q.trim()), 350)
    return () => window.clearTimeout(id)
  }, [q])

  const params = new URLSearchParams({ limit: '50' })
  if (vps) params.set('vps_id', vps)
  if (category) params.set('category', category)
  if (severity) params.set('severity', severity)
  if (debounced) params.set('q', debounced)
  if (from) params.set('from', toISO(from))
  if (to) params.set('to', toISO(to))
  const key = params.toString()

  const first = useLoad((s) => api.get<Page>(`/api/v1/security/events?${key}`, s), [key], 20_000)
  const [extra, setExtra] = useState<{ key: string; items: JournalEvent[]; more: boolean | null }>({ key: '', items: [], more: null })
  const [err, setErr] = useState('')
  // Pages added by "show more" belong to the filters they were loaded under.
  const added = extra.key === key ? extra : { key, items: [], more: null }
  const items = [...(first.data?.items ?? []), ...added.items]
  const hasMore = added.more ?? first.data?.more ?? false

  async function loadMore() {
    const last = items[items.length - 1]
    setErr('')
    try {
      const p = new URLSearchParams(params)
      p.set('before_ts', last.observed_at)
      p.set('before_id', last.id)
      const r = await api.get<Page>(`/api/v1/security/events?${p}`)
      setExtra({ key, items: [...added.items, ...r.items], more: r.more })
    } catch (e) {
      setErr(errorText(e))
    }
  }
  const reset = () => { setVps(''); setCategory(''); setSeverity(''); setQ(''); setFrom(''); setTo('') }

  return (
    <div className="space-y-4">
      <Card title={t('sec.j.title')}>
        <div className="flex flex-wrap items-end gap-3">
          <Field label={t('sec.j.server')} htmlFor="j-vps">
            <select id="j-vps" className={inputCls} value={vps} onChange={(e) => setVps(e.target.value)}>
              <option value="">{t('sec.j.allServers')}</option>
              {(servers.data?.items ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          </Field>
          <Field label={t('sec.j.category')} htmlFor="j-cat">
            <select id="j-cat" className={inputCls} value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">{t('sec.j.allCategories')}</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{t(`sec.cat.${c}` as MsgKey)}</option>)}
            </select>
          </Field>
          <Field label={t('sec.j.severity')} htmlFor="j-sev">
            <select id="j-sev" className={inputCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">{t('sec.j.allSeverities')}</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{t(`sec.sev.${s}` as MsgKey)}</option>)}
            </select>
          </Field>
          <Field label={t('sec.j.search')} htmlFor="j-q"><input id="j-q" className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} spellCheck={false} /></Field>
          <Field label={t('sec.j.from')} htmlFor="j-from"><input id="j-from" type="datetime-local" className={inputCls} value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
          <Field label={t('sec.j.to')} htmlFor="j-to"><input id="j-to" type="datetime-local" className={inputCls} value={to} onChange={(e) => setTo(e.target.value)} /></Field>
          <GhostButton onClick={reset}>×</GhostButton>
        </div>
      </Card>

      <Card>
        {first.error && <p role="alert" className="text-[13px] text-red">{first.error}</p>}
        {first.data && items.length === 0 && <p className="text-[13px] text-muted">{t('sec.j.none')}</p>}
        <ul className="divide-y divide-line">
          {items.map((e) => (
            <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-3 py-2 text-[13px]">
              <span>
                <Chip tone={e.severity === 'info' ? 'muted' : e.severity === 'warning' ? 'amber' : 'red'}>{t(`sec.sev.${e.severity}` as MsgKey)}</Chip>
                <Link to={`/security/${e.vps_id}`} className="ml-2 font-medium hover:text-cyan hover:underline">{e.vps_name}</Link>
                <EventLink e={e} className="ml-2" />
              </span>
              <span className="tnum text-xs text-muted">{formatDateTime(e.observed_at, 'local')} · {t(e.source === 'external_check' ? 'sec.ext.source' : 'sec.events.source')}</span>
            </li>
          ))}
        </ul>
        {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
        {hasMore && <div className="mt-3"><GhostButton onClick={() => void loadMore()}>{t('sec.events.more')}</GhostButton></div>}
      </Card>
      <Params />
    </div>
  )
}
