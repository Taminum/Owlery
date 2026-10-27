import { Link } from 'react-router-dom'
import { useEffect, useMemo, useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { t } from '../i18n'
import { C } from '../lib/colors'
import { useLook } from '../lib/chartLook'
import { useApp } from '../lib/context'
import { formatAxisTime, formatBytes, formatDateTime, formatInt, tzOffsetMinutes } from '../lib/format'
import { useAnalytics } from '../hooks/useAnalytics'
import { hasAwg } from '../components/SourceMarks'
import type { ActivityResponse, RulesResponse, SiteDetailResponse, SitesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { CoverageLine, NoDataPanel, PageHead, ShareBar, TableSkeleton } from '../components/Analyzer'
import { controlCls } from '../components/Popover'
import { Drawer } from '../components/Drawer'
import { SubjectSelect } from '../components/SubjectSelect'
import { Heatmap } from '../components/Heatmap'
import { CountriesCard } from '../components/Countries'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'

const PAGE = 50

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

const bytesText = (b: number | null) => (b == null ? '—' : formatBytes(b))

function Detail({ site, subject }: { site: string; subject: string }) {
  const look = useLook()
  const { filters } = useApp()
  const tz = filters.tz
  const { data, error } = useAnalytics<SiteDetailResponse>('sites/detail', filters, { site, subject })
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.meta.state === 'no_data') return <NoDataPanel meta={data.meta} />
  const hostMax = Math.max(0, ...data.hosts.map((h) => h.share))
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 className="text-lg font-semibold">{data.site}</h3>
        {data.service && <Chip tone="cyan">{data.service}</Chip>}
        <span className="text-[13px] text-muted">{data.category}</span>
        {data.auto && <span className="basis-full text-xs text-muted">{t('origin.detail', { model: data.auto.model, pct: Math.round(data.auto.score * 100), when: data.auto.classified_at ? new Date(data.auto.classified_at).toLocaleDateString('ru-RU') : '—' })}{data.auto.reason ? ` · ${data.auto.reason}` : ''}</span>}
        <span className="tnum text-[13px] text-muted">{t('sites.visitsN', { n: formatInt(data.visits) })} · {t('sites.connN', { n: formatInt(data.connections) })} · {t('sites.whoN', { n: data.users })}</span>
      </div>
      <div className="h-[150px]" role="img" aria-label={t('an.users.timeline')}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data.timeline} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={C.line} strokeOpacity={0.5} vertical={false} />
            <XAxis dataKey="ts" type="number" domain={['dataMin', 'dataMax']} scale="time" stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} tickCount={6} tickFormatter={(v: number) => formatAxisTime(v, tz, data.meta.granularity_seconds)} />
            <YAxis stroke={C.muted} fontSize={11} tickLine={false} axisLine={false} width={38} tickFormatter={(v: number) => formatInt(v)} />
            <Tooltip contentStyle={{ background: C.elevated, border: `1px solid ${C.line}`, borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => formatDateTime(Number(v), tz)} />
            <Area {...look(data.timeline.length)} dataKey="connections" name={t('an.connections')} stroke={C.blue} fill={C.blue} fillOpacity={0.25} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <div>
          <h3 className="mb-2 text-[13px] font-medium">{t('sites.who')}</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('sites.who')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('an.users.user')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('sites.visits')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.bytes')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('an.lastSeen')}</th>
              </tr></thead>
              <tbody>
                {data.who.map((w) => (
                  <tr key={`${w.kind}|${w.subject}|${w.label}`} className="border-t border-line/60">
                    <td className="px-2 py-2"><span className="font-medium">{w.label}</span>{w.note ? <span className="ml-2 text-xs text-muted">{w.note}</span> : null}<div className="text-xs text-muted">{w.kind === 'awg' ? t('src.awg') : w.kind === 'device' ? t('sites.kind.device') : w.panel_name}</div></td>
                    <td className="tnum px-2 py-2 text-right">{formatInt(w.visits)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatInt(w.connections)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{bytesText(w.bytes)}</td>
                    <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatDateTime(w.last_seen, tz)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div>
          <h3 className="mb-2 text-[13px] font-medium">{t('sites.hosts')}</h3>
          <table className="w-full border-collapse text-[13px]">
            <caption className="sr-only">{t('sites.hosts')}</caption>
            <thead><tr className="text-left text-xs text-muted">
              <th scope="col" className="px-2 py-2 font-medium">{t('an.dest')}</th>
              <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
              <th scope="col" className="w-[130px] px-2 py-2 font-medium">{t('an.share')}</th>
              <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.bytes')}</th>
            </tr></thead>
            <tbody>
              {data.hosts.map((h) => (
                <tr key={h.host} className="border-t border-line/60">
                  <td className="max-w-[260px] truncate px-2 py-2 font-medium" title={h.host}>{h.host}</td>
                  <td className="tnum px-2 py-2 text-right">{formatInt(h.connections)}</td>
                  <td className="px-2 py-2"><ShareBar share={h.share} max={hostMax} /></td>
                  <td className="tnum px-2 py-2 text-right text-muted">{bytesText(h.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/** Weekday x hour: when the selected person or device is active. */
function ActivityView({ subject }: { subject: string }) {
  const { filters } = useApp()
  const off = useMemo(() => String(tzOffsetMinutes(filters.tz)), [filters.tz])
  const { data, error } = useAnalytics<ActivityResponse>('activity', filters, { subject, tz_offset: off })
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.meta.state === 'no_data') return <NoDataPanel meta={data.meta} />
  return (
    <Card title={t('act.title')} note={t('act.note')}>
      <Heatmap grid={data.grid} max={data.max} />
      <p className="tnum mt-3 text-xs text-muted">{t('act.total', { n: formatInt(data.total) })} · {t('act.busiest', { n: formatInt(data.max) })}</p>
    </Card>
  )
}

/** Give a site a category (and a name) by hand; it overrides the built-in rule for that domain. */
function RuleDialog({ site, onClose, onDone }: { site: string; onClose: () => void; onDone: () => void }) {
  const { data } = useLoad((s) => api.get<RulesResponse>('/api/v1/rules', s), [])
  const [category, setCategory] = useState('')
  const [service, setService] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function save() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/rules', { pattern: site, category: category.trim(), service: service.trim() })
      onDone()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={`${t('sites.ruleTitle')}: ${site}`} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && category.trim()) void save() }}>
        <p className="text-[13px] text-muted">{t('sites.ruleHint')}</p>
        <Field label={t('sites.category')} htmlFor="rule-cat">
          <input id="rule-cat" className={inputCls} list="rule-cats" value={category} onChange={(e) => setCategory(e.target.value)} maxLength={64} autoComplete="off" data-autofocus />
          <datalist id="rule-cats">{(data?.categories ?? []).map((c) => <option key={c} value={c} />)}</datalist>
        </Field>
        <Field label={t('sites.serviceName')} hint={t('sites.serviceHint')} htmlFor="rule-svc">
          <input id="rule-svc" className={inputCls} value={service} onChange={(e) => setService(e.target.value)} maxLength={64} autoComplete="off" />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !category.trim()}>{t('sites.ruleSave')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

export default function Sites() {
  const { filters } = useApp()
  const { state: auth } = useAuth()
  const isOwner = auth.status === 'authed' && auth.me.account.is_owner
  const [view, setView] = useState<'sites' | 'categories' | 'activity' | 'countries'>('sites')
  const [newOnly, setNewOnly] = useState(false)
  const [ruleFor, setRuleFor] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [subject, setSubject] = useState('')
  const [category, setCategory] = useState('')
  const [zone, setZone] = useState<'' | 'ru' | 'other'>('')
  const [offset, setOffset] = useState(0)
  const [sort, setSort] = useState('connections')
  const [dir, setDir] = useState<'asc' | 'desc'>('desc')
  const sortBy = (key: string) => {
    if (key === sort) setDir(dir === 'desc' ? 'asc' : 'desc')
    else { setSort(key); setDir(key === 'site' || key === 'category' ? 'asc' : 'desc') }
    setOffset(0)
  }
  const sortTh = (k: string, label: string, right?: boolean, title?: string) => (
    <th key={k} scope="col" aria-sort={sort === k ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'} className={`px-2 py-2 font-medium ${right ? 'text-right' : ''}`} title={title}>
      <button type="button" onClick={() => sortBy(k)} className="font-medium hover:text-fg">{label}{sort === k ? (dir === 'asc' ? ' ▲' : ' ▼') : ''}</button>
    </th>
  )
  const [sel, setSel] = useState<string | null>(null)
  const q = useDebounced(search.trim(), 300)
  const { data, error, reload } = useAnalytics<SitesResponse>('sites', filters, { q, subject, category, zone, ...(newOnly ? { new: '1' } : {}), sort, dir, limit: String(PAGE), offset: String(offset) })
  const tz = filters.tz
  const max = data ? Math.max(0, ...data.rows.map((r) => r.share)) : 0
  const catMax = data ? Math.max(0, ...data.categories.map((c) => c.share)) : 0

  return (
    <div className="space-y-4">
      <PageHead title={t('sites.title')} subtitle={t('sites.subtitle')} />
      <div className="flex flex-wrap items-center gap-3">
        <div role="group" aria-label={t('sites.title')} className="flex h-10 items-center rounded-control border border-line bg-surface p-0.5">
          {(['sites', 'categories', 'activity', 'countries'] as const).map((v) => (
            <button key={v} type="button" aria-pressed={view === v} onClick={() => setView(v)}
              className={`h-8 rounded-[8px] px-3 text-[13px] ${view === v ? 'bg-elevated font-medium text-fg shadow-[inset_0_0_0_1px_var(--color-cyan)]' : 'text-muted hover:text-fg'}`}>{t(v === 'sites' ? 'sites.tab.sites' : v === 'categories' ? 'sites.tab.categories' : v === 'activity' ? 'sites.tab.activity' : 'sites.tab.countries')}</button>
          ))}
        </div>
        <SubjectSelect value={subject} onChange={(v) => { setSubject(v); setOffset(0); setSel(null) }} />
        <label className="sr-only" htmlFor="site-search">{t('sites.search')}</label>
        <input id="site-search" type="search" value={search} maxLength={100} onChange={(e) => { setSearch(e.target.value); setOffset(0) }} placeholder={t('sites.search')} autoComplete="off" spellCheck={false}
          className={`${controlCls} min-w-[220px] flex-1 sm:max-w-sm`} />
        <div role="group" aria-label={t('sites.zone')} className="flex h-10 items-center rounded-control border border-line bg-surface p-0.5">
          {([['', 'sites.zone.all'], ['ru', 'sites.zone.ru'], ['other', 'sites.zone.other']] as const).map(([v, k]) => (
            <button key={v} type="button" aria-pressed={zone === v} onClick={() => { setZone(v); setOffset(0) }}
              className={`h-8 rounded-[8px] px-3 text-[13px] ${zone === v ? 'bg-elevated font-medium text-fg shadow-[inset_0_0_0_1px_var(--color-cyan)]' : 'text-muted hover:text-fg'}`}>{t(k)}</button>
          ))}
        </div>
        <button type="button" aria-pressed={newOnly} onClick={() => { setNewOnly((v) => !v); setOffset(0) }}
          className={`${controlCls} ${newOnly ? 'border-cyan text-fg' : 'text-muted'}`} title={t('sites.newHint')}>{t('sites.newOnly')}</button>
        {category && (
          <button type="button" onClick={() => { setCategory(''); setOffset(0) }} className={`${controlCls} inline-flex items-center gap-2`} aria-label={t('sites.clearCategory')}>
            {category} <span aria-hidden>×</span>
          </button>
        )}
      </div>
      {data && <CoverageLine meta={data.meta} tz={tz} />}
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data?.meta.state === 'no_data' && <NoDataPanel meta={data.meta} />}
      {view === 'activity' && <ActivityView subject={subject} />}
      {view === 'countries' && <CountriesCard subject={subject} limit={40} />}
      {data && data.meta.state === 'ok' && view === 'categories' && (
        <Card title={t('sites.tab.categories')} note={t('sites.catNote')}>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <caption className="sr-only">{t('sites.tab.categories')}</caption>
              <thead><tr className="text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">{t('sites.category')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('sites.sites')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('sites.visits')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.connections')}</th>
                <th scope="col" className="w-[150px] px-2 py-2 font-medium">{t('an.share')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.users')}</th>
                <th scope="col" className="px-2 py-2 text-right font-medium">{t('an.bytes')}</th>
              </tr></thead>
              <tbody>
                {data.categories.map((c) => (
                  <tr key={c.category} className="border-t border-line/60">
                    <td className="px-2 py-2">
                      <button type="button" onClick={() => { setCategory(c.category); setView('sites'); setOffset(0) }} className={`font-medium underline-offset-2 hover:text-cyan hover:underline ${c.classified ? 'text-fg' : 'text-muted'}`}>{c.category}</button>
                    </td>
                    <td className="tnum px-2 py-2 text-right">{formatInt(c.sites)}</td>
                    <td className="tnum px-2 py-2 text-right">{formatInt(c.visits)}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{formatInt(c.connections)}</td>
                    <td className="px-2 py-2"><ShareBar share={c.share} max={catMax} /></td>
                    <td className="tnum px-2 py-2 text-right text-muted">{c.users}</td>
                    <td className="tnum px-2 py-2 text-right text-muted">{bytesText(c.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {data && data.meta.state === 'ok' && view === 'sites' && (
        <Card title={`${t('an.total', { n: formatInt(data.total_connections) })} · ${t('an.groups', { n: formatInt(data.groups) })}`} note={t('sites.note')}>
          {data.rows.length === 0 ? <p className="py-6 text-center text-[13px] text-muted">{t('an.noMatch')}</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <caption className="sr-only">{t('sites.title')}</caption>
                <thead><tr className="text-left text-xs text-muted">
                  {sortTh('site', t('sites.site'))}
                  {sortTh('category', t('sites.category'))}
                  {sortTh('visits', t('sites.visits'), true, t('sites.visitsHint'))}
                  {sortTh('connections', t('an.connections'), true)}
                  <th scope="col" className="w-[130px] px-2 py-2 font-medium">{t('an.share')}</th>
                  {sortTh('users', t('an.users'), true)}
                  {sortTh('devices', t('sites.devices'), true)}
                  {sortTh('hosts', t('sites.subs'), true)}
                  {sortTh('bytes', t('an.bytes'), true, t('an.bytesHint'))}
                  {sortTh('blocked', t('sites.blocked'), true, t('sites.blockedHint'))}
                  {sortTh('warp', t('sites.warp'), true, t('sites.warpHint'))}
                  {sortTh('last', t('an.lastSeen'))}
                  {isOwner && <th scope="col" className="px-2 py-2"><span className="sr-only">{t('sites.setCategory')}</span></th>}
                </tr></thead>
                <tbody>
                  {data.rows.map((r) => (
                    <tr key={r.site} className={`border-t border-line/60 ${sel === r.site ? 'bg-elevated' : ''}`}>
                      <td className="max-w-[260px] px-2 py-2">
                        <button type="button" aria-pressed={sel === r.site} onClick={() => setSel(sel === r.site ? null : r.site)} className="max-w-full truncate text-left font-medium text-fg underline-offset-2 hover:text-cyan hover:underline" title={r.site}>{r.site}</button>
                        {r.service && <div className="text-xs text-cyan">{r.service}</div>}
                      </td>
                      <td className={`px-2 py-2 text-xs ${r.classified ? 'text-fg' : 'text-muted'}`}>{r.category}</td>
                      <td className="tnum px-2 py-2 text-right text-fg">{formatInt(r.visits)}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{formatInt(r.connections)}</td>
                      <td className="px-2 py-2"><ShareBar share={r.share} max={max} /></td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.users}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.devices}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.hosts}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{bytesText(r.bytes)}</td>
                      <td className={`tnum px-2 py-2 text-right ${r.blocked > 0 ? 'text-amber' : 'text-muted'}`}>{r.blocked > 0 ? formatInt(r.blocked) : '—'}</td>
                      <td className="tnum px-2 py-2 text-right text-muted">{r.warp > 0 ? formatInt(r.warp) : '—'}</td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{formatDateTime(r.last_seen, tz)}</td>
                      {isOwner && (
                        <td className="whitespace-nowrap px-2 py-2 text-right">
                          <Link to={`/intel?target=${encodeURIComponent(r.site)}`} className="mr-3 text-xs text-muted underline-offset-2 hover:text-cyan hover:underline" aria-label={`${t('intel.investigate')}: ${r.site}`}>{t('intel.investigate')}</Link>
                          <button type="button" onClick={() => setRuleFor(r.site)} className="whitespace-nowrap text-xs text-muted underline-offset-2 hover:text-cyan hover:underline" aria-label={`${t('sites.setCategory')}: ${r.site}`}>{r.classified ? t('sites.change') : t('sites.setCategory')}</button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {hasAwg(data.rows) && <p className="mt-3 text-xs leading-5 text-muted">{t('src.awg.note')}</p>}
          {data.groups > PAGE && (
            <nav aria-label="pagination" className="mt-3 flex items-center justify-between gap-3 text-[13px] text-muted">
              <span className="tnum">{t('an.page', { from: offset + 1, to: Math.min(offset + PAGE, data.groups), total: data.groups })}</span>
              <div className="flex gap-2">
                <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className={`${controlCls} disabled:opacity-40`}>{t('an.prev')}</button>
                <button type="button" disabled={offset + PAGE >= data.groups} onClick={() => setOffset(offset + PAGE)} className={`${controlCls} disabled:opacity-40`}>{t('an.next')}</button>
              </div>
            </nav>
          )}
        </Card>
      )}
      {ruleFor && <RuleDialog site={ruleFor} onClose={() => setRuleFor(null)} onDone={() => { setRuleFor(null); reload() }} />}
      {sel && view === 'sites' && <Drawer title={sel} onClose={() => setSel(null)}><Detail site={sel} subject={subject} /></Drawer>}
    </div>
  )
}
