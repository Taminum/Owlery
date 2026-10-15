import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Plus } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { DnsChange, DnsCoverage, DnsGraph as GraphData, DnsGraphNode, DnsMap, DnsRecord, DnsRun } from '../lib/types'
import { Card, Chip } from '../components/ui'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import { DnsGraph } from '../components/DnsGraph'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'

type Tone = 'muted' | 'amber' | 'green' | 'red' | 'cyan'
const STATUS_TONE: Record<string, Tone> = { ok: 'green', partial: 'amber', failed: 'red', running: 'cyan', none: 'muted' }
const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean)
const BASE = '/api/v1/intel/dns/maps'

/** Which of these addresses are a registered server in "Security". Only a registered address links;
 *  an IP that merely looks related to a server is not shown as one. */
function useServerLinks(ips: string[]): Record<string, { vps_id: string; name: string }> {
  const list = [...new Set(ips)].sort().slice(0, 100)
  const qs = list.map((x) => `a=${encodeURIComponent(x)}`).join('&')
  const { data } = useLoad((s) => (list.length === 0 ? Promise.resolve(null) : api.get<{ items: Record<string, { vps_id: string; name: string }> }>(`/api/v1/security/vps-by-address?${qs}`, s)), [qs])
  return data?.items ?? {}
}

function ServerLink({ m }: { m?: { vps_id: string; name: string } }) {
  if (!m) return null
  return <Link to={`/security/${m.vps_id}`} className="ml-2 font-sans text-xs text-cyan hover:underline">{t('dns.vps.link', { name: m.name })}</Link>
}

function statusOf(m: DnsMap): string {
  if (m.last_run?.status === 'running') return 'running'
  return m.last_status ?? 'none'
}

function StatusChip({ m }: { m: DnsMap }) {
  const s = statusOf(m)
  return <Chip tone={STATUS_TONE[s] ?? 'muted'}>{t(`dns.status.${s}` as MsgKey)}</Chip>
}

function AddDialog({ onClose, onDone }: { onClose: () => void; onDone: (m: DnsMap) => void }) {
  const [domain, setDomain] = useState('')
  const [extra, setExtra] = useState('')
  const [useCt, setUseCt] = useState(false)
  const [hours, setHours] = useState(24)
  const [scope, setScope] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function save() {
    setBusy(true)
    setError('')
    try {
      onDone(await api.post<DnsMap>(BASE, { domain: domain.trim(), extra_names: lines(extra), use_ct: useCt, interval_hours: hours, confirm_scope: scope }))
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('dns.add')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && domain.trim() && scope) void save() }}>
        <Field label={t('dns.domain')} htmlFor="dns-domain"><input id="dns-domain" className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)} spellCheck={false} placeholder="example.com" data-autofocus /></Field>
        <Field label={t('dns.extra')} hint={t('dns.extraHint')} htmlFor="dns-extra">
          <textarea id="dns-extra" className={`${inputCls} h-24 py-2 font-mono text-[13px]`} value={extra} onChange={(e) => setExtra(e.target.value)} spellCheck={false} />
        </Field>
        <label className="flex items-start gap-2 text-[13px]"><input type="checkbox" className="mt-1" checked={useCt} onChange={(e) => setUseCt(e.target.checked)} /><span>{t('dns.useCt')}<span className="block text-xs text-muted">{t('dns.useCtHint')}</span></span></label>
        <Field label={t('dns.interval')} htmlFor="dns-int">
          <select id="dns-int" className={inputCls} value={hours} onChange={(e) => setHours(Number(e.target.value))}>{[6, 12, 24, 72, 168].map((h) => <option key={h} value={h}>{t('dns.hours', { n: h })}</option>)}</select>
        </Field>
        <label className="flex items-start gap-2 text-[13px]"><input type="checkbox" className="mt-1" checked={scope} onChange={(e) => setScope(e.target.checked)} /><span>{t('dns.scope')}</span></label>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={busy || !domain.trim() || !scope}>{t('dns.create')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

/** The list of studied domains, shown inside Network Intel. */
export function DnsMapList() {
  const nav = useNavigate()
  const { data, error } = useLoad((s) => api.get<{ items: DnsMap[] }>(BASE, s), [], 15_000)
  const [adding, setAdding] = useState(false)
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <p className="max-w-2xl text-[13px] text-muted">{t('dns.subtitle')}</p>
        <PrimaryButton onClick={() => setAdding(true)}><span className="inline-flex items-center gap-2"><Plus size={16} aria-hidden />{t('dns.add')}</span></PrimaryButton>
      </div>
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!data && !error && <TableSkeleton />}
      {data && data.items.length === 0 && (
        <div role="status" className="rounded-card border border-line bg-surface px-6 py-12 text-center">
          <h2 className="text-lg font-semibold">{t('dns.none')}</h2>
          <p className="mx-auto mt-2 max-w-md text-[13px] text-muted">{t('dns.noneHint')}</p>
        </div>
      )}
      {data && data.items.length > 0 && (
        <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.items.map((m) => (
            <li key={m.id}>
              <Link to={`/intel/dns/${m.id}`} className="block rounded-card border border-line bg-surface p-4 hover:border-blue/60">
                <div className="flex items-start justify-between gap-3">
                  <h2 className="break-all text-[16px] font-semibold">{m.display}</h2>
                  <StatusChip m={m} />
                </div>
                <p className="mt-2 text-[12px] text-muted">
                  {m.last_run_at ? `${t('dns.lastRun')}: ${formatDateTime(m.last_run_at, 'local')}` : t('dns.status.none')}
                  {!m.enabled && ` · ${t('dns.disabled')}`}
                </p>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {adding && <AddDialog onClose={() => setAdding(false)} onDone={(m) => nav(`/intel/dns/${m.id}`)} />}
    </div>
  )
}

function Coverage({ m }: { m: DnsMap }) {
  const run = m.last_run
  const c = run && 'discovery' in run.coverage ? (run.coverage as DnsCoverage) : null
  return (
    <Card title={t('dns.cover.title')}>
      <ul className="space-y-1 text-[13px] text-muted">
        {c ? (
          <>
            <li>{t('dns.cover.known', { n: c.names_checked, m: c.names_total })}</li>
            {c.names_dropped > 0 && <li>{t('dns.cover.dropped', { n: c.names_dropped })}</li>}
            <li>{t('dns.cover.questions', { n: c.questions, f: c.failures, u: c.unconfirmed })}</li>
            <li>{t('dns.cover.resolvers')}: {(c.resolvers ?? []).join(', ')}. {t('dns.cover.auth', { n: c.authoritative_asked })}</li>
            {run && run.mismatch.length > 0 && <li className="text-amber">{t('dns.cover.mismatch', { types: run.mismatch.join(', ') })}</li>}
          </>
        ) : <li>{t('dns.map.empty')}</li>}
        <li>{t('dns.cover.dnssec')}</li>
      </ul>
    </Card>
  )
}

const TABS = ['map', 'records', 'history', 'checks'] as const
type Tab = (typeof TABS)[number]

export function DnsMapDetail() {
  const { id = '' } = useParams()
  const nav = useNavigate()
  const { data, error, reload } = useLoad((s) => api.get<{ map: DnsMap }>(`${BASE}/${id}`, s), [id], 10_000)
  const [tab, setTab] = useState<Tab>('map')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [confirm, setConfirm] = useState(false)
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  const m = data.map
  // A run that finishes changes what every tab shows, so the tabs reload when it does.
  const rk = `${m.last_run_at ?? ''}|${m.last_status ?? ''}`
  async function refresh() {
    setErr('')
    setMsg('')
    try {
      await api.post(`${BASE}/${id}/refresh`)
      setMsg(t('dns.refreshSent'))
      window.setTimeout(reload, 5000)
    } catch (e) {
      setErr(errorText(e))
    }
  }
  async function archive() {
    try {
      await api.del(`${BASE}/${id}`)
      nav('/intel?view=dns')
    } catch (e) {
      setConfirm(false)
      setErr(errorText(e))
    }
  }
  return (
    <div className="space-y-4">
      <Link to="/intel?view=dns" className="inline-flex items-center gap-2 text-[13px] text-muted hover:text-fg"><ArrowLeft size={15} aria-hidden />{t('dns.back')}</Link>
      <PageHead title={m.display} subtitle={t('dns.subtitle')}
        right={<div className="flex flex-wrap items-center gap-3"><StatusChip m={m} /><PrimaryButton onClick={() => void refresh()}>{t('dns.refresh')}</PrimaryButton></div>} />
      {msg && <p role="status" className="text-[13px] text-muted">{msg}</p>}
      {err && <p role="alert" className="text-[13px] text-red">{err}</p>}
      <p className="text-xs text-muted">
        {m.last_run_at && `${t('dns.lastRun')}: ${formatDateTime(m.last_run_at, 'local')}`}
        {m.next_run_at && m.enabled && ` · ${t('dns.nextRun')}: ${formatDateTime(m.next_run_at, 'local')}`}
        {!m.enabled && ` · ${t('dns.disabled')}`}
      </p>
      <Coverage m={m} />
      <div role="tablist" aria-label={m.display} className="flex flex-wrap gap-2">
        {TABS.map((x) => (
          <button key={x} role="tab" type="button" aria-selected={tab === x} onClick={() => setTab(x)}
            className={`h-8 rounded-control border px-3 text-[13px] ${tab === x ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(`dns.tab.${x}` as MsgKey)}</button>
        ))}
      </div>
      {tab === 'map' && <MapTab id={id} rk={rk} finished={!!m.last_run_at} />}
      {tab === 'records' && <RecordsTab id={id} rk={rk} />}
      {tab === 'history' && <HistoryTab id={id} rk={rk} />}
      {tab === 'checks' && <ChecksTab id={id} rk={rk} />}
      <div><DangerButton onClick={() => setConfirm(true)}>{t('dns.archive')}</DangerButton></div>
      {confirm && (
        <Modal title={t('dns.archive')} onClose={() => setConfirm(false)}>
          <p className="text-[13px] text-muted">{t('dns.archiveConfirm')}</p>
          <div className="mt-4 flex justify-end gap-3"><GhostButton onClick={() => setConfirm(false)}>{t('common.cancel')}</GhostButton><DangerButton onClick={() => void archive()}>{t('dns.archive')}</DangerButton></div>
        </Modal>
      )}
    </div>
  )
}

// ---- map -----------------------------------------------------------------------------------------

function MapTab({ id, rk, finished }: { id: string; rk: string; finished: boolean }) {
  const [max, setMax] = useState(150)
  const [selected, setSelected] = useState<DnsGraphNode | null>(null)
  const [query, setQuery] = useState('')
  const { data, error } = useLoad((s) => api.get<GraphData>(`${BASE}/${id}/graph?max_nodes=${max}`, s), [id, max, rk], 30_000)
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label={t('dns.rec.search')} htmlFor="dns-gq"><input id="dns-gq" className={inputCls} value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} /></Field>
        <Field label={t('dns.map.max')} htmlFor="dns-max">
          <select id="dns-max" className={inputCls} value={max} onChange={(e) => setMax(Number(e.target.value))}>{[50, 150, 400].map((n) => <option key={n} value={n}>{n}</option>)}</select>
        </Field>
      </div>
      {data.nodes.length === 0 ? <p className="text-[13px] text-muted">{t(finished ? 'dns.map.noRecords' : 'dns.map.empty')}</p> : (
        <DnsGraph graph={data} selected={selected?.id ?? null} onSelect={setSelected} query={query} />
      )}
      {data.truncated && <p className="mt-2 text-[13px] text-amber">{t('dns.map.truncated', { n: data.nodes.length, m: data.total_nodes })}</p>}
      <p className="mt-2 text-xs text-muted">{t('dns.map.legend')}</p>
      {selected && <NodeDetails id={id} node={selected} graph={data} />}
    </Card>
  )
}

function NodeDetails({ id, node, graph }: { id: string; node: DnsGraphNode; graph: GraphData }) {
  const isName = node.kind === 'name'
  const { data } = useLoad((s) => (isName ? api.get<{ items: DnsRecord[] }>(`${BASE}/${id}/records?name=${encodeURIComponent(node.label)}&limit=100`, s) : Promise.resolve(null)), [id, node.id])
  const related = graph.edges.filter((e) => e.from === node.id || e.to === node.id)
  const links = useServerLinks(node.kind === 'ip' ? [node.label] : [])
  return (
    <div className="mt-4 rounded-control border border-line p-3 text-[13px]">
      <h3 className="mb-2 font-medium">{t('dns.map.node')}: <span className="font-mono">{node.label}</span> <span className="text-muted">({t(`dns.map.kind.${node.kind}` as MsgKey)})</span></h3>
      {node.kind === 'ip' && <><Link className="text-cyan hover:underline" to={`/intel?target=${encodeURIComponent(node.label)}`}>{t('dns.map.open')}</Link><ServerLink m={links[node.label]} /></>}
      {isName && data && (
        <ul className="space-y-1">
          {data.items.map((r) => (
            <li key={r.type}><span className="inline-block w-14 font-medium">{r.type}</span> <span className="font-mono text-[12px]">{r.values.join(' · ') || '—'}</span> <span className="text-xs text-muted">{r.confirmed ? t('dns.rec.confirmed') : t('dns.rec.unconfirmed')}{r.no_longer_observed ? ` · ${t('dns.rec.gone')}` : ''}</span></li>
          ))}
        </ul>
      )}
      {!isName && <ul className="space-y-1 text-muted">{related.map((e, i) => <li key={i}>{e.type}{e.label ? ` ${e.label}` : ''}: {e.from.replace(/^name:/, '')}</li>)}</ul>}
    </div>
  )
}

// ---- records -------------------------------------------------------------------------------------

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'CAA', 'DS', 'DNSKEY']

function ValueText({ r, v, links }: { r: DnsRecord; v: string; links: Record<string, { vps_id: string; name: string }> }) {
  if (r.type === 'A' || r.type === 'AAAA') return <><Link className="hover:text-cyan hover:underline" to={`/intel?target=${encodeURIComponent(v)}`}>{v}</Link><ServerLink m={links[v]} /></>
  return <>{v}</>
}

function RecordsTab({ id, rk }: { id: string; rk: string }) {
  const [type, setType] = useState('')
  const [q, setQ] = useState('')
  const [dq, setDq] = useState('')
  const [open, setOpen] = useState('')
  const [extra, setExtra] = useState<{ key: string; items: DnsRecord[]; more: boolean | null }>({ key: '', items: [], more: null })
  const [err, setErr] = useState('')
  useEffect(() => {
    const h = window.setTimeout(() => setDq(q.trim()), 350)
    return () => window.clearTimeout(h)
  }, [q])
  const qs = new URLSearchParams({ limit: '100' })
  if (type) qs.set('type', type)
  if (dq) qs.set('q', dq)
  const key = qs.toString()
  const first = useLoad((s) => api.get<{ items: DnsRecord[]; more: boolean }>(`${BASE}/${id}/records?${key}`, s), [id, key, rk], 30_000)
  const added = extra.key === key ? extra : { key, items: [], more: null }
  const items = [...(first.data?.items ?? []), ...added.items]
  const more = added.more ?? first.data?.more ?? false
  const links = useServerLinks(items.filter((r) => r.type === 'A' || r.type === 'AAAA').flatMap((r) => r.values))
  async function loadMore() {
    const last = items[items.length - 1]
    setErr('')
    try {
      const p = new URLSearchParams(qs)
      p.set('after_name', last.name)
      p.set('after_type', last.type)
      const r = await api.get<{ items: DnsRecord[]; more: boolean }>(`${BASE}/${id}/records?${p}`)
      setExtra({ key, items: [...added.items, ...r.items], more: r.more })
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label={t('dns.rec.type')} htmlFor="dns-rt">
          <select id="dns-rt" className={inputCls} value={type} onChange={(e) => setType(e.target.value)}><option value="">{t('dns.rec.allTypes')}</option>{TYPES.map((x) => <option key={x} value={x}>{x}</option>)}</select>
        </Field>
        <Field label={t('dns.rec.search')} htmlFor="dns-rq"><input id="dns-rq" className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} spellCheck={false} /></Field>
      </div>
      {first.error && <p role="alert" className="text-[13px] text-red">{first.error}</p>}
      {first.data && items.length === 0 && <p className="text-[13px] text-muted">{t('dns.rec.none')}</p>}
      {items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-xs text-muted"><th className="py-2 pr-4 font-medium">{t('dns.rec.name')}</th><th className="pr-4 font-medium">{t('dns.rec.type')}</th><th className="pr-4 font-medium">{t('dns.rec.values')}</th><th className="pr-4 font-medium">{t('dns.rec.ttl')}</th><th className="font-medium">{t('dns.rec.state')}</th></tr></thead>
            <tbody>
              {items.map((r) => {
                const k = `${r.name}|${r.type}`
                return (
                  <tr key={k} className="border-t border-line align-top">
                    <td className="py-2 pr-4 font-mono text-[12px]"><button type="button" className="text-left hover:text-cyan" aria-expanded={open === k} onClick={() => setOpen(open === k ? '' : k)}>{r.name}</button></td>
                    <td className="pr-4">{r.type}</td>
                    <td className="break-all pr-4 font-mono text-[12px]">
                      {r.values.length === 0 ? <span className="font-sans text-muted">{t(`dns.out.${r.result ?? r.last_result}` as MsgKey)}</span> : r.values.map((v) => <div key={v}><ValueText r={r} v={v} links={links} /></div>)}
                      {open === k && (
                        <div className="mt-2 rounded-control border border-line p-2 font-sans text-xs text-muted">
                          <p className="font-medium text-fg">{t('dns.rec.views')}</p>
                          {r.views.map((v) => <p key={v.server}><span className="font-mono">{v.server}</span>: {t(`dns.out.${v.outcome}` as MsgKey)}{v.values && v.values.length > 0 ? ` · ${v.values.join(' · ')}` : ''}</p>)}
                          <p className="mt-1">{t('dns.rec.seen')}: {formatDateTime(r.first_seen, 'local')} → {r.last_seen ? formatDateTime(r.last_seen, 'local') : '—'}</p>
                          <p>{t('dns.rec.lastResult')}: {t(`dns.out.${r.last_result}` as MsgKey)}</p>
                        </div>
                      )}
                    </td>
                    <td className="tnum pr-4">{r.ttl || '—'}</td>
                    <td><Chip tone={r.no_longer_observed ? 'amber' : r.confirmed ? 'green' : 'muted'}>{r.no_longer_observed ? t('dns.rec.gone') : r.confirmed ? t('dns.rec.confirmed') : t('dns.rec.unconfirmed')}</Chip></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
      {more && <div className="mt-3"><GhostButton onClick={() => void loadMore()}>{t('dns.rec.more')}</GhostButton></div>}
    </Card>
  )
}

// ---- history -------------------------------------------------------------------------------------

const KINDS = ['dns.record_added', 'dns.record_removed', 'dns.value_changed', 'dns.mx_changed', 'dns.ns_changed', 'dns.spf_changed', 'dns.dmarc_changed', 'dns.check_failed', 'dns.check_recovered']

function HistoryTab({ id, rk }: { id: string; rk: string }) {
  const [kind, setKind] = useState('')
  const [type, setType] = useState('')
  const [period, setPeriod] = useState<'all' | '24h' | '7d' | '30d'>('all')
  const [name, setName] = useState('')
  const [dname, setDname] = useState('')
  const [extra, setExtra] = useState<{ key: string; items: DnsChange[]; more: boolean | null }>({ key: '', items: [], more: null })
  const [err, setErr] = useState('')
  useEffect(() => {
    const h = window.setTimeout(() => setDname(name.trim().toLowerCase()), 350)
    return () => window.clearTimeout(h)
  }, [name])
  // The lower bound is fixed when the period is chosen, so the query does not change on every render.
  const [since, setSince] = useState('')
  function choosePeriod(p: typeof period) {
    const h = { all: 0, '24h': 24, '7d': 24 * 7, '30d': 24 * 30 }[p]
    setPeriod(p)
    setSince(h ? new Date(Date.now() - h * 3_600_000).toISOString() : '')
  }
  const qs = new URLSearchParams({ limit: '50' })
  if (kind) qs.set('kind', kind)
  if (type) qs.set('type', type)
  if (since) qs.set('from', since)
  if (dname) qs.set('name', dname)
  const key = qs.toString()
  const first = useLoad((s) => api.get<{ items: DnsChange[]; more: boolean }>(`${BASE}/${id}/changes?${key}`, s), [id, key, rk], 30_000)
  const added = extra.key === key ? extra : { key, items: [], more: null }
  const items = [...(first.data?.items ?? []), ...added.items]
  const more = added.more ?? first.data?.more ?? false
  async function loadMore() {
    const last = items[items.length - 1]
    setErr('')
    try {
      const p = new URLSearchParams(qs)
      p.set('before_ts', last.observed_at)
      p.set('before_id', last.id)
      const r = await api.get<{ items: DnsChange[]; more: boolean }>(`${BASE}/${id}/changes?${p}`)
      setExtra({ key, items: [...added.items, ...r.items], more: r.more })
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label={t('dns.hist.kind')} htmlFor="dns-hk">
          <select id="dns-hk" className={inputCls} value={kind} onChange={(e) => setKind(e.target.value)}><option value="">{t('dns.hist.allKinds')}</option>{KINDS.map((k) => <option key={k} value={k}>{t(`dns.kind.${k}` as MsgKey)}</option>)}</select>
        </Field>
        <Field label={t('dns.rec.type')} htmlFor="dns-ht">
          <select id="dns-ht" className={inputCls} value={type} onChange={(e) => setType(e.target.value)}><option value="">{t('dns.rec.allTypes')}</option>{TYPES.map((x) => <option key={x} value={x}>{x}</option>)}</select>
        </Field>
        <Field label={t('dns.hist.period')} htmlFor="dns-hp">
          <select id="dns-hp" className={inputCls} value={period} onChange={(e) => choosePeriod(e.target.value as typeof period)}>
            {(['all', '24h', '7d', '30d'] as const).map((p) => <option key={p} value={p}>{t(`dns.hist.period.${p}` as MsgKey)}</option>)}
          </select>
        </Field>
        <Field label={t('dns.hist.name')} htmlFor="dns-hn"><input id="dns-hn" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={253} spellCheck={false} /></Field>
      </div>
      {first.error && <p role="alert" className="text-[13px] text-red">{first.error}</p>}
      {first.data && items.length === 0 && <p className="text-[13px] text-muted">{t('dns.hist.none')}</p>}
      <ul className="divide-y divide-line">
        {items.map((c) => (
          <li key={c.id} className="py-2 text-[13px]">
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <span><Chip tone={c.kind === 'dns.check_failed' ? 'red' : c.kind === 'dns.record_added' || c.kind === 'dns.check_recovered' ? 'muted' : 'amber'}>{t(`dns.kind.${c.kind}` as MsgKey)}</Chip>
                <span className="ml-2 font-mono text-[12px]">{c.name || '—'}{c.type !== '*' ? ` ${c.type}` : ''}</span></span>
              <span className="tnum text-xs text-muted">{formatDateTime(c.observed_at, 'local')}</span>
            </div>
            {(c.before.length > 0 || c.after.length > 0) && (
              <div className="mt-1 grid gap-1 font-mono text-[12px] sm:grid-cols-2">
                <div className="text-muted">{t('dns.hist.before')}: {c.before.join(' · ') || '—'}</div>
                <div>{t('dns.hist.after')}: {c.after.join(' · ') || '—'}</div>
              </div>
            )}
            {c.volatile && <p className="mt-1 text-xs text-amber">{t('dns.hist.volatile')}</p>}
          </li>
        ))}
      </ul>
      {err && <p role="alert" className="mt-2 text-[13px] text-red">{err}</p>}
      {more && <div className="mt-3"><GhostButton onClick={() => void loadMore()}>{t('dns.rec.more')}</GhostButton></div>}
    </Card>
  )
}

// ---- checks --------------------------------------------------------------------------------------

function ChecksTab({ id, rk }: { id: string; rk: string }) {
  const { data, error } = useLoad((s) => api.get<{ items: DnsRun[] }>(`${BASE}/${id}/checks?limit=20`, s), [id, rk], 20_000)
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return <TableSkeleton />
  if (data.items.length === 0) return <Card><p className="text-[13px] text-muted">{t('dns.checks.none')}</p></Card>
  return (
    <div className="space-y-3">
      {data.items.map((r, i) => (
        <Card key={r.id} title={formatDateTime(r.started_at, 'local')} note={t(`dns.checks.trigger.${r.trigger}` as MsgKey)}
          right={<Chip tone={STATUS_TONE[r.status] ?? 'muted'}>{t(`dns.status.${r.status}` as MsgKey)}</Chip>}>
          {r.error && <p className="text-[13px] text-red">{t('dns.checks.error')}: {r.error}</p>}
          {r.mismatch.length > 0 && <p className="text-[13px] text-amber">{t('dns.cover.mismatch', { types: r.mismatch.join(', ') })}</p>}
          {i === 0 && r.auth.length > 0 && (
            <div className="mt-2 text-[13px]">
              <p className="font-medium">{t('dns.checks.auth')}</p>
              <ul className="mt-1 space-y-1 text-muted">
                {r.auth.map((a) => (
                  <li key={a.ns}><span className="font-mono text-[12px] text-fg">{a.ns}</span> {a.addr ? <span className="font-mono text-[12px]">{a.addr}</span> : t(`dns.checks.skipped.${a.skipped ?? 'unresolved'}` as MsgKey)}
                    {a.answers && ` · ${Object.entries(a.answers).map(([ty, x]) => `${ty}: ${t(`dns.out.${x.outcome}` as MsgKey)}`).join(', ')}`}</li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      ))}
    </div>
  )
}
