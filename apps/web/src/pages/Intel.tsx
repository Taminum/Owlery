import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { formatInt } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { PageHead } from '../components/Analyzer'
import { GhostButton, PrimaryButton, inputCls } from '../components/Modal'

interface Source { name: string; ok: boolean; error?: string }
interface Envelope<T> { kind: string; target: string; display: string; fetched_at: string; expires_at: string; cached: boolean; vantage: string; sources: Source[]; data: T | null }
interface RDAP { name?: string; handle?: string; range?: string; cidr?: string; org?: string; country?: string; registered?: string; changed?: string }
interface IPInfo { ip: string; version: number; public: boolean; ptr?: string; asn?: number; owner?: string; country?: string; rdap?: RDAP }
interface DNSRecords { a: string[]; aaaa: string[]; cname?: string; mx: { host: string; priority: number }[]; ns: string[]; txt: string[] }
interface DomainOverview { dns: DNSRecords; ips: IPInfo[] }
interface CIDRInfo { cidr: string; version: number; first: string; last: string; addresses: string; netmask?: string; public: boolean }
interface SubList { names: string[]; total: number; truncated: boolean }
interface PingRes { address: string; sent: number; received: number; loss_pct: number; min_ms: number | null; avg_ms: number | null; max_ms: number | null; reachable: boolean }
interface Hop { ttl: number; addr?: string; owner?: string; asn?: number; rtt_ms: number[]; lost: number; reached: boolean }
interface TraceRes { address: string; hops: Hop[]; reached: boolean }
interface Cert { subject: string; issuer: string; not_before: string; not_after: string; days_left: number; dns_names?: string[]; serial: string; sig_alg: string; key_type: string; ca: boolean }
interface TLSRes { address: string; port: number; sni?: string; version: string; cipher: string; alpn?: string; verified: boolean; verify_error?: string; handshake_ms: number; chain: Cert[] }
interface HTTPHop { url: string; status: number; proto: string; ms: number; location?: string; tls?: string; headers: Record<string, string> }
interface HTTPRes { hops: HTTPHop[]; final_status: number; security: Record<string, boolean> }
interface PortsRes { address: string; results: { port: number; open: boolean; error?: string; ms?: number }[] }

const TABS = ['overview', 'dns', 'subdomains', 'ping', 'trace', 'ports', 'tls', 'http'] as const
type Tab = (typeof TABS)[number]

const errText = (code?: string) => {
  const key = `intel.err.${code}` as MsgKey
  try {
    const s = t(key)
    if (s !== key) return s
  } catch { /* unknown code */ }
  return t('intel.err.other', { code: code ?? '?' })
}

const when = (iso: string) => new Date(iso).toLocaleString('ru-RU')

function Meta({ env, onRefresh }: { env: Envelope<unknown>; onRefresh?: () => void }) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-muted">
      <span>{t('intel.fetched', { when: when(env.fetched_at) })}</span>
      {env.cached && <span>· {t('intel.cached', { until: when(env.expires_at) })}</span>}
      {env.sources.map((s) => <Chip key={s.name} tone={s.ok ? 'green' : 'amber'}>{s.name}{s.ok ? '' : `: ${errText(s.error)}`}</Chip>)}
      {onRefresh && <GhostButton onClick={onRefresh}>{t('intel.refresh')}</GhostButton>}
    </div>
  )
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return <div className="flex flex-wrap gap-x-3 py-1.5 text-[13px]"><dt className="w-40 shrink-0 text-muted">{k}</dt><dd className="min-w-0 break-words text-fg">{children}</dd></div>
}

function IPCard({ ip }: { ip: IPInfo }) {
  return (
    <div className="rounded-control border border-line p-3">
      <div className="mb-1 flex flex-wrap items-center gap-2"><span className="font-mono text-[14px] font-medium">{ip.ip}</span><Chip tone={ip.public ? 'muted' : 'amber'}>{ip.public ? t('intel.ip.public') : t('intel.ip.private')}</Chip></div>
      <dl>
        {ip.owner && <Row k={t('intel.ip.owner')}>{ip.owner}{ip.asn ? ` · AS${ip.asn}` : ''}<div className="text-xs text-muted">{t('intel.ip.ownerHint')}</div></Row>}
        {ip.country && <Row k={t('intel.ip.country')}>{ip.country}</Row>}
        {ip.ptr && <Row k={t('intel.ip.ptr')}>{ip.ptr}</Row>}
        {ip.rdap && (
          <>
            {ip.rdap.org && <Row k={t('intel.ip.org')}>{ip.rdap.org}</Row>}
            {(ip.rdap.cidr || ip.rdap.range) && <Row k={t('intel.ip.range')}>{ip.rdap.cidr ?? ip.rdap.range}{ip.rdap.name ? ` · ${ip.rdap.name}` : ''}</Row>}
            {ip.rdap.registered && <Row k={t('intel.ip.registered')}>{ip.rdap.registered.slice(0, 10)}</Row>}
            {ip.rdap.changed && <Row k={t('intel.ip.changed')}>{ip.rdap.changed.slice(0, 10)}</Row>}
          </>
        )}
      </dl>
    </div>
  )
}

function DNSView({ d }: { d: DNSRecords }) {
  const line = (label: string, vals: string[]) => <Row k={label}>{vals.length ? <span className="font-mono text-[12px]">{vals.join(' · ')}</span> : <span className="text-muted">{t('intel.dns.none')}</span>}</Row>
  return (
    <dl>
      {line(t('intel.dns.a'), d.a)}
      {line(t('intel.dns.aaaa'), d.aaaa)}
      {d.cname && line(t('intel.dns.cname'), [d.cname])}
      {line(t('intel.dns.mx'), d.mx.map((m) => `${m.priority} ${m.host}`))}
      {line(t('intel.dns.ns'), d.ns)}
      <Row k={t('intel.dns.txt')}>{d.txt.length ? <ul className="space-y-1">{d.txt.map((x, i) => <li key={i} className="break-all font-mono text-[12px]">{x}</li>)}</ul> : <span className="text-muted">{t('intel.dns.none')}</span>}</Row>
    </dl>
  )
}

function useIntel<T>(kind: string, target: string, extra: string, nonce: number, enabled: boolean) {
  return useLoad((s) => (enabled ? api.get<Envelope<T>>(`/api/v1/intel/${kind}?target=${encodeURIComponent(target)}${extra}`, s) : Promise.resolve(null)), [kind, target, extra, nonce, enabled])
}

function Result<T>({ q, children, refresh }: { q: ReturnType<typeof useIntel<T>>; children: (env: Envelope<T>) => React.ReactNode; refresh?: () => void }) {
  if (q.error) return <p role="alert" className="text-[13px] text-red">{q.error}</p>
  if (!q.data) return <p className="text-[13px] text-muted">{t('state.loading')}</p>
  const env = q.data
  return (
    <>
      <Meta env={env} onRefresh={refresh} />
      {env.data ? children(env) : <p className="text-[13px] text-amber">{env.sources.filter((s) => !s.ok).map((s) => errText(s.error)).join(' ') || errText('unavailable')}</p>}
    </>
  )
}

function Overview({ target, nonce, bump, isCidr, isDomain }: { target: string; nonce: number; bump: () => void; isCidr: boolean; isDomain: boolean }) {
  const q = useIntel<DomainOverview | IPInfo | CIDRInfo>('lookup', target, nonce ? '&refresh=1' : '', nonce, true)
  return (
    <Result q={q} refresh={isCidr ? undefined : bump}>
      {(env) => {
        if (isCidr) {
          const c = env.data as CIDRInfo
          return <dl><Row k="CIDR">{c.cidr}</Row><Row k={t('intel.cidr.first')}>{c.first}</Row><Row k={t('intel.cidr.last')}>{c.last}</Row><Row k={t('intel.cidr.count')}>{c.addresses.length < 16 ? formatInt(Number(c.addresses)) : c.addresses}</Row>{c.netmask && <Row k={t('intel.cidr.mask')}>{c.netmask}</Row>}</dl>
        }
        if (isDomain) {
          const o = env.data as DomainOverview
          return (
            <div className="space-y-4">
              <DNSView d={o.dns} />
              {o.ips.length > 0 && <div><h3 className="mb-2 text-[13px] font-medium">{t('intel.addresses')}</h3><div className="grid gap-3 lg:grid-cols-2">{o.ips.map((ip) => <IPCard key={ip.ip} ip={ip} />)}</div></div>}
              <Link className="text-[13px] text-muted underline-offset-2 hover:text-cyan hover:underline" to={`/sites?q=${encodeURIComponent(target)}`}>{t('intel.openSite')}</Link>
            </div>
          )
        }
        return <IPCard ip={env.data as IPInfo} />
      }}
    </Result>
  )
}

function Active({ kind, target, extra, children }: { kind: 'ping' | 'ports' | 'trace' | 'tls' | 'http'; target: string; extra: string; children: (env: Envelope<never>) => React.ReactNode }) {
  const [run, setRun] = useState(0)
  const q = useIntel<never>(kind, target, extra, run, run > 0)
  return (
    <div>
      <PrimaryButton disabled={run > 0 && !q.data && !q.error} onClick={() => setRun((n) => n + 1)}>{run > 0 && !q.data && !q.error ? t('intel.running') : t('intel.run')}</PrimaryButton>
      <div className="mt-4">{run > 0 && <Result q={q}>{children}</Result>}</div>
    </div>
  )
}

function Panels({ target, kind }: { target: string; kind: string }) {
  const [tab, setTab] = useState<Tab>('overview')
  const [nonce, setNonce] = useState(0)
  const [ports, setPorts] = useState('80,443')
  const isDomain = kind === 'domain'
  const isCidr = kind === 'cidr'
  const allowed: Tab[] = isCidr ? ['overview'] : isDomain ? [...TABS] : ['overview', 'ping', 'trace', 'ports', 'tls', 'http']
  const cur = allowed.includes(tab) ? tab : 'overview'
  return (
    <Card>
      <div role="tablist" aria-label={t('intel.title')} className="mb-4 flex flex-wrap gap-2">
        {allowed.map((x) => (
          <button key={x} role="tab" type="button" aria-selected={cur === x} onClick={() => setTab(x)}
            className={`h-8 rounded-control border px-3 text-[13px] ${cur === x ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{t(`intel.tab.${x}` as MsgKey)}</button>
        ))}
      </div>
      {cur === 'overview' && <Overview target={target} nonce={nonce} bump={() => setNonce((n) => n + 1)} isCidr={isCidr} isDomain={isDomain} />}
      {cur === 'dns' && <DNSTab target={target} />}
      {cur === 'subdomains' && <SubTab target={target} />}
      {cur === 'ping' && (
        <Active kind="ping" target={target} extra="&count=4">
          {(env) => {
            const p = env.data as unknown as PingRes
            return (
              <div className="space-y-3">
                {p.reachable ? (
                  <dl className="grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-4">
                    <div><dt className="text-xs text-muted">{t('intel.ping.sent')} / {t('intel.ping.received')}</dt><dd className="tnum text-[22px] font-bold">{p.sent} / {p.received}</dd></div>
                    <div><dt className="text-xs text-muted">{t('intel.ping.loss')}</dt><dd className="tnum text-[22px] font-bold">{p.loss_pct}%</dd></div>
                    <div><dt className="text-xs text-muted">{t('intel.ping.avg')}</dt><dd className="tnum text-[22px] font-bold">{p.avg_ms?.toFixed(1)} мс</dd></div>
                    <div><dt className="text-xs text-muted">{t('intel.ping.range')}</dt><dd className="tnum text-[22px] font-bold">{p.min_ms?.toFixed(1)} / {p.max_ms?.toFixed(1)}</dd></div>
                  </dl>
                ) : <p className="text-[13px] text-amber">{t('intel.ping.down')} ({p.address})</p>}
                <p className="text-xs text-muted">{t('intel.ping.note')}</p>
              </div>
            )
          }}
        </Active>
      )}
      {cur === 'trace' && (
        <Active kind="trace" target={target} extra="">
          {(env) => {
            const r = env.data as unknown as TraceRes
            return (
              <div className="space-y-3">
                <table className="w-full text-[13px]">
                  <thead><tr className="text-left text-xs text-muted"><th className="px-2 py-1 font-medium">{t('intel.trace.hop')}</th><th className="px-2 py-1 font-medium">{t('intel.trace.addr')}</th><th className="px-2 py-1 font-medium">{t('intel.trace.owner')}</th><th className="px-2 py-1 text-right font-medium">{t('intel.trace.rtt')}</th></tr></thead>
                  <tbody>
                    {r.hops.map((h) => (
                      <tr key={h.ttl} className="border-t border-line/60">
                        <td className="tnum px-2 py-1.5">{h.ttl}</td>
                        <td className="px-2 py-1.5 font-mono text-[12px]">{h.addr ?? <span className="text-muted">{t('intel.trace.silent')}</span>}</td>
                        <td className="px-2 py-1.5 text-muted">{h.owner ? `${h.owner} · AS${h.asn}` : ''}</td>
                        <td className="tnum px-2 py-1.5 text-right">{h.rtt_ms.length ? h.rtt_ms.map((x) => x.toFixed(1)).join(' / ') : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className={`text-[13px] ${r.reached ? 'text-green' : 'text-amber'}`}>{r.reached ? t('intel.trace.reached') : t('intel.trace.notReached')}</p>
                <p className="text-xs text-muted">{t('intel.trace.note')}</p>
              </div>
            )
          }}
        </Active>
      )}
      {cur === 'tls' && (
        <Active kind="tls" target={target} extra="">
          {(env) => {
            const r = env.data as unknown as TLSRes
            return (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone={r.verified ? 'green' : 'amber'}>{r.verified ? t('intel.tls.verified') : `${t('intel.tls.notVerified')}: ${t(`intel.tls.verify.${r.verify_error ?? 'invalid'}` as MsgKey)}`}</Chip>
                  <span className="text-xs text-muted">{r.address}:{r.port}</span>
                </div>
                <dl>
                  <Row k={t('intel.tls.version')}>{r.version}</Row>
                  <Row k={t('intel.tls.cipher')}>{r.cipher}</Row>
                  {r.alpn && <Row k={t('intel.tls.alpn')}>{r.alpn}</Row>}
                  <Row k={t('intel.tls.handshake')}>{r.handshake_ms} мс</Row>
                </dl>
                <h3 className="text-[13px] font-medium">{t('intel.tls.chain')}</h3>
                {r.chain.map((c, i) => (
                  <div key={i} className="rounded-control border border-line p-3">
                    <dl>
                      <Row k={t('intel.tls.subject')}>{c.subject}</Row>
                      <Row k={t('intel.tls.issuer')}>{c.issuer}</Row>
                      <Row k={t('intel.tls.valid')}>{c.not_before.slice(0, 10)} — {c.not_after.slice(0, 10)} · {t('intel.tls.left', { n: c.days_left })}</Row>
                      <Row k={t('intel.tls.key')}>{c.key_type} · {c.sig_alg}</Row>
                      {c.dns_names && c.dns_names.length > 0 && <Row k={t('intel.tls.names')}><span className="font-mono text-[12px]">{c.dns_names.join(' · ')}</span></Row>}
                    </dl>
                  </div>
                ))}
              </div>
            )
          }}
        </Active>
      )}
      {cur === 'http' && <HTTPTab target={target} />}
      {cur === 'ports' && (
        <div className="space-y-3">
          <input aria-label={t('intel.ports.input')} className={`${inputCls} max-w-xs`} value={ports} onChange={(e) => setPorts(e.target.value)} placeholder={t('intel.ports.input')} />
          <Active kind="ports" target={target} extra={`&ports=${encodeURIComponent(ports)}`}>
            {(env) => {
              const p = env.data as unknown as PortsRes
              return (
                <div className="space-y-3">
                  <table className="text-[13px]"><tbody>
                    {p.results.map((r) => (
                      <tr key={r.port} className="border-t border-line/60"><td className="tnum px-2 py-1.5 font-medium">{r.port}</td>
                        <td className={`px-2 py-1.5 ${r.open ? 'text-green' : 'text-muted'}`}>{r.open ? `${t('intel.ports.open')}${r.ms ? ` · ${r.ms} мс` : ''}` : t(`intel.ports.${r.error ?? 'unreachable'}` as MsgKey)}</td></tr>
                    ))}
                  </tbody></table>
                  <p className="text-xs text-muted">{t('intel.ports.note')} ({p.address})</p>
                </div>
              )
            }}
          </Active>
        </div>
      )}
    </Card>
  )
}

function HTTPTab({ target }: { target: string }) {
  const [scheme, setScheme] = useState('https')
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[13px]">
        <label htmlFor="intel-scheme" className="text-muted">{t('intel.http.scheme')}</label>
        <select id="intel-scheme" className={`${inputCls} w-28`} value={scheme} onChange={(e) => setScheme(e.target.value)}><option value="https">https</option><option value="http">http</option></select>
      </div>
      <Active kind="http" target={target} extra={`&scheme=${scheme}`}>
        {(env) => {
          const r = env.data as unknown as HTTPRes
          return (
            <div className="space-y-4">
              <p className="text-[13px]">{t('intel.http.final')}: <b className="tnum">{r.final_status}</b></p>
              <div>
                <h3 className="mb-1 text-[13px] font-medium">{t('intel.http.hops')}</h3>
                <ol className="space-y-1 text-[13px]">
                  {r.hops.map((h, i) => <li key={i} className="break-all"><span className="tnum mr-2 font-medium">{h.status}</span>{h.url}{h.location ? <span className="text-muted"> → {h.location}</span> : null}<span className="ml-2 text-xs text-muted">{h.ms} мс · {h.proto}{h.tls ? ` · ${h.tls}` : ''}</span></li>)}
                </ol>
              </div>
              <div>
                <h3 className="mb-1 text-[13px] font-medium">{t('intel.http.security')}</h3>
                <ul className="flex flex-wrap gap-2 text-xs">{Object.entries(r.security).map(([k, v]) => <li key={k}><Chip tone={v ? 'green' : 'muted'}>{k}: {v ? t('intel.http.present') : t('intel.http.absent')}</Chip></li>)}</ul>
              </div>
              <details>
                <summary className="cursor-pointer text-[13px] text-muted">{t('intel.http.headers')}</summary>
                <dl className="mt-2">{Object.entries(r.hops[r.hops.length - 1].headers).map(([k, v]) => <Row key={k} k={k}><span className="break-all font-mono text-[12px]">{v}</span></Row>)}</dl>
              </details>
              <p className="text-xs text-muted">{t('intel.http.note')}</p>
            </div>
          )
        }}
      </Active>
    </div>
  )
}

function DNSTab({ target }: { target: string }) {
  const [nonce, setNonce] = useState(0)
  const q = useIntel<DNSRecords>('dns', target, nonce ? '&refresh=1' : '', nonce, true)
  return <Result q={q} refresh={() => setNonce((n) => n + 1)}>{(env) => <DNSView d={env.data as DNSRecords} />}</Result>
}

function SubTab({ target }: { target: string }) {
  const [nonce, setNonce] = useState(0)
  const q = useIntel<SubList>('subdomains', target, nonce ? '&refresh=1' : '', nonce, true)
  return (
    <Result q={q} refresh={() => setNonce((n) => n + 1)}>
      {(env) => {
        const s = env.data as SubList
        return (
          <div className="space-y-3">
            <p className="text-[13px]">{t('intel.sub.total', { n: formatInt(s.total) })}{s.truncated ? ` ${t('intel.sub.shown', { n: s.names.length })}` : ''}</p>
            <ul className="max-h-[420px] overflow-auto text-[13px] leading-6">{s.names.map((n) => <li key={n} className="font-mono"><Link className="hover:text-cyan hover:underline" to={`/intel?target=${encodeURIComponent(n)}`}>{n}</Link></li>)}</ul>
            <p className="text-xs text-muted">{t('intel.sub.note')}</p>
          </div>
        )
      }}
    </Result>
  )
}

export default function Intel() {
  const [params, setParams] = useSearchParams()
  const target = params.get('target') ?? ''
  const [text, setText] = useState(target)
  // The server validates and normalises the target; the kind it reports decides which tabs make sense.
  const probe = useLoad((s) => (target ? api.get<Envelope<unknown>>(`/api/v1/intel/lookup?target=${encodeURIComponent(target)}`, s) : Promise.resolve(null)), [target])
  const kind = probe.data?.kind ?? ''

  return (
    <div className="space-y-5">
      <PageHead title={t('intel.title')} subtitle={t('intel.subtitle')} />
      <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); const v = text.trim(); if (v) setParams({ target: v }) }}>
        <input aria-label={t('intel.placeholder')} className={`${inputCls} min-w-[260px] flex-1`} value={text} onChange={(e) => setText(e.target.value)} placeholder={t('intel.placeholder')} />
        <PrimaryButton type="submit">{t('intel.go')}</PrimaryButton>
      </form>
      {target && probe.error && <p role="alert" className="text-[13px] text-red">{probe.error}</p>}
      {target && kind && <Panels key={probe.data?.target} target={probe.data?.target ?? target} kind={kind} />}
      {!target && <p className="py-8 text-center text-[13px] text-muted">{t('intel.empty')}</p>}
    </div>
  )
}
