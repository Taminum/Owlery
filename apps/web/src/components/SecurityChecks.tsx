import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { PublicPort, PublicPortsResponse, TLSEndpoint, TLSResponse, Vantage } from '../lib/types'
import { Card, Chip } from './ui'
import { Field, GhostButton, PrimaryButton, inputCls } from './Modal'

type Tone = 'muted' | 'amber' | 'green' | 'red' | 'cyan'

/** The checker's point of view, always on screen: a result without it would read as more than it is. */
/** Says where the checks were made from. A result from the RemnaScope server is not an independent point of
 *  view, and a result from a checker on another machine is: each endpoint carries its own. */
function VantageNote({ items }: { items: { vantage: Vantage | null; last_checked_at: string | null }[] }) {
  const checked = items.filter((i) => i.last_checked_at)
  const independent = [...new Set(checked.filter((i) => i.vantage?.independent).map((i) => i.vantage!.name || i.vantage!.id))]
  const warn = checked.length === 0 || checked.some((i) => !i.vantage?.independent)
  return (
    <>
      {independent.length > 0 && <p role="note" className="mb-3 rounded-control border border-green/40 px-3 py-2 text-[13px] text-green">{t('sec.ext.vantage.agent', { name: independent.join(', ') })}</p>}
      {warn && <p role="note" className="mb-3 rounded-control border border-amber/40 px-3 py-2 text-[13px] text-amber">{t('sec.ext.vantage')}</p>}
    </>
  )
}

const PORT_TONE: Record<string, Tone> = { reachable: 'green', refused: 'muted', timeout: 'amber', filtered_or_unknown: 'amber', error: 'muted' }

function PortResult({ p }: { p: PublicPort }) {
  if (!p.last_result) return <span className="text-muted">—</span>
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Chip tone={PORT_TONE[p.last_result] ?? 'muted'}>{t(`sec.ext.res.${p.last_result}` as MsgKey)}</Chip>
      {p.last_result === 'error' && p.last_error && <span className="text-xs text-muted">{t(`sec.ext.err.${p.last_error}` as MsgKey)}</span>}
      {p.last_ip && <span className="font-mono text-xs text-muted">{p.last_ip}</span>}
    </span>
  )
}

function RunNow({ vpsId, kind, onDone }: { vpsId: string; kind: 'ports' | 'tls'; onDone: () => void }) {
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  async function run() {
    setErr('')
    setMsg('')
    try {
      await api.post(`/api/v1/security/vps/${vpsId}/checks/${kind}/run`)
      setMsg(t('sec.ext.runSent'))
      window.setTimeout(onDone, 4000)
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <div className="flex flex-wrap items-center gap-3">
      <GhostButton onClick={() => void run()}>{t('sec.ext.runNow')}</GhostButton>
      {msg && <span role="status" className="text-[13px] text-muted">{msg}</span>}
      {err && <span role="alert" className="text-[13px] text-red">{err}</span>}
    </div>
  )
}

function AddPort({ vpsId, onDone }: { vpsId: string; onDone: () => void }) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [expected, setExpected] = useState(true)
  const [err, setErr] = useState('')
  async function save() {
    setErr('')
    try {
      await api.post(`/api/v1/security/vps/${vpsId}/public-ports`, { host: host.trim(), port: Number(port), expected })
      setHost('')
      onDone()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); if (host.trim()) void save() }}>
      <Field label={t('sec.ext.host')} hint={t('sec.ext.addHint')} htmlFor="ext-host"><input id="ext-host" className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} spellCheck={false} /></Field>
      <Field label={t('sec.ext.port')} htmlFor="ext-port"><input id="ext-port" className={`${inputCls} w-24`} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></Field>
      <label className="flex h-10 items-center gap-2 text-[13px]"><input type="checkbox" checked={expected} onChange={(e) => setExpected(e.target.checked)} />{t('sec.ext.expectedLabel')}</label>
      <PrimaryButton type="submit" disabled={!host.trim()}>{t('sec.ext.add')}</PrimaryButton>
      {err && <p role="alert" className="w-full text-[13px] text-red">{err}</p>}
    </form>
  )
}

export function PublicPorts({ vpsId, canEdit }: { vpsId: string; canEdit: boolean }) {
  const { data, error, reload } = useLoad((s) => api.get<PublicPortsResponse>(`/api/v1/security/vps/${vpsId}/public-ports`, s), [vpsId], 30_000)
  const [err, setErr] = useState('')
  async function patch(p: PublicPort, body: { expected?: boolean; enabled?: boolean }) {
    setErr('')
    try {
      await api.patch(`/api/v1/security/vps/${vpsId}/public-ports/${p.id}`, body)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return null
  return (
    <Card title={t('sec.ext.title')} note={t('sec.ext.coverage', { n: data.interval_minutes })}
      right={canEdit ? <RunNow vpsId={vpsId} kind="ports" onDone={reload} /> : undefined}>
      <VantageNote items={data.items} />
      {err && <p role="alert" className="mb-2 text-[13px] text-red">{err}</p>}
      {data.items.length === 0 && <p className="text-[13px] text-muted">{t('sec.ext.none')}</p>}
      {data.items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-xs text-muted"><th className="py-2 pr-4 font-medium">{t('sec.ext.host')}</th><th className="pr-4 font-medium">{t('sec.ext.port')}</th><th className="pr-4 font-medium">{t('sec.ext.expected')}</th><th className="pr-4 font-medium">{t('sec.ext.result')}</th><th className="font-medium">{t('sec.ext.checked')}</th></tr></thead>
            <tbody>
              {data.items.map((p) => (
                <tr key={p.id} className={`border-t border-line align-top ${p.enabled ? '' : 'opacity-50'}`}>
                  <td className="py-2 pr-4 font-mono text-[12px]">{p.host}<div className="font-sans text-xs text-muted">{t(`sec.ext.source.${p.source}` as MsgKey)}{p.enabled ? '' : ` · ${t('sec.ext.disabled')}`}</div></td>
                  <td className="tnum pr-4">{p.port}</td>
                  <td className="pr-4">
                    {canEdit
                      ? <input type="checkbox" aria-label={`${t('sec.ext.expected')}: ${p.host}:${p.port}`} checked={p.expected} onChange={(e) => void patch(p, { expected: e.target.checked })} />
                      : (p.expected ? '✓' : <span className="text-muted">{t('sec.ext.unexpected')}</span>)}
                  </td>
                  <td className="pr-4"><PortResult p={p} /></td>
                  <td className="tnum text-xs text-muted">{p.last_checked_at ? formatDateTime(p.last_checked_at, 'local') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canEdit && <AddPort vpsId={vpsId} onDone={reload} />}
    </Card>
  )
}

const TLS_TONE: Record<string, Tone> = { ok: 'green', expired: 'red', untrusted: 'amber', hostname_mismatch: 'amber', invalid: 'amber', handshake_error: 'amber', unreachable: 'muted', error: 'muted' }

function Expiry({ e }: { e: TLSEndpoint }) {
  const o = e.last_obs
  if (!e.last_not_after || o.days_left === undefined) return <span className="text-muted">—</span>
  const d = o.days_left
  const warn = d <= 30
  return (
    <span className={d < 0 ? 'text-red' : warn ? 'text-amber' : ''}>
      {formatDateTime(e.last_not_after, 'local')} <span className="text-xs">({d < 0 ? t('sec.tls.expiredAgo', { n: -d }) : t('sec.tls.daysLeft', { n: d })})</span>
    </span>
  )
}

function AddTLS({ vpsId, onDone }: { vpsId: string; onDone: () => void }) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [sni, setSni] = useState('')
  const [err, setErr] = useState('')
  async function save() {
    setErr('')
    try {
      await api.post(`/api/v1/security/vps/${vpsId}/tls`, { host: host.trim(), port: Number(port), sni: sni.trim() })
      setHost('')
      setSni('')
      onDone()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  return (
    <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); if (host.trim()) void save() }}>
      <Field label={t('sec.ext.host')} hint={t('sec.ext.addHint')} htmlFor="tls-host"><input id="tls-host" className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} spellCheck={false} /></Field>
      <Field label={t('sec.ext.port')} htmlFor="tls-port"><input id="tls-port" className={`${inputCls} w-24`} value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></Field>
      <Field label={t('sec.tls.sni')} hint={t('sec.tls.sniHint')} htmlFor="tls-sni"><input id="tls-sni" className={inputCls} value={sni} onChange={(e) => setSni(e.target.value)} spellCheck={false} /></Field>
      <PrimaryButton type="submit" disabled={!host.trim()}>{t('sec.tls.add')}</PrimaryButton>
      {err && <p role="alert" className="w-full text-[13px] text-red">{err}</p>}
    </form>
  )
}

export function TLSTab({ vpsId, canEdit }: { vpsId: string; canEdit: boolean }) {
  const { data, error, reload } = useLoad((s) => api.get<TLSResponse>(`/api/v1/security/vps/${vpsId}/tls`, s), [vpsId], 30_000)
  const [err, setErr] = useState('')
  async function toggle(e: TLSEndpoint) {
    setErr('')
    try {
      await api.patch(`/api/v1/security/vps/${vpsId}/tls/${e.id}`, { enabled: !e.enabled })
      reload()
    } catch (x) {
      setErr(errorText(x))
    }
  }
  if (error) return <p role="alert" className="text-[13px] text-red">{error}</p>
  if (!data) return null
  return (
    <Card title={t('sec.tls.title')} note={t('sec.tls.hint', { n: data.interval_hours })} right={canEdit ? <RunNow vpsId={vpsId} kind="tls" onDone={reload} /> : undefined}>
      <VantageNote items={data.items} />
      {err && <p role="alert" className="mb-2 text-[13px] text-red">{err}</p>}
      {data.items.length === 0 && <p className="text-[13px] text-muted">{t('sec.tls.none')}</p>}
      {data.items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-xs text-muted"><th className="py-2 pr-4 font-medium">{t('sec.ext.host')}</th><th className="pr-4 font-medium">{t('sec.ext.result')}</th><th className="pr-4 font-medium">{t('sec.tls.expires')}</th><th className="pr-4 font-medium">{t('sec.tls.issuer')}</th><th className="font-medium">{t('sec.ext.checked')}</th></tr></thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} className={`border-t border-line align-top ${e.enabled ? '' : 'opacity-50'}`}>
                  <td className="py-2 pr-4 font-mono text-[12px]">{e.host}:{e.port}
                    <div className="font-sans text-xs text-muted">{e.sni ? `SNI ${e.sni}` : t('sec.tls.nameUnchecked')}{e.enabled ? '' : ` · ${t('sec.ext.disabled')}`}{e.source === 'auto' ? ` · ${t('sec.tls.auto')}` : ''}</div>
                    {canEdit && <button type="button" className="font-sans text-xs text-muted underline hover:text-fg" onClick={() => void toggle(e)}>{e.enabled ? t('sec.ext.disable') : t('sec.ext.enable')}</button>}
                  </td>
                  <td className="pr-4">{e.last_state ? <Chip tone={TLS_TONE[e.last_state] ?? 'muted'}>{t(`sec.tls.state.${e.last_state}` as MsgKey)}</Chip> : <span className="text-muted">{t('sec.tls.unchecked')}</span>}</td>
                  <td className="pr-4"><Expiry e={e} /></td>
                  <td className="pr-4 text-xs text-muted">{e.last_obs.issuer ?? '—'}</td>
                  <td className="tnum text-xs text-muted">{e.last_checked_at ? formatDateTime(e.last_checked_at, 'local') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canEdit && <AddTLS vpsId={vpsId} onDone={reload} />}
    </Card>
  )
}
