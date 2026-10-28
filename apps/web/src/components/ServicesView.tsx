import { useState } from 'react'
import { ExternalLink, Trash2 } from 'lucide-react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from './ui'
import { Field, PrimaryButton, inputCls } from './Modal'

interface WebService { id: string; slug: string; title: string; port: number }
interface ServicesResponse { services: WebService[]; domain: string; allowed: boolean; online: boolean }

// What the address may hold: Latin letters, digits and inner hyphens, as the server checks.
const slugOf = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)

/** Web services of the machine (admin panels on 127.0.0.1), each opened at its own address through the agent. */
export function ServicesView({ serverId, serverName }: { serverId: string; serverName: string }) {
  const q = useLoad((sig) => api.get<ServicesResponse>(`/api/v1/servers/${serverId}/services`, sig), [serverId])
  const [title, setTitle] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const d = q.data
  const autoSlug = slugOf(`${title}-${serverName}`)
  const effSlug = slugTouched ? slug : autoSlug

  async function add() {
    setBusy(true)
    setError('')
    try {
      await api.post(`/api/v1/servers/${serverId}/services`, { title: title.trim(), slug: effSlug, port: Number(port) })
      setTitle(''); setSlug(''); setSlugTouched(false); setPort('')
      q.reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }
  async function remove(id: string) {
    setError('')
    try {
      await api.del(`/api/v1/servers/${serverId}/services/${id}`)
      q.reload()
    } catch (e) {
      setError(errorText(e))
    }
  }

  return (
    <Card title={t('web.title')} note={t('web.note')}>
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {d && !d.domain && <p className="text-[13px] text-muted">{t('web.off')}</p>}
      {d && d.domain && (
        <div className="space-y-4">
          {!d.allowed && <p className="text-[13px] text-amber">{t('web.notAllowed')}</p>}
          {d.allowed && !d.online && <p className="text-[13px] text-amber">{t('web.offline')}</p>}
          {d.services.length === 0 ? <p className="text-[13px] text-muted">{t('web.empty')}</p> : (
            <ul className="divide-y divide-line">
              {d.services.map((s) => {
                const href = `https://${s.slug}.${d.domain}/`
                return (
                  <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 py-2 text-[13px]">
                    <span className="min-w-0">
                      <span className="font-medium text-fg">{s.title}</span>
                      <span className="ml-2 font-mono text-xs text-muted">127.0.0.1:{s.port}</span>
                      <span className="block truncate font-mono text-xs text-muted">{href}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      <a href={href} target="_blank" rel="noopener" className="inline-flex h-8 items-center gap-1.5 rounded-control border border-line px-3 text-[13px] text-fg hover:border-cyan">
                        <ExternalLink size={14} aria-hidden />{t('web.open')}
                      </a>
                      <button type="button" aria-label={`${t('web.remove')}: ${s.title}`} onClick={() => void remove(s.id)}
                        className="grid h-8 w-8 place-items-center rounded-control text-muted hover:bg-elevated hover:text-red"><Trash2 size={15} aria-hidden /></button>
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
          <form className="grid gap-3 border-t border-line pt-4 sm:grid-cols-[1fr_1fr_120px_auto] sm:items-end" onSubmit={(e) => { e.preventDefault(); if (!busy) void add() }}>
            <Field label={t('web.name')} htmlFor="web-title"><input id="web-title" className={inputCls} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={64} placeholder="Komodo" /></Field>
            <Field label={t('web.address')} htmlFor="web-slug">
              <input id="web-slug" className={`${inputCls} font-mono`} value={effSlug} onChange={(e) => { setSlugTouched(true); setSlug(slugOf(e.target.value)) }} maxLength={40} />
            </Field>
            <Field label={t('web.port')} htmlFor="web-port"><input id="web-port" className={inputCls} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} maxLength={5} placeholder="9120" /></Field>
            <PrimaryButton type="submit" disabled={busy || !title.trim() || !effSlug || !port}>{t('web.add')}</PrimaryButton>
            {effSlug && <p className="text-xs text-muted sm:col-span-4">{t('web.willOpen')} <span className="font-mono">https://{effSlug}.{d.domain}/</span></p>}
          </form>
          {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
          <p className="text-xs text-muted"><Chip tone="muted">{t('web.howBadge')}</Chip> {t('web.how')}</p>
        </div>
      )}
    </Card>
  )
}
