import { useEffect, useRef, useState } from 'react'
import { Maximize2 } from 'lucide-react'
import type Guacamole from 'guacamole-common-js'
import { t } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { Card } from './ui'
import { Field, GhostButton, PrimaryButton, inputCls } from './Modal'

type Login = { protocol: 'rdp' | 'vnc'; username: string; password: string; domain: string }

/**
 * The machine's own desktop, through its agent and guacd. The login is asked for each time and never kept: the page
 * trades it for a one-use ticket, and only the ticket goes into the WebSocket address.
 */
export function DesktopView({ serverId }: { serverId: string }) {
  const [login, setLogin] = useState<Login>({ protocol: 'rdp', username: '', password: '', domain: '' })
  const [ticket, setTicket] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function connect() {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ ticket: string }>(`/api/v1/servers/${serverId}/desktop`, login)
      setLogin((l) => ({ ...l, password: '' }))
      setTicket(r.ticket)
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (ticket) return <Screen serverId={serverId} ticket={ticket} onClose={(msg) => { setTicket(''); setError(msg) }} />
  return (
    <Card title={t('desk.title')} note={t('desk.note')}>
      <form className="grid max-w-xl gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); if (!busy) void connect() }}>
        <Field label={t('desk.protocol')} htmlFor="desk-proto">
          <select id="desk-proto" className={inputCls} value={login.protocol} onChange={(e) => setLogin({ ...login, protocol: e.target.value as Login['protocol'] })}>
            <option value="rdp">RDP (Windows)</option>
            <option value="vnc">VNC</option>
          </select>
        </Field>
        {login.protocol === 'rdp' && (
          <Field label={t('desk.domain')} htmlFor="desk-domain"><input id="desk-domain" className={inputCls} value={login.domain} onChange={(e) => setLogin({ ...login, domain: e.target.value })} autoComplete="off" /></Field>
        )}
        {login.protocol === 'rdp' && (
          <Field label={t('desk.user')} htmlFor="desk-user"><input id="desk-user" className={inputCls} value={login.username} onChange={(e) => setLogin({ ...login, username: e.target.value })} autoComplete="username" /></Field>
        )}
        <Field label={t('desk.password')} htmlFor="desk-pass"><input id="desk-pass" type="password" className={inputCls} value={login.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} autoComplete="current-password" /></Field>
        {error && <p role="alert" className="text-[13px] text-red sm:col-span-2">{error}</p>}
        <div className="sm:col-span-2"><PrimaryButton type="submit" disabled={busy}>{t('desk.connect')}</PrimaryButton></div>
        <p className="text-xs text-muted sm:col-span-2">{t('desk.hint')}</p>
      </form>
    </Card>
  )
}

function Screen({ serverId, ticket, onClose }: { serverId: string; ticket: string; onClose: (msg: string) => void }) {
  const box = useRef<HTMLDivElement>(null)
  const [live, setLive] = useState(false)
  const closed = useRef(onClose)
  useEffect(() => { closed.current = onClose })

  useEffect(() => {
    const host = box.current
    if (!host) return
    let alive = true
    let cleanup = () => {}
    void (async () => {
      const { default: Guacamole } = await import('guacamole-common-js')
      if (!alive) return
      const rect = host.getBoundingClientRect()
      const width = Math.max(800, Math.round(rect.width))
      const height = Math.max(500, Math.round(rect.height))
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      // The library adds the connect data after a "?" itself, so the address has no query of its own.
      const tunnel = new Guacamole.WebSocketTunnel(`${proto}//${location.host}/api/v1/servers/${serverId}/desktop`)
      const client = new Guacamole.Client(tunnel)
      const display = client.getDisplay()
      const el = display.getElement()
      host.appendChild(el)
      const end = (msg: string) => { if (alive) { alive = false; closed.current(msg) } }
      client.onerror = (st) => end(st.message || t('desk.lost'))
      tunnel.onerror = (st) => end(st.message || t('desk.lost'))
      client.onstatechange = (s) => {
        if (s === 3) setLive(true)
        if (s === 5) end(t('desk.ended'))
      }
      const mouse = new Guacamole.Mouse(el)
      const send = (s: Guacamole.Mouse.State) => client.sendMouseState(s)
      mouse.onmousedown = send
      mouse.onmouseup = send
      mouse.onmousemove = send
      // Keys go to the machine only while the desktop has focus, so the rest of the page keeps its keyboard.
      const keyboard = new Guacamole.Keyboard(host)
      keyboard.onkeydown = (k) => { client.sendKeyEvent(1, k); return false }
      keyboard.onkeyup = (k) => client.sendKeyEvent(0, k)
      const ro = new ResizeObserver(() => {
        const r = host.getBoundingClientRect()
        if (r.width > 200 && r.height > 200) client.sendSize(Math.round(r.width), Math.round(r.height))
      })
      ro.observe(host)
      client.connect(`ticket=${encodeURIComponent(ticket)}&width=${width}&height=${height}&dpi=${Math.round(window.devicePixelRatio * 96)}`)
      host.focus()
      cleanup = () => { ro.disconnect(); keyboard.reset(); client.disconnect(); el.remove() }
    })()
    return () => { alive = false; cleanup() }
  }, [serverId, ticket])

  return (
    <Card title={t('desk.title')} right={
      <div className="flex gap-2">
        <GhostButton onClick={() => void box.current?.requestFullscreen()}><Maximize2 size={14} aria-hidden /> {t('desk.full')}</GhostButton>
        <GhostButton onClick={() => onClose('')}>{t('desk.close')}</GhostButton>
      </div>}>
      {!live && <p className="mb-2 text-[13px] text-muted" role="status">{t('desk.connecting')}</p>}
      <div ref={box} tabIndex={0} className="h-[70vh] min-h-[400px] overflow-hidden rounded-control border border-line bg-black outline-none focus:border-cyan" />
    </Card>
  )
}
