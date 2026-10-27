import { useEffect, useRef, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { Card } from './ui'
import { GhostButton, PrimaryButton } from './Modal'

type State = 'idle' | 'connecting' | 'open' | 'closed'

// Why the server closed the connection, in the person's words.
const REASON: Record<number, MsgKey> = { 4001: 'term.noAgent', 4002: 'term.notAllowed', 4003: 'term.noAnswer', 1008: 'term.forbidden' }

/** A terminal on the machine, through its agent. It opens on request, never by itself, and each session is recorded. */
export function TerminalView({ serverId }: { serverId: string }) {
  const box = useRef<HTMLDivElement>(null)
  const [state, setState] = useState<State>('idle')
  const [reason, setReason] = useState<MsgKey | ''>('')
  const [session, setSession] = useState(0)

  useEffect(() => {
    if (session === 0 || !box.current) return
    let disposed = false
    let cleanup = () => {}
    void (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([import('@xterm/xterm'), import('@xterm/addon-fit'), import('@xterm/xterm/css/xterm.css')])
      if (disposed || !box.current) return
      const term = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', theme: { background: '#0b0f14' }, scrollback: 5000 })
      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(box.current)
      fit.fit()
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      const ws = new WebSocket(`${proto}://${location.host}/api/v1/servers/${serverId}/terminal?cols=${term.cols}&rows=${term.rows}`)
      ws.binaryType = 'arraybuffer'
      const enc = new TextEncoder()
      ws.onopen = () => { setState('open'); term.focus() }
      ws.onmessage = (e) => { if (e.data instanceof ArrayBuffer) term.write(new Uint8Array(e.data)) }
      ws.onclose = (e) => {
        if (disposed) return
        setState('closed')
        setReason(REASON[e.code] ?? (e.code === 1000 ? 'term.ended' : 'term.lost'))
        term.write('\r\n')
      }
      const input = term.onData((d) => { if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d)) })
      const resized = term.onResize(({ cols, rows }) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols, rows })) })
      const ro = new ResizeObserver(() => { try { fit.fit() } catch { /* not laid out yet */ } })
      ro.observe(box.current)
      cleanup = () => { ro.disconnect(); input.dispose(); resized.dispose(); ws.close(); term.dispose() }
    })()
    return () => { disposed = true; cleanup() }
  }, [session, serverId])

  const start = () => { setReason(''); setState('connecting'); setSession((n) => n + 1) }
  return (
    <Card title={t('term.title')} note={t('term.note')}
      right={state === 'open' ? <GhostButton onClick={() => { setState('closed'); setReason('term.ended'); setSession(0) }}>{t('term.close')}</GhostButton> : undefined}>
      {state === 'idle' && <PrimaryButton onClick={start}>{t('term.open')}</PrimaryButton>}
      {state === 'connecting' && <p className="mb-2 text-[13px] text-muted" role="status">{t('term.connecting')}</p>}
      {state === 'closed' && (
        <div className="mb-3 flex flex-wrap items-center gap-3">
          {reason && <p className="text-[13px] text-muted" role="status">{t(reason)}</p>}
          <PrimaryButton onClick={start}>{t('term.reopen')}</PrimaryButton>
        </div>
      )}
      {session > 0 && <div ref={box} className="h-[60vh] min-h-[320px] overflow-hidden rounded-control border border-line bg-[#0b0f14] p-2" />}
    </Card>
  )
}
