import { useEffect, useRef, useState } from 'react'
import { Maximize2 } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { Card } from './ui'
import { GhostButton, PrimaryButton } from './Modal'

type State = 'idle' | 'connecting' | 'open' | 'closed'

// Why the server closed the connection, in the person's words.
const REASON: Record<number, MsgKey> = { 4001: 'scr.noAgent', 4002: 'scr.notAllowed', 4003: 'scr.noAnswer', 4004: 'scr.noHelper', 1008: 'scr.forbidden' }

// The machine's helper speaks [1 byte type][4 bytes big-endian length][payload] in both directions (see package remotehelper).
const MSG_FRAME = 1
const MSG_MOUSE = 2
const MSG_KEY = 3
const MSG_ERROR = 4
const MSG_END = 5
const MSG_VIDEO = 6 // [flag: 1 = a picture a decoder can start from][one H.264 picture, Annex B]

function message(type: number, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(5 + payload.length)
  out[0] = type
  new DataView(out.buffer).setUint32(1, payload.length)
  out.set(payload, 5)
  return out
}

/**
 * The screen of the person at the machine, live, with mouse and keyboard. The person sees an icon in their tray for
 * as long as this is open and can end it from its menu; opening and closing are in the audit log, the picture is not
 * recorded.
 */
export function ScreenView({ serverId }: { serverId: string }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const box = useRef<HTMLDivElement>(null)
  const [state, setState] = useState<State>('idle')
  const [reason, setReason] = useState('')
  const [session, setSession] = useState(0)

  useEffect(() => {
    const cv = canvas.current
    if (session === 0 || !cv) return
    let disposed = false
    const ctx = cv.getContext('2d')
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/api/v1/servers/${serverId}/screen`)
    ws.binaryType = 'arraybuffer'
    let buf = new Uint8Array(0)
    let told = '' // the helper's own explanation, shown when the connection ends
    let drawing = Promise.resolve()
    const finish = (key: string) => { if (!disposed) { setState('closed'); setReason(told || key) } }

    // H.264 goes through the browser's own decoder (hardware where there is one); the still pictures are the fallback of
    // a machine without a video encoder.
    let decoder: VideoDecoder | null = null
    let needKey = true
    const shown = () => setState((s) => (s === 'connecting' ? 'open' : s))
    const video = (p: Uint8Array) => {
      if (typeof VideoDecoder === 'undefined') { told = t('scr.noCodec'); ws.close(); return }
      const key = p[0] === 1
      if (!decoder || decoder.state === 'closed') {
        decoder = new VideoDecoder({
          output: (f) => {
            if (!disposed) {
              if (cv.width !== f.displayWidth || cv.height !== f.displayHeight) { cv.width = f.displayWidth; cv.height = f.displayHeight }
              ctx?.drawImage(f, 0, 0)
              shown()
            }
            f.close()
          },
          error: () => { needKey = true },
        })
        // Baseline profile, Annex B: what the helper's encoder writes.
        decoder.configure({ codec: 'avc1.42E028', optimizeForLatency: true, avc: { format: 'annexb' } } as VideoDecoderConfig)
        needKey = true
      }
      if (needKey && !key) return
      if (decoder.decodeQueueSize > 8 && !key) return // the decoder is behind: wait for the next picture it can restart from
      needKey = false
      try { decoder.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: performance.now() * 1000, data: p.subarray(1) })) } catch { needKey = true }
    }
    const handle = (type: number, p: Uint8Array) => {
      if (type === MSG_VIDEO && p.length > 1) {
        video(p)
      } else if (type === MSG_FRAME && p.length > 4) {
        const dv = new DataView(p.buffer, p.byteOffset, p.byteLength)
        const w = dv.getUint16(0)
        const h = dv.getUint16(2)
        const jpg = p.slice(4)
        drawing = drawing.then(async () => {
          try {
            const bmp = await createImageBitmap(new Blob([jpg as BlobPart], { type: 'image/jpeg' }))
            if (disposed) return
            if (cv.width !== w || cv.height !== h) { cv.width = w; cv.height = h }
            ctx?.drawImage(bmp, 0, 0)
            bmp.close()
            shown()
          } catch { /* a broken frame is skipped */ }
        })
      } else if (type === MSG_ERROR) {
        told = new TextDecoder().decode(p)
      } else if (type === MSG_END) {
        told = t('scr.stopped')
      }
    }
    ws.onmessage = (e) => {
      if (!(e.data instanceof ArrayBuffer)) return
      const add = new Uint8Array(e.data)
      const joined = new Uint8Array(buf.length + add.length)
      joined.set(buf)
      joined.set(add, buf.length)
      buf = joined
      while (buf.length >= 5) {
        const len = new DataView(buf.buffer, buf.byteOffset).getUint32(1)
        if (len > 16 << 20) { ws.close(); return }
        if (buf.length < 5 + len) break
        handle(buf[0], buf.slice(5, 5 + len))
        buf = buf.slice(5 + len)
      }
    }
    ws.onclose = (e) => finish(e.code in REASON ? t(REASON[e.code]) : e.code === 1000 ? t('scr.ended') : t('scr.lost'))

    const send = (type: number, payload: Uint8Array) => { if (ws.readyState === WebSocket.OPEN) ws.send(message(type, payload)) }
    let buttons = 0
    const mouse = (e: PointerEvent | WheelEvent, wheel: number) => {
      const r = cv.getBoundingClientRect()
      const x = Math.min(65535, Math.max(0, Math.round(((e.clientX - r.left) / r.width) * 65535)))
      const y = Math.min(65535, Math.max(0, Math.round(((e.clientY - r.top) / r.height) * 65535)))
      const p = new Uint8Array(7)
      const dv = new DataView(p.buffer)
      dv.setUint16(0, x)
      dv.setUint16(2, y)
      p[4] = buttons
      dv.setInt16(5, wheel)
      send(MSG_MOUSE, p)
    }
    const bit = (b: number) => (b === 0 ? 1 : b === 2 ? 2 : b === 1 ? 4 : 0)
    const onMove = (e: PointerEvent) => mouse(e, 0)
    const onDown = (e: PointerEvent) => { cv.setPointerCapture(e.pointerId); box.current?.focus(); buttons |= bit(e.button); mouse(e, 0) }
    const onUp = (e: PointerEvent) => { buttons &= ~bit(e.button); mouse(e, 0) }
    const onWheel = (e: WheelEvent) => { e.preventDefault(); mouse(e, e.deltaY > 0 ? -1 : 1) }
    const onMenu = (e: Event) => e.preventDefault()
    cv.addEventListener('pointermove', onMove)
    cv.addEventListener('pointerdown', onDown)
    cv.addEventListener('pointerup', onUp)
    cv.addEventListener('wheel', onWheel, { passive: false })
    cv.addEventListener('contextmenu', onMenu)

    // Keys go to the machine only while the screen has focus, so the rest of the page keeps its keyboard.
    const host = box.current
    const key = (down: boolean) => (e: KeyboardEvent) => {
      e.preventDefault()
      const code = new TextEncoder().encode(e.code)
      if (code.length === 0 || code.length > 40) return
      const p = new Uint8Array(2 + code.length)
      p[0] = down ? 1 : 0
      p[1] = code.length
      p.set(code, 2)
      send(MSG_KEY, p)
    }
    const kd = key(true)
    const ku = key(false)
    host?.addEventListener('keydown', kd)
    host?.addEventListener('keyup', ku)
    host?.focus()

    return () => {
      disposed = true
      cv.removeEventListener('pointermove', onMove)
      cv.removeEventListener('pointerdown', onDown)
      cv.removeEventListener('pointerup', onUp)
      cv.removeEventListener('wheel', onWheel)
      cv.removeEventListener('contextmenu', onMenu)
      host?.removeEventListener('keydown', kd)
      host?.removeEventListener('keyup', ku)
      ws.close()
      if (decoder && decoder.state !== 'closed') decoder.close()
    }
  }, [session, serverId])

  const start = () => { setReason(''); setState('connecting'); setSession((n) => n + 1) }
  const stop = () => { setState('closed'); setReason(t('scr.ended')); setSession(0) }
  return (
    <Card title={t('scr.title')} note={t('scr.note')}
      right={state !== 'idle' && state !== 'closed' ? (
        <div className="flex gap-2">
          <GhostButton onClick={() => void box.current?.requestFullscreen()}><Maximize2 size={14} aria-hidden /> {t('desk.full')}</GhostButton>
          <GhostButton onClick={stop}>{t('scr.close')}</GhostButton>
        </div>) : undefined}>
      {state === 'idle' && <PrimaryButton onClick={start}>{t('scr.open')}</PrimaryButton>}
      {state === 'connecting' && <p className="mb-2 text-[13px] text-muted" role="status">{t('scr.connecting')}</p>}
      {state === 'closed' && (
        <div className="mb-3 flex flex-wrap items-center gap-3">
          {reason && <p className="text-[13px] text-muted" role="status">{reason}</p>}
          <PrimaryButton onClick={start}>{t('scr.reopen')}</PrimaryButton>
        </div>
      )}
      {session > 0 && (
        <div ref={box} tabIndex={0} className="flex min-h-[320px] items-center justify-center overflow-hidden rounded-control border border-line bg-black outline-none focus:border-cyan">
          <canvas ref={canvas} className="max-h-[75vh] max-w-full cursor-default" />
        </div>
      )}
    </Card>
  )
}
