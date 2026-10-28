import { useEffect, useRef, useState } from 'react'
import { Maximize2, X } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { Card } from './ui'
import { PrimaryButton } from './Modal'
import { ScreenFiles, sendFile } from './ScreenFiles'
import { FsClient, joinPath } from '../lib/screenfs'

type State = 'idle' | 'connecting' | 'open' | 'closed'
type Monitor = { w: number; h: number; primary: boolean }

// Why the server closed the connection, in the person's words.
const REASON: Record<number, MsgKey> = { 4001: 'scr.noAgent', 4002: 'scr.notAllowed', 4003: 'scr.noAnswer', 4004: 'scr.noHelper', 1008: 'scr.forbidden' }

// The machine's helper speaks [1 byte type][4 bytes big-endian length][payload] in both directions (see package remotehelper).
const MSG_FRAME = 1
const MSG_MOUSE = 2
const MSG_KEY = 3
const MSG_ERROR = 4
const MSG_END = 5
const MSG_VIDEO = 6 // [flag: 1 = a picture a decoder can start from][one H.264 picture, Annex B]
const MSG_MONITORS = 7 // JSON {list: [{w, h, primary}], current}
const MSG_SELECT = 8 // one byte: the monitor to show
const MSG_QUALITY = 9 // one byte: 0 auto, 1 high, 2 medium, 3 low
const MSG_COMBO = 10 // one byte: 1 Win, 2 Alt+Tab, 3 Ctrl+Alt+Del
const MSG_TEXT = 11 // UTF-8 text to type

function message(type: number, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(5 + payload.length)
  out[0] = type
  new DataView(out.buffer).setUint32(1, payload.length)
  out.set(payload, 5)
  return out
}

const btn = 'h-7 shrink-0 rounded-control border border-line bg-elevated px-2.5 text-xs text-fg hover:border-cyan'

/**
 * The screen of the person at the machine, live, with mouse and keyboard, filling the window with a bar of controls on
 * top. The person sees an icon in their tray for as long as this is open and can end it from its menu; opening and
 * closing are in the audit log, the picture is not recorded.
 */
export function ScreenView({ serverId }: { serverId: string }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const box = useRef<HTMLDivElement>(null)
  const view = useRef<HTMLDivElement>(null)
  const sender = useRef<(type: number, payload: Uint8Array) => void>(() => {})
  const [state, setState] = useState<State>('idle')
  const [reason, setReason] = useState('')
  const [session, setSession] = useState(0)
  const [monitors, setMonitors] = useState<Monitor[]>([])
  const [monitor, setMonitor] = useState(0)
  const fs = useRef<FsClient | null>(null)
  const pickFile = useRef<HTMLInputElement>(null)
  const [client, setClient] = useState<FsClient | null>(null) // the same client as fs, for rendering
  const [files, setFiles] = useState(false)
  const [transfer, setTransfer] = useState('')

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
    const finish = (key: string) => { if (!disposed) { setState('closed'); setReason(told || key); setSession(0) } }

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
      if (fs.current?.handle(type, p)) return
      if (type === MSG_VIDEO && p.length > 1) {
        video(p)
      } else if (type === MSG_MONITORS) {
        try {
          const m = JSON.parse(new TextDecoder().decode(p)) as { list: Monitor[]; current: number }
          setMonitors(m.list ?? [])
          setMonitor(m.current ?? 0)
        } catch { /* a list the page cannot read is left out */ }
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
    sender.current = send
    const fsc = new FsClient(send, () => ws.bufferedAmount)
    fs.current = fsc
    ws.onopen = () => setClient(fsc)
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
      sender.current = () => {}
      fs.current?.close()
      fs.current = null
      setClient(null)
      setFiles(false)
      setTransfer('')
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

  const start = () => { setReason(''); setState('connecting'); setMonitors([]); setMonitor(0); setSession((n) => n + 1) }
  const stop = () => { setState('closed'); setReason(t('scr.ended')); setSession(0) }
  const combo = (id: number) => { sender.current(MSG_COMBO, new Uint8Array([id])); box.current?.focus() }
  const pasteText = async () => {
    const text = await navigator.clipboard.readText().catch(() => window.prompt(t('scr.pasteAsk')) ?? '')
    if (text) sender.current(MSG_TEXT, new TextEncoder().encode(text.slice(0, 4000)))
    box.current?.focus()
  }
  // "Файл": the page sends one file into the person's Downloads folder, without opening the file browser.
  const sendOne = async (f: File) => {
    const client = fs.current
    if (!client) return
    setTransfer(t('scr.progress', { n: f.name, p: '0' }))
    try {
      const home = (await client.list('')).home
      if (!home) throw new Error(t('scr.noHome'))
      await sendFile(client, f, joinPath(home, f.name), (p) => setTransfer(t('scr.progress', { n: f.name, p: String(p) })))
      setTransfer(t('scr.sent', { n: f.name }))
    } catch (e) {
      setTransfer(e instanceof Error ? e.message : String(e))
    }
  }
  return (
    <>
      <Card title={t('scr.title')} note={t('scr.note')}>
        {state === 'closed' && reason && <p className="mb-3 text-[13px] text-muted" role="status">{reason}</p>}
        <PrimaryButton onClick={start}>{state === 'closed' ? t('scr.reopen') : t('scr.open')}</PrimaryButton>
      </Card>
      {session > 0 && (
        <div ref={view} className="fixed inset-0 z-50 flex flex-col bg-black">
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-surface px-2 py-1.5">
            <span className="text-xs font-semibold text-cyan">{t('scr.title')}</span>
            {monitors.length > 0 && (
              <select aria-label={t('scr.monitor')} className={btn} value={monitor}
                onChange={(e) => { const i = Number(e.target.value); setMonitor(i); sender.current(MSG_SELECT, new Uint8Array([i])); box.current?.focus() }}>
                {monitors.map((m, i) => <option key={i} value={i}>{t('scr.monitorN', { n: String(i + 1), w: String(m.w), h: String(m.h) })}</option>)}
              </select>
            )}
            <select aria-label={t('scr.quality')} className={btn} defaultValue="0"
              onChange={(e) => { sender.current(MSG_QUALITY, new Uint8Array([Number(e.target.value)])); box.current?.focus() }}>
              <option value="0">{t('scr.q.auto')}</option>
              <option value="1">{t('scr.q.high')}</option>
              <option value="2">{t('scr.q.mid')}</option>
              <option value="3">{t('scr.q.low')}</option>
            </select>
            <button type="button" className={btn} onClick={() => combo(3)}>Ctrl+Alt+Del</button>
            <button type="button" className={btn} onClick={() => combo(1)}>Win</button>
            <button type="button" className={btn} onClick={() => combo(2)}>Alt+Tab</button>
            <button type="button" className={btn} onClick={() => void pasteText()}>{t('scr.paste')}</button>
            <button type="button" className={btn} onClick={() => pickFile.current?.click()}>{t('scr.file')}</button>
            <input ref={pickFile} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void sendOne(f) }} />
            <button type="button" className={btn} onClick={() => setFiles((v) => !v)}>{t('scr.files')}</button>
            <button type="button" className={btn} aria-label={t('desk.full')} onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : view.current?.requestFullscreen())}><Maximize2 size={13} aria-hidden /></button>
            <span className="ml-auto text-xs text-muted" role="status">{state === 'connecting' ? t('scr.connecting') : transfer}</span>
            <button type="button" className="h-7 rounded-control border border-line px-2 text-fg hover:border-red" aria-label={t('scr.close')} onClick={stop}><X size={14} aria-hidden /></button>
          </div>
          <div ref={box} tabIndex={0} className="relative flex min-h-0 flex-1 items-center justify-center overflow-hidden outline-none">
            {files && client && <ScreenFiles fs={client} onClose={() => setFiles(false)} />}
            <canvas ref={canvas} className="max-h-full max-w-full cursor-default object-contain" />
          </div>
        </div>
      )}
    </>
  )
}
