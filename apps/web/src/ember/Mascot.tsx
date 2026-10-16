import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { Link } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { Director, moodForAlert, type Mood } from './director'
import { MASCOT_SIZES, setKawaii, useKawaii } from './settings'

interface Cell { a: number; x: number; y: number }
interface Marker { name: string; atMs: number; origin?: { x: number; y: number }; count?: number }
interface Flight { releaseMs: number; endMs: number; origin: { x: number; y: number }; dx: number; dy: number; width: number; height: number }
interface Clip {
  frames: Cell[]; durationsMs: number[]; loop: boolean; markers: Marker[]; effect: boolean
  heart?: { texture: string; flight: Flight }
  interaction?: { type: string; introEndMs: number; waitLoopStartMs: number } // a scene that waits to be clicked
  wardrobe?: { holdFinal: boolean } // the scene ends in other clothes, and the last picture stays
}
interface Keyframe { x: number; y: number; rotation: number; opacity: number; offset: number }
interface Manifest {
  frameSize: { width: number; height: number }
  atlasSize: number
  poster: Cell
  clips: Record<string, Clip>
  projectile: { file: string; width: number; height: number }
  particleMotion: { widthPx: number; heightPx: number; durationMs: number; keyframes: Keyframe[] }
}
interface Phrases { clips: Record<string, string[]> }

const BASE = '/ember'
const MOOD_CLIP: Record<Mood, string> = { alert: 'alert', concerned: 'concerned', curious: 'curious', smug: 'smug', celebrate: 'celebrate', happy: 'happy', sleepy: 'sleepy' }

function pick<T>(xs: T[] | undefined): T | undefined {
  return xs && xs.length ? xs[Math.floor(Math.random() * xs.length)] : undefined
}

function subscribeReduced(cb: () => void): () => void {
  const mq = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null
  mq?.addEventListener?.('change', cb)
  return () => mq?.removeEventListener?.('change', cb)
}
function systemReducedNow(): boolean {
  return typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : false
}

function subscribeWidth(cb: () => void): () => void {
  window.addEventListener('resize', cb)
  return () => window.removeEventListener('resize', cb)
}
const narrowNow = () => window.innerWidth < 640

function typingNow(): boolean {
  const el = document.activeElement
  if (!el) return false
  const tag = el.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (el as HTMLElement).isContentEditable
}

interface AlertRow { id: string; kind: string; resolved_at: string | null }

/** The speech bubble: the text is typed out, a click finishes it and the next click closes it. Screen readers get
 *  the whole sentence at once. Remounted (by key) for every new sentence. */
function Bubble({ text, theme, reduced, onClose }: { text: string; theme: 'dark' | 'paper'; reduced: boolean; onClose: () => void }) {
  const [n, setN] = useState(() => (reduced ? text.length : 0))
  useEffect(() => {
    if (reduced) return
    const id = window.setInterval(() => setN((v) => (v >= text.length ? v : v + 1)), 25)
    return () => window.clearInterval(id)
  }, [text, reduced])
  const shown = reduced ? text.length : n
  return (
    <div className="ember-bubble" data-theme={theme} role="button" tabIndex={0} onClick={() => (shown < text.length ? setN(text.length) : onClose())}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (shown < text.length) setN(text.length); else onClose() } }}>
      <span className="ember-bubble__name" aria-hidden="true">Ember</span>
      <span className="sr-only" role="status">{text}</span>
      <span aria-hidden="true">{text.slice(0, shown)}</span>
    </div>
  )
}

/** The decorative mascot. It exists only while Kawaii Mode is on, loads its pictures then, and reacts to the
 *  alerts the application already has: it never asks for anything the page does not ask for itself. */
export function Mascot() {
  const s = useKawaii()
  const [manifest, setManifest] = useState<Manifest | null>(null)
  const [phrases, setPhrases] = useState<Phrases | null>(null)
  const [hidden, setHidden] = useState(false)
  const [menu, setMenu] = useState(false)
  const [frame, setFrame] = useState<{ clip: string; i: number }>({ clip: 'idle', i: 0 })
  const [say, setSay] = useState<{ id: number; text: string } | null>(null)
  const [tank, setTank] = useState(false) // after "takes the hoodie off" the last picture stays
  const systemReduced = useSyncExternalStore(subscribeReduced, systemReducedNow, () => false)
  const playRef = useRef<(m: Manifest, clipId: string, say?: string) => void>(() => {})
  const stageRef = useRef<HTMLDivElement>(null)
  const timer = useRef<number | undefined>(undefined)
  const sayTimer = useRef<number | undefined>(undefined)
  const busy = useRef(false)
  const tankRef = useRef(false)
  const clipRef = useRef('idle')
  const caught = useRef(false) // the click that ends the waiting of "caught flirting"
  const lastTap = useRef(0)
  const lastBusySay = useRef(0)
  const hoverTimer = useRef<number | undefined>(undefined)
  const sayId = useRef(0)
  const masks = useRef(new Map<number, CanvasRenderingContext2D | null>())
  const loadedAtlas = useRef(new Set<number>())
  const loadToken = useRef(0)
  const director = useMemo(() => new Director(), [])
  const narrow = useSyncExternalStore(subscribeWidth, narrowNow, () => false)
  const reduced = s.reduced || systemReduced
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null) // while the mascot is being moved
  const moved = useRef(false)
  const animated = s.animations && !reduced

  // Pictures and phrases are fetched only when the mode is on and the mascot is shown.
  const active = s.enabled && s.mascot && !hidden
  useEffect(() => {
    if (!active || manifest) return
    let dead = false
    void Promise.all([
      fetch(`${BASE}/ember.json`).then((r) => (r.ok ? (r.json() as Promise<Manifest>) : Promise.reject(new Error('manifest')))),
      fetch(`${BASE}/phrases.ru.json`).then((r) => (r.ok ? (r.json() as Promise<Phrases>) : null)),
    ]).then(([m, p]) => {
      if (dead) return
      setManifest(m)
      setPhrases(p)
    }).catch(() => { /* no pictures: nothing is shown, nothing else is affected */ })
    return () => { dead = true }
  }, [active, manifest])

  const stop = useCallback(() => {
    window.clearTimeout(timer.current)
    timer.current = undefined
  }, [])

  const showSay = useCallback((text: string | undefined) => {
    if (!text || !s.comments) return
    sayId.current += 1
    setSay({ id: sayId.current, text })
    window.clearTimeout(sayTimer.current)
    sayTimer.current = window.setTimeout(() => setSay(null), 5000 + text.length * 45)
  }, [s.comments])

  const spawn = useCallback((m: Manifest, origin: { x: number; y: number }, count: number) => {
    const stage = stageRef.current
    if (!stage || !animated) return
    const k = stage.clientWidth / m.frameSize.width
    const pm = m.particleMotion
    for (let i = 0; i < Math.min(count, 12); i++) {
      const img = document.createElement('img')
      img.src = `${BASE}/${m.projectile.file}`
      img.alt = ''
      img.setAttribute('aria-hidden', 'true')
      const w = pm.widthPx * k
      const h = pm.heightPx * k
      Object.assign(img.style, { position: 'absolute', left: `${origin.x * k - w / 2}px`, top: `${origin.y * k - h / 2}px`, width: `${w}px`, height: `${h}px`, pointerEvents: 'none', zIndex: '3' })
      stage.appendChild(img)
      const jx = (Math.random() - 0.5) * 40 * k
      const jy = (Math.random() - 0.5) * 30 * k
      const life = pm.durationMs * (0.75 + Math.random() * 0.2)
      const done = () => img.remove()
      if (typeof img.animate === 'function') {
        const a = img.animate(pm.keyframes.map((f) => ({ transform: `translate(${f.x * k + jx}px, ${f.y * k + jy}px) rotate(${f.rotation}deg)`, opacity: f.opacity, offset: f.offset })),
          { duration: life, delay: i * 70, fill: 'forwards', easing: 'linear' })
        a.onfinish = done
      }
      window.setTimeout(done, life + i * 70 + 200) // the safety net: a particle never outlives its flight
    }
  }, [animated])

  /** The air kiss: a separate heart flies from the hand. The path is the one the asset package describes. */
  const spawnHeart = useCallback((m: Manifest, h: NonNullable<Clip['heart']>) => {
    const stage = stageRef.current
    if (!stage || !animated) return
    const k = stage.clientWidth / m.frameSize.width
    const f = h.flight
    const w = f.width * k
    const hh = f.height * k
    const img = document.createElement('img')
    img.src = `${BASE}/${h.texture}`
    img.alt = ''
    img.setAttribute('aria-hidden', 'true')
    Object.assign(img.style, { position: 'absolute', left: `${f.origin.x * k - w / 2}px`, top: `${f.origin.y * k - hh / 2}px`, width: `${w}px`, height: `${hh}px`, pointerEvents: 'none', zIndex: '3', opacity: '0' })
    stage.appendChild(img)
    const life = f.endMs - f.releaseMs
    const done = () => img.remove()
    if (typeof img.animate === 'function') {
      const frames = Array.from({ length: 9 }, (_, j) => {
        const u = j / 8
        const x = f.dx * u
        const y = f.dy * u - Math.sin(Math.PI * u) * 12
        return {
          transform: `translate(${x * k}px, ${y * k}px) scale(${0.45 + 0.65 * Math.min(1, u * 4)}) rotate(${Math.sin(Math.PI * u * 2) * 12}deg)`,
          opacity: Math.min(1, u * 8) * Math.min(1, (1 - u) * 4), offset: u,
        }
      })
      img.animate(frames, { duration: life, fill: 'forwards', easing: 'linear' }).onfinish = done
    }
    window.setTimeout(done, life + 200)
  }, [animated])

  /** Plays one clip, then returns to the idle loop (or, after a change of clothes, stays on the last picture). */
  const play = useCallback((m: Manifest, clipId: string, say?: string) => {
    const clip = m.clips[clipId]
    if (!clip || !animated) {
      showSay(say)
      return
    }
    // A clip is not started before its pictures have arrived: an atlas that is still loading would show as a gap.
    const pending = [...new Set(clip.frames.map((f) => f.a))].filter((a) => !loadedAtlas.current.has(a))
    if (pending.length > 0) {
      const token = ++loadToken.current
      void Promise.all(pending.map((a) => new Promise<void>((resolve) => {
        const img = new Image()
        const done = () => { loadedAtlas.current.add(a); resolve() }
        img.onload = done
        img.onerror = done // a missing picture must not stop the mascot for good
        img.src = `${BASE}/atlas-${a}.webp`
        window.setTimeout(done, 3000) // slow or stuck: go on without it rather than wait for ever
      }))).then(() => { if (token === loadToken.current) playRef.current(m, clipId, say) })
      return
    }
    stop()
    busy.current = clipId !== 'idle' && clipId !== 'blink'
    clipRef.current = clipId
    caught.current = false
    // A phrase that belongs to a moment of the scene waits for its marker; any other starts at once.
    const speechAtMarker = clip.markers.some((mk) => mk.name === 'speech')
    if (!speechAtMarker) showSay(say)
    const ia = clip.interaction?.type === 'click-to-catch' ? clip.interaction : null
    let waitFrom = 0
    if (ia) { // the first frame that starts at the point the waiting loop returns to
      let at = 0
      while (waitFrom < clip.frames.length - 1 && at + (clip.durationsMs[waitFrom] ?? 0) <= ia.waitLoopStartMs) { at += clip.durationsMs[waitFrom] ?? 0; waitFrom++ }
    }
    let i = 0
    let elapsed = 0
    const fired = new Set<number>()
    const step = () => {
      if (document.hidden) { // a hidden tab does not animate; try again when it is looked at
        timer.current = window.setTimeout(step, 500)
        return
      }
      setFrame({ clip: clipId, i })
      clip.markers.forEach((mk, n) => {
        if (fired.has(n) || mk.atMs > elapsed + 1) return
        if (mk.origin && (mk.name.startsWith('release') || mk.name.startsWith('storm'))) {
          fired.add(n)
          spawn(m, mk.origin, mk.count ?? 1)
        } else if (mk.name === 'heart-release' && clip.heart) {
          fired.add(n)
          spawnHeart(m, clip.heart)
        } else if (mk.name === 'speech') {
          fired.add(n)
          showSay(say)
        }
      })
      const d = clip.durationsMs[i] ?? 50
      elapsed += d
      i++
      if (ia && !caught.current && elapsed >= ia.introEndMs) { // wait for the click, repeating the loop of two poses
        i = waitFrom
        elapsed = ia.waitLoopStartMs
      }
      if (i >= clip.frames.length) {
        if (clip.loop && clipId === 'idle') { i = 0; elapsed = 0 }
        else if (clip.wardrobe?.holdFinal) { // in other clothes now: the last picture stays
          timer.current = window.setTimeout(() => {
            busy.current = false
            tankRef.current = true
            setTank(true)
          }, d)
          return
        }
        else {
          timer.current = window.setTimeout(() => {
            busy.current = false
            setFrame({ clip: 'idle', i: 0 })
            playRef.current(m, 'idle')
          }, d)
          return
        }
      }
      timer.current = window.setTimeout(step, d)
    }
    step()
  }, [animated, showSay, spawn, spawnHeart, stop])
  useEffect(() => { playRef.current = play }, [play])

  // The idle loop, with an occasional blink.
  useEffect(() => {
    if (!manifest || !active) return
    if (!animated) { stop(); return }
    const start = window.setTimeout(() => play(manifest, 'idle'), 0)
    const blink = window.setInterval(() => {
      if (!busy.current && !tankRef.current && !document.hidden) play(manifest, 'blink')
    }, 9000 + Math.random() * 5000)
    return () => { window.clearTimeout(start); window.clearInterval(blink); stop() }
  }, [manifest, active, animated, play, stop])

  useEffect(() => () => { window.clearTimeout(sayTimer.current); window.clearTimeout(hoverTimer.current); stop() }, [stop])

  const react = useCallback((mood: Mood) => {
    if (!manifest || !active) return
    if (!director.allow(mood, Date.now(), { typing: typingNow(), busy: busy.current })) return
    if (tankRef.current) { // in the other clothes she only talks
      showSay(pick(phrases?.clips[MOOD_CLIP[mood]]))
      return
    }
    play(manifest, MOOD_CLIP[mood], pick(phrases?.clips[MOOD_CLIP[mood]]))
  }, [manifest, active, director, play, phrases, showSay])

  // What the mascot reacts to: the application's own alerts, and new Fail2ban bans.
  const seenAlerts = useRef<Set<string> | null>(null)
  const hadOpen = useRef(false)
  const alerts = useLoad((sg) => (active ? api.get<{ alerts: AlertRow[] }>('/api/v1/alerts?state=open', sg) : Promise.resolve(null)), [active], 60_000)
  useEffect(() => {
    const rows = alerts.data?.alerts
    if (!rows) return
    const open = rows.filter((a) => !a.resolved_at)
    if (seenAlerts.current === null) { // the first reading is the baseline: nothing is announced for what was already there
      seenAlerts.current = new Set(open.map((a) => a.id))
      hadOpen.current = open.length > 0
      return
    }
    const fresh = open.filter((a) => !seenAlerts.current!.has(a.id))
    fresh.forEach((a) => seenAlerts.current!.add(a.id))
    if (fresh.length > 0) {
      hadOpen.current = true
      react(moodForAlert(fresh[0].kind))
    } else if (open.length === 0 && hadOpen.current) {
      hadOpen.current = false
      react('celebrate')
    }
  }, [alerts.data, react])

  const lastBan = useRef<string | null | undefined>(undefined)
  const bans = useLoad((sg) => (active ? api.get<{ items: { id: string }[] }>('/api/v1/security/events?type=fail2ban.ban&limit=1', sg).catch(() => null) : Promise.resolve(null)), [active], 120_000)
  useEffect(() => {
    const id = bans.data?.items?.[0]?.id ?? null
    if (lastBan.current === undefined) { lastBan.current = id; return }
    if (id && id !== lastBan.current) { lastBan.current = id; react('smug') }
  }, [bans.data, react])

  if (!active || !manifest) return null
  const base = MASCOT_SIZES[s.size]
  const size = narrow ? Math.round(base * 0.72) : base
  const k = size / manifest.frameSize.width
  // Where it sits: the corner by default, or where it was dragged to, kept inside the window.
  const clampPos = (p: { x: number; y: number }) => ({
    x: Math.min(Math.max(0, p.x), Math.max(0, window.innerWidth - size)),
    y: Math.min(Math.max(0, p.y), Math.max(0, window.innerHeight - size)),
  })
  const shown = drag ?? (s.pos ? clampPos(s.pos) : null)
  const onDown = (e: React.PointerEvent<HTMLButtonElement>) => {
    if (e.button !== 0) return
    const root = (e.currentTarget.closest('.ember-root') as HTMLElement).getBoundingClientRect()
    const grab = { dx: e.clientX - root.left, dy: e.clientY - root.top, sx: e.clientX, sy: e.clientY }
    moved.current = false
    e.currentTarget.setPointerCapture(e.pointerId)
    const move = (ev: PointerEvent) => {
      if (!moved.current && Math.hypot(ev.clientX - grab.sx, ev.clientY - grab.sy) < 6) return
      moved.current = true
      setMenu(false)
      setDrag(clampPos({ x: ev.clientX - grab.dx, y: ev.clientY - grab.dy }))
    }
    const up = (ev: PointerEvent) => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      if (moved.current) {
        const p = clampPos({ x: ev.clientX - grab.dx, y: ev.clientY - grab.dy })
        setKawaii({ pos: p })
        setDrag(null)
      }
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }
  const clip = manifest.clips[frame.clip] ?? manifest.clips.idle
  const cell = !animated ? manifest.poster : clip.frames[Math.min(frame.i, clip.frames.length - 1)]

  // Is the point on the drawing, not on its transparent corners? The alpha of the current picture says so.
  const onDrawing = (e: React.MouseEvent<HTMLButtonElement>): boolean => {
    if (e.detail === 0) return true // a key press has no point
    const key = cell.a
    let ctx = masks.current.get(key)
    if (ctx === undefined) {
      masks.current.set(key, null)
      const img = new Image()
      img.onload = () => {
        const c = document.createElement('canvas')
        c.width = img.naturalWidth
        c.height = img.naturalHeight
        const g = c.getContext('2d', { willReadFrequently: true })
        if (g) { g.drawImage(img, 0, 0); masks.current.set(key, g) }
      }
      img.src = `${BASE}/atlas-${key}.webp`
      ctx = null
    }
    if (!ctx) return true // not loaded yet, or no canvas: the whole square counts
    const r = e.currentTarget.getBoundingClientRect()
    const x = Math.min(manifest.frameSize.width - 1, Math.max(0, Math.floor((e.clientX - r.left) / k)))
    const y = Math.min(manifest.frameSize.height - 1, Math.max(0, Math.floor((e.clientY - r.top) / k)))
    try {
      return ctx.getImageData(cell.x + x, cell.y + y, 1, 1).data[3] >= 32
    } catch {
      return true
    }
  }

  const onBodyClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (moved.current) { moved.current = false; return }
    if (!onDrawing(e)) return
    const taps = phrases?.clips.tap
    if (!animated) { showSay(pick(taps)); return }
    if (tankRef.current) { showSay(pick(phrases?.clips.hoodie_off)); return } // the clothes stay: only a phrase
    if (clipRef.current === 'caught_flirting' && busy.current && !caught.current) { caught.current = true; return } // the click she was waiting for
    const now = performance.now()
    if (busy.current) {
      if (now - lastBusySay.current > 1200) {
        lastBusySay.current = now
        showSay(clipRef.current === 'hoodie_off' ? t('kw.stuck') : t('kw.busy'))
      }
      return
    }
    if (now - lastTap.current < 2400) return
    lastTap.current = now
    play(manifest, 'tap', pick(taps))
  }

  const onEnter = (e: React.PointerEvent<HTMLButtonElement>) => {
    if (e.pointerType !== 'mouse' || reduced || !animated) return
    window.clearTimeout(hoverTimer.current)
    hoverTimer.current = window.setTimeout(() => {
      if (clipRef.current === 'idle' && !busy.current && !tankRef.current && !document.hidden) play(manifest, 'curious', pick(phrases?.clips.curious))
    }, 650)
  }
  const onLeave = () => window.clearTimeout(hoverTimer.current)

  const scene = (id: string) => { setMenu(false); play(manifest, id, pick(phrases?.clips[id])) }
  const dress = () => {
    setMenu(false)
    tankRef.current = false
    setTank(false)
    clipRef.current = 'idle'
    play(manifest, 'idle')
  }
  const themeName = s.theme === 'sakura_light' ? 'paper' : 'dark'

  return (
    <div className="ember-root" data-testid="ember" style={shown ? { left: shown.x, top: shown.y, right: 'auto', bottom: 'auto' } : undefined}>
      {say && <Bubble key={say.id} text={say.text} theme={themeName} reduced={reduced} onClose={() => setSay(null)} />}
      <div ref={stageRef} className="ember-stage" style={{ width: size, height: size }}>
        <button type="button" className="ember-gear" aria-label={t('kw.menu')} aria-expanded={menu} onClick={() => setMenu((v) => !v)}>⋯</button>
        <button type="button" className="ember-body" aria-label={t('kw.mascot')} onPointerDown={onDown} onPointerEnter={onEnter} onPointerLeave={onLeave} onClick={onBodyClick}
          style={{ width: size, height: size, backgroundImage: `url(${BASE}/atlas-${cell.a}.webp)`, backgroundSize: `${manifest.atlasSize * k}px ${manifest.atlasSize * k}px`, backgroundPosition: `-${cell.x * k}px -${cell.y * k}px` }} />
      </div>
      {menu && (
        <div className="ember-menu" role="menu">
          {s.itemStorm && animated && !tank && <button role="menuitem" type="button" onClick={() => scene('item_storm')}>{t('kw.tease')}</button>}
          {s.playful && animated && !tank && <button role="menuitem" type="button" onClick={() => scene('kiss_tease')}>{t('kw.kiss')}</button>}
          {s.playful && animated && !tank && <button role="menuitem" type="button" onClick={() => scene('caught_flirting')}>{t('kw.caught')}</button>}
          {s.playful && animated && !tank && <button role="menuitem" type="button" onClick={() => scene('hoodie_off')}>{t('kw.hoodieOff')}</button>}
          {tank && <button role="menuitem" type="button" onClick={dress}>{t('kw.hoodieOn')}</button>}
          {s.pos && <button role="menuitem" type="button" onClick={() => { setMenu(false); setKawaii({ pos: null }) }}>{t('kw.reset')}</button>}
          <button role="menuitem" type="button" onClick={() => { setMenu(false); setHidden(true) }}>{t('kw.hide')}</button>
          <button role="menuitem" type="button" onClick={() => { setMenu(false); setKawaii({ mascot: false }) }}>{t('kw.off')}</button>
          <Link role="menuitem" to="/settings?tab=appearance" onClick={() => setMenu(false)}>{t('kw.settings')}</Link>
        </div>
      )}
    </div>
  )
}
