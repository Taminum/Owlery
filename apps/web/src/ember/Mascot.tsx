import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { Link } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { Director, moodForAlert, type Mood } from './director'
import { setKawaii, useKawaii } from './settings'

interface Cell { a: number; x: number; y: number }
interface Marker { name: string; atMs: number; origin?: { x: number; y: number }; count?: number }
interface Clip { frames: Cell[]; durationsMs: number[]; loop: boolean; markers: Marker[]; effect: boolean }
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

function typingNow(): boolean {
  const el = document.activeElement
  if (!el) return false
  const tag = el.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (el as HTMLElement).isContentEditable
}

interface AlertRow { id: string; kind: string; resolved_at: string | null }

/** The decorative mascot. It exists only while Kawaii Mode is on, loads its pictures then, and reacts to the
 *  alerts the application already has: it never asks for anything the page does not ask for itself. */
export function Mascot() {
  const s = useKawaii()
  const [manifest, setManifest] = useState<Manifest | null>(null)
  const [phrases, setPhrases] = useState<Phrases | null>(null)
  const [hidden, setHidden] = useState(false)
  const [menu, setMenu] = useState(false)
  const [frame, setFrame] = useState<{ clip: string; i: number }>({ clip: 'idle', i: 0 })
  const [say, setSay] = useState<string | null>(null)
  const systemReduced = useSyncExternalStore(subscribeReduced, systemReducedNow, () => false)
  const playRef = useRef<(m: Manifest, clipId: string, say?: string) => void>(() => {})
  const stageRef = useRef<HTMLDivElement>(null)
  const timer = useRef<number | undefined>(undefined)
  const sayTimer = useRef<number | undefined>(undefined)
  const busy = useRef(false)
  const director = useMemo(() => new Director(), [])
  const reduced = s.reduced || systemReduced
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
    setSay(text)
    window.clearTimeout(sayTimer.current)
    sayTimer.current = window.setTimeout(() => setSay(null), 4500 + text.length * 40)
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

  /** Plays one clip, then returns to the idle loop. */
  const play = useCallback((m: Manifest, clipId: string, say?: string) => {
    const clip = m.clips[clipId]
    if (!clip || !animated) {
      showSay(say)
      return
    }
    stop()
    busy.current = clipId !== 'idle' && clipId !== 'blink'
    showSay(say)
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
        if (!fired.has(n) && mk.atMs <= elapsed + 1 && mk.origin && (mk.name.startsWith('release') || mk.name.startsWith('storm'))) {
          fired.add(n)
          spawn(m, mk.origin, mk.count ?? 1)
        }
      })
      const d = clip.durationsMs[i] ?? 50
      elapsed += d
      i++
      if (i >= clip.frames.length) {
        if (clip.loop && clipId === 'idle') { i = 0; elapsed = 0 }
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
  }, [animated, showSay, spawn, stop])
  useEffect(() => { playRef.current = play }, [play])

  // The idle loop, with an occasional blink.
  useEffect(() => {
    if (!manifest || !active) return
    if (!animated) { stop(); return }
    const start = window.setTimeout(() => play(manifest, 'idle'), 0)
    const blink = window.setInterval(() => {
      if (!busy.current && !document.hidden) play(manifest, 'blink')
    }, 9000 + Math.random() * 5000)
    return () => { window.clearTimeout(start); window.clearInterval(blink); stop() }
  }, [manifest, active, animated, play, stop])

  useEffect(() => () => { window.clearTimeout(sayTimer.current); stop() }, [stop])

  const react = useCallback((mood: Mood) => {
    if (!manifest || !active) return
    if (!director.allow(mood, Date.now(), { typing: typingNow(), busy: busy.current })) return
    play(manifest, MOOD_CLIP[mood], pick(phrases?.clips[MOOD_CLIP[mood]]))
  }, [manifest, active, director, play, phrases])

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
  const size = 176
  const k = size / manifest.frameSize.width
  const clip = manifest.clips[frame.clip] ?? manifest.clips.idle
  const cell = !animated ? manifest.poster : clip.frames[Math.min(frame.i, clip.frames.length - 1)]

  return (
    <div className="ember-root" data-testid="ember">
      {say && (
        <div className="ember-bubble" role="status" onClick={() => setSay(null)}>{say}</div>
      )}
      <div ref={stageRef} className="ember-stage" style={{ width: size, height: size }}>
        <button type="button" className="ember-body" aria-label={t('kw.mascot')} aria-expanded={menu} onClick={() => setMenu((v) => !v)}
          style={{ width: size, height: size, backgroundImage: `url(${BASE}/atlas-${cell.a}.webp)`, backgroundSize: `${manifest.atlasSize * k}px ${manifest.atlasSize * k}px`, backgroundPosition: `-${cell.x * k}px -${cell.y * k}px` }} />
      </div>
      {menu && (
        <div className="ember-menu" role="menu">
          {s.itemStorm && animated && <button role="menuitem" type="button" onClick={() => { setMenu(false); play(manifest, 'item_storm', pick(phrases?.clips.item_storm)) }}>{t('kw.tease')}</button>}
          <button role="menuitem" type="button" onClick={() => { setMenu(false); setHidden(true) }}>{t('kw.hide')}</button>
          <button role="menuitem" type="button" onClick={() => { setMenu(false); setKawaii({ mascot: false }) }}>{t('kw.off')}</button>
          <Link role="menuitem" to="/settings?tab=appearance" onClick={() => setMenu(false)}>{t('kw.settings')}</Link>
        </div>
      )}
    </div>
  )
}
