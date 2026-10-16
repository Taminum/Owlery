import { render, screen, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Director, moodForAlert } from '../ember/director'
import { KAWAII_DEFAULTS, reloadKawaiiForTests, resetKawaiiForTests, setKawaii } from '../ember/settings'
import { Mascot } from '../ember/Mascot'

beforeEach(() => {
  // Pictures "load" at once; the mascot waits for the atlas of a clip before it plays it.
  vi.stubGlobal('Image', class {
    onload: (() => void) | null = null
    set src(_v: string) { setTimeout(() => this.onload?.(), 0) }
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
  resetKawaiiForTests()
})

describe('Kawaii settings', () => {
  it('is off by default and puts the theme on the document only while on', () => {
    expect(KAWAII_DEFAULTS.enabled).toBe(false)
    expect(document.documentElement.getAttribute('data-kawaii-theme')).toBeNull()
    setKawaii({ enabled: true, theme: 'sakura_light' })
    expect(document.documentElement.getAttribute('data-kawaii-theme')).toBe('sakura_light')
    setKawaii({ enabled: false })
    expect(document.documentElement.getAttribute('data-kawaii-theme')).toBeNull()
  })

  it('ignores a stored theme that does not exist', () => {
    localStorage.setItem('remnascope.kawaii', JSON.stringify({ enabled: true, theme: 'hot_pink_fire' }))
    reloadKawaiiForTests()
    expect(document.documentElement.getAttribute('data-kawaii-theme')).toBe('kawaii_dark')
  })
})

describe('Mascot placement', () => {
  it('is large by default, remembers where it was moved and ignores a broken position', () => {
    expect(KAWAII_DEFAULTS.size).toBe('l')
    expect(KAWAII_DEFAULTS.pos).toBeNull()
    setKawaii({ enabled: true, pos: { x: 120.4, y: 80 }, size: 'xl' })
    reloadKawaiiForTests()
    const saved = JSON.parse(localStorage.getItem('remnascope.kawaii') ?? '{}')
    expect(saved.pos).toEqual({ x: 120.4, y: 80 })
    expect(saved.size).toBe('xl')
    localStorage.setItem('remnascope.kawaii', JSON.stringify({ enabled: true, pos: { x: 'a', y: null }, size: 'huge' }))
    reloadKawaiiForTests()
    expect(JSON.parse(localStorage.getItem('remnascope.kawaii') ?? '{}').size).toBe('huge') // the raw text is untouched...
    setKawaii({ mascot: true }) // ...and a write normalises it
    const fixed = JSON.parse(localStorage.getItem('remnascope.kawaii') ?? '{}')
    expect(fixed.size).toBe('l')
    expect(fixed.pos).toBeNull()
  })
})

describe('Director', () => {
  const idle = { typing: false, busy: false }
  it('keeps decoration quiet and lets an alert go first', () => {
    const d = new Director({ globalGapMs: 90_000, alertGapMs: 10_000, moodCooldownMs: 600_000 })
    expect(d.allow('happy', 0, idle)).toBe(true)
    expect(d.allow('smug', 30_000, idle)).toBe(false) // too soon after the previous one
    expect(d.allow('alert', 30_000, idle)).toBe(true) // an alert may follow sooner
    expect(d.allow('alert', 31_000, idle)).toBe(false) // but not the same one again at once
    expect(d.allow('smug', 200_000, idle)).toBe(true)
  })
  it('does not interrupt typing or a scene in progress, except for an alert', () => {
    const d = new Director()
    expect(d.allow('smug', 0, { typing: true, busy: false })).toBe(false)
    expect(d.allow('smug', 0, { typing: false, busy: true })).toBe(false)
    expect(d.allow('alert', 0, { typing: true, busy: true })).toBe(true)
  })
  it('maps alert kinds to moods', () => {
    expect(moodForAlert('sec_tls')).toBe('concerned')
    expect(moodForAlert('dns_change')).toBe('curious')
    expect(moodForAlert('sec_agent_silent')).toBe('alert')
  })
})

const manifest = {
  frameSize: { width: 512, height: 512 }, atlasSize: 2048, poster: { a: 0, x: 0, y: 0 },
  clips: {
    idle: { frames: [{ a: 0, x: 0, y: 0 }], durationsMs: [100], loop: true, markers: [], effect: false },
    alert: { frames: [{ a: 0, x: 0, y: 0 }], durationsMs: [50], loop: false, markers: [], effect: false },
  },
  projectile: { file: 'projectile.png', width: 192, height: 128 },
  particleMotion: { widthPx: 54, heightPx: 36, durationMs: 1000, keyframes: [{ x: 0, y: 0, rotation: 0, opacity: 1, offset: 0 }, { x: 10, y: 10, rotation: 0, opacity: 0, offset: 1 }] },
}

function stubFetch(alerts: { id: string; kind: string; resolved_at: string | null }[], mf: object = manifest, phrases: object = { alert: ['Бака! Сервер пропал!'] }) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    const body = url.includes('ember.json') ? mf
      : url.includes('phrases') ? { clips: phrases }
      : url.includes('/alerts') ? { alerts }
      : { items: [] }
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  return calls
}

describe('Mascot', () => {
  it('asks for nothing and shows nothing while the mode is off', async () => {
    const calls = stubFetch([])
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByTestId('ember')).toBeNull()
    expect(calls).toHaveLength(0)
  })

  it('appears when the mode is on, says nothing about what was already open, and reacts to a new alert', async () => {
    setKawaii({ enabled: true })
    const first = [{ id: 'a1', kind: 'sec_tls', resolved_at: null }]
    stubFetch(first)
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    expect(await screen.findByTestId('ember')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Ember/ })).toBeInTheDocument()
    // The baseline: an alert that was open at the start is not announced.
    await act(async () => { await new Promise((r) => setTimeout(r, 50)) })
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('can be switched off from its own menu without a reload', async () => {
    setKawaii({ enabled: true })
    stubFetch([])
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    await screen.findByTestId('ember')
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    ;(await screen.findByRole('menuitem', { name: 'Выключить талисмана' })).click()
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByTestId('ember')).toBeNull()
  })
})

const cell = { a: 0, x: 0, y: 0 }
const sceneManifest = {
  ...manifest,
  clips: {
    ...manifest.clips,
    tap: { frames: [cell], durationsMs: [20], loop: false, markers: [], effect: false },
    hoodie_off: { frames: [cell, cell], durationsMs: [20, 20], loop: false, effect: false, markers: [{ name: 'speech', atMs: 20 }], wardrobe: { holdFinal: true } },
    caught_flirting: {
      frames: [cell, cell, cell, cell], durationsMs: [10, 10, 10, 10], loop: false, effect: false, markers: [{ name: 'speech', atMs: 30 }],
      interaction: { type: 'click-to-catch', introEndMs: 30, waitLoopStartMs: 10 },
    },
  },
}
const scenePhrases = { tap: ['Эй!'], hoodie_off: ['Жарко мне.'], caught_flirting: ['Я просто удобно села.'] }
const wait = (ms: number) => act(async () => { await new Promise((r) => setTimeout(r, ms)) })

describe('Mascot scenes', () => {
  it('holds the last picture after the clothes come off, talks instead of moving, and dresses again from the menu', async () => {
    setKawaii({ enabled: true })
    stubFetch([], sceneManifest, scenePhrases)
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    await screen.findByTestId('ember')
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    ;(await screen.findByRole('menuitem', { name: 'Снять худи' })).click()
    await wait(200)
    expect(screen.getByText('Жарко мне.', { selector: '.sr-only' })).toBeInTheDocument()
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    expect(await screen.findByRole('menuitem', { name: 'Надеть худи' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Воздушный поцелуй' })).toBeNull() // no other scene in the other clothes
    screen.getByRole('menuitem', { name: 'Надеть худи' }).click()
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    expect(await screen.findByRole('menuitem', { name: 'Снять худи' })).toBeInTheDocument()
  })

  it('waits for the click in "caught flirting" and speaks only after it', async () => {
    setKawaii({ enabled: true })
    stubFetch([], sceneManifest, scenePhrases)
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    await screen.findByTestId('ember')
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    ;(await screen.findByRole('menuitem', { name: 'Поймана за флиртом' })).click()
    await wait(250)
    expect(screen.queryByText('Я просто удобно села.', { selector: '.sr-only' })).toBeNull() // still waiting
    screen.getByRole('button', { name: /Талисман Ember/ }).click()
    await wait(250)
    expect(screen.getByText('Я просто удобно села.', { selector: '.sr-only' })).toBeInTheDocument()
  })

  it('does not offer the cheeky scenes when they are switched off', async () => {
    setKawaii({ enabled: true, playful: false })
    stubFetch([], sceneManifest, scenePhrases)
    render(<MemoryRouter><Mascot /></MemoryRouter>)
    await screen.findByTestId('ember')
    screen.getByRole('button', { name: 'Меню талисмана' }).click()
    await screen.findByRole('menuitem', { name: 'Выключить талисмана' })
    expect(screen.queryByRole('menuitem', { name: 'Снять худи' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Воздушный поцелуй' })).toBeNull()
  })
})
