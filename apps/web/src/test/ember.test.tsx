import { render, screen, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Director, moodForAlert } from '../ember/director'
import { KAWAII_DEFAULTS, reloadKawaiiForTests, resetKawaiiForTests, setKawaii } from '../ember/settings'
import { Mascot } from '../ember/Mascot'

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

function stubFetch(alerts: { id: string; kind: string; resolved_at: string | null }[]) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    const body = url.includes('ember.json') ? manifest
      : url.includes('phrases') ? { clips: { alert: ['Бака! Сервер пропал!'] } }
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
    screen.getByRole('button', { name: /Ember/ }).click()
    ;(await screen.findByRole('menuitem', { name: 'Выключить талисмана' })).click()
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByTestId('ember')).toBeNull()
  })
})
