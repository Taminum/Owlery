import { useSyncExternalStore } from 'react'

// The decorative mode is a preference of this browser, off by default. Nothing in it is needed to use the app,
// and turning it off puts the standard look back exactly.
export type KawaiiTheme = 'kawaii_dark' | 'sakura_light' | 'neko_terminal'
export const KAWAII_THEMES: KawaiiTheme[] = ['kawaii_dark', 'sakura_light', 'neko_terminal']

export type MascotSize = 's' | 'm' | 'l' | 'xl'
export const MASCOT_SIZES: Record<MascotSize, number> = { s: 200, m: 280, l: 420, xl: 520 }

export interface KawaiiSettings {
  enabled: boolean
  theme: KawaiiTheme
  mascot: boolean
  comments: boolean
  animations: boolean
  itemStorm: boolean
  reduced: boolean // a manual "less motion"; the system preference is honoured as well
  size: MascotSize
  pos: { x: number; y: number } | null // where the mascot was dragged to (left and top, in px); null: the corner
}

export const KAWAII_DEFAULTS: KawaiiSettings = {
  enabled: false, theme: 'kawaii_dark', mascot: true, comments: true, animations: true, itemStorm: true, reduced: false, size: 'l', pos: null,
}

const KEY = 'remnascope.kawaii'
const listeners = new Set<() => void>()

function read(): KawaiiSettings {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return KAWAII_DEFAULTS
    const p = JSON.parse(raw) as Partial<KawaiiSettings>
    return {
      enabled: p.enabled === true,
      theme: KAWAII_THEMES.includes(p.theme as KawaiiTheme) ? (p.theme as KawaiiTheme) : KAWAII_DEFAULTS.theme,
      mascot: p.mascot !== false,
      comments: p.comments !== false,
      animations: p.animations !== false,
      itemStorm: p.itemStorm !== false,
      reduced: p.reduced === true,
      size: p.size === 's' || p.size === 'm' || p.size === 'xl' ? p.size : 'l',
      pos: p.pos && Number.isFinite(p.pos.x) && Number.isFinite(p.pos.y) ? { x: Math.round(p.pos.x), y: Math.round(p.pos.y) } : null,
    }
  } catch {
    return KAWAII_DEFAULTS // storage blocked or broken: the default look
  }
}

let current: KawaiiSettings = read()

/** Puts the theme on the document, or takes it off. Called wherever the settings are applied. */
export function applyKawaiiTheme(s: KawaiiSettings): void {
  const el = document.documentElement
  if (s.enabled) el.setAttribute('data-kawaii-theme', s.theme)
  else el.removeAttribute('data-kawaii-theme')
}

applyKawaiiTheme(current)

export function setKawaii(patch: Partial<KawaiiSettings>): void {
  current = { ...current, ...patch }
  try {
    localStorage.setItem(KEY, JSON.stringify(current))
  } catch {
    /* not remembered, still applied */
  }
  applyKawaiiTheme(current)
  listeners.forEach((l) => l())
}

export function useKawaii(): KawaiiSettings {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    () => current,
    () => KAWAII_DEFAULTS,
  )
}

/** For tests: forget everything and re-read. */
export function resetKawaiiForTests(): void {
  try {
    localStorage.removeItem(KEY)
  } catch {
    /* ignore */
  }
  current = read()
  applyKawaiiTheme(current)
  listeners.forEach((l) => l())
}

/** For tests: re-read what is stored, as a fresh page load would. */
export function reloadKawaiiForTests(): void {
  current = read()
  applyKawaiiTheme(current)
  listeners.forEach((l) => l())
}
