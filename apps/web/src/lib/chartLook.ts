import { useSyncExternalStore } from 'react'

// How lines are drawn. By default a line joins the measured points with straight segments and shows
// the points themselves when there are few of them, so a bend never suggests a measurement that was
// not taken. Smoothing is a preference for those who want the softer look; it is remembered per browser.
const KEY = 'remnascope.smooth'
const listeners = new Set<() => void>()
let smooth = false
try {
  smooth = localStorage.getItem(KEY) === '1'
} catch {
  /* storage can be blocked: the default stays */
}

export function setSmooth(v: boolean) {
  smooth = v
  try {
    localStorage.setItem(KEY, v ? '1' : '0')
  } catch {
    /* not remembered, still applied */
  }
  listeners.forEach((l) => l())
}

export function useSmooth(): boolean {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    () => smooth,
    () => false,
  )
}

/** Points are drawn as dots up to this many measurements; beyond it they would only be noise. */
export const DOTS_UP_TO = 48

/** Props for an <Area> given how many measurements it has. */
export function useLook() {
  const s = useSmooth()
  return (n: number) => ({
    type: (s ? 'monotone' : 'linear') as 'monotone' | 'linear',
    dot: n <= DOTS_UP_TO ? ({ r: 2, strokeWidth: 0 } as const) : (false as const),
    activeDot: { r: 4 },
  })
}
