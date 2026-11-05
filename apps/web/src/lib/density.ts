import { useSyncExternalStore } from 'react'

// How tables (and the cards around them) are drawn: "compact" is the default, close rows on the page itself, as in Resources; "roomy"
// keeps the card and more air. It is a preference of this browser, put on the document as data-density so every table follows at once.
export type Density = 'compact' | 'roomy'

const KEY = 'owlery.density'
const listeners = new Set<() => void>()

function read(): Density {
  try {
    return localStorage.getItem(KEY) === 'roomy' ? 'roomy' : 'compact'
  } catch {
    return 'compact' // storage blocked: the default
  }
}

let current: Density = read()

function apply(d: Density): void {
  document.documentElement.setAttribute('data-density', d)
}
apply(current)

export function setDensity(d: Density): void {
  current = d
  try {
    localStorage.setItem(KEY, d)
  } catch {
    /* not remembered, still applied */
  }
  apply(d)
  listeners.forEach((l) => l())
}

export function useDensity(): Density {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    () => current,
    () => 'compact',
  )
}
