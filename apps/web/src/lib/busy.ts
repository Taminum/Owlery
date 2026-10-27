import { useSyncExternalStore } from 'react'

// How many loads the user is waiting for right now (polling refreshes do not count): the top bar shows while it is above zero.
let pending = 0
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

export function busyStart(): () => void {
  pending++
  emit()
  let done = false
  return () => {
    if (done) return
    done = true
    pending--
    emit()
  }
}

export function useBusy(): boolean {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    () => pending > 0,
  )
}
