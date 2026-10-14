import { useCallback, useEffect, useState } from 'react'
import { ApiError, fetchOverview, fetchScope } from '../lib/api'
import type { Filters } from '../lib/filters'
import type { Overview, PanelInfo } from '../lib/types'

export type Failure = { kind: 'forbidden' | 'invalid' | 'error'; message: string; requestId?: string }

function toFailure(e: unknown): Failure {
  if (e instanceof ApiError) {
    if (e.status === 403) return { kind: 'forbidden', message: e.message, requestId: e.requestId }
    if (e.status === 400) return { kind: 'invalid', message: e.message, requestId: e.requestId }
    return { kind: 'error', message: e.message, requestId: e.requestId }
  }
  return { kind: 'error', message: String(e) }
}

export function usePanels() {
  const [panels, setPanels] = useState<PanelInfo[] | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const ac = new AbortController()
    fetchScope(ac.signal)
      .then((r) => {
        setPanels(r.panels)
        setFailure(null)
      })
      .catch((e) => {
        if ((e as Error).name !== 'AbortError') setFailure(toFailure(e))
      })
    return () => ac.abort()
  }, [attempt])
  return { panels, failure, retry: () => setAttempt((n) => n + 1) }
}

const REFRESH_MS = { off: 0, '1m': 60_000, '5m': 300_000 } as const

/**
 * Loads the overview for the current filters. The previous payload stays on
 * screen while a new one loads, so filter changes never flash an empty page.
 */
export function useOverview(filters: Filters | null, demoState: string | undefined) {
  const [data, setData] = useState<Overview | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [settled, setSettled] = useState<string | null>(null)
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null)
  const [nonce, setNonce] = useState(0)
  const key = filters ? JSON.stringify(filters) : null
  const requestKey = `${key}|${demoState ?? ''}|${nonce}`
  // Derived, not set in the effect: loading until the response for *this* request lands.
  const loading = settled !== requestKey

  useEffect(() => {
    if (key === null) return
    const f = JSON.parse(key) as Filters
    const ac = new AbortController()
    fetchOverview(f, demoState, ac.signal)
      .then((ov) => {
        setData(ov)
        setFailure(null)
        setFetchedAt(new Date())
        setSettled(requestKey)
      })
      .catch((e) => {
        if ((e as Error).name === 'AbortError') return
        setFailure(toFailure(e))
        setSettled(requestKey)
      })
    return () => ac.abort()
  }, [key, demoState, nonce, requestKey])

  const every = filters ? REFRESH_MS[filters.refresh] : 0
  useEffect(() => {
    if (!every) return
    const id = setInterval(() => setNonce((n) => n + 1), every)
    return () => clearInterval(id)
  }, [every])

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  return { data, failure, loading, fetchedAt, refresh }
}
