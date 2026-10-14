import { useCallback, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { parseFilters, sanitizeFilters, serializeFilters, type Filters } from '../lib/filters'
import type { PanelInfo } from '../lib/types'

/** Filters live in the URL: shareable, back-button friendly, no secrets involved. */
export function useFilters(panels: PanelInfo[] | null) {
  const [sp, setSp] = useSearchParams()
  const raw = useMemo(() => parseFilters(sp), [sp])
  const filters = useMemo(() => (panels ? sanitizeFilters(raw, panels) : null), [raw, panels])
  const demoState = sp.get('demo_state') ?? undefined

  const write = useCallback(
    (next: Filters, replace = false) => {
      const out = serializeFilters(next)
      const ds = new URLSearchParams(window.location.search).get('demo_state')
      if (ds) out.set('demo_state', ds)
      setSp(out, { replace })
    },
    [setSp],
  )

  // A stale panel/node pick in the URL is cleaned up once panels are known.
  useEffect(() => {
    if (filters && filters !== raw) write(filters, true)
  }, [filters, raw, write])

  const update = useCallback(
    (patch: Partial<Filters> | ((f: Filters) => Filters)) => {
      const base = filters ?? raw
      write(typeof patch === 'function' ? patch(base) : { ...base, ...patch })
    },
    [filters, raw, write],
  )

  return { filters, update, demoState }
}
