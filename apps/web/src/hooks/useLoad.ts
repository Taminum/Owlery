import { useEffect, useState } from 'react'
import { errorText } from '../lib/errors'

/**
 * Loads data when `deps` change, optionally polling, and exposes `reload`. State is only set in
 * promise callbacks, never synchronously in the effect.
 */
export function useLoad<T>(fetcher: (signal: AbortSignal) => Promise<T>, deps: unknown[], pollMs = 0) {
  const [state, setState] = useState<{ data: T | null; error: string }>({ data: null, error: '' })
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    const ac = new AbortController()
    fetcher(ac.signal)
      .then((data) => setState({ data, error: '' }))
      .catch((e) => {
        if ((e as Error).name !== 'AbortError') setState((s) => ({ ...s, error: errorText(e) }))
      })
    return () => ac.abort()
    // The fetcher is intentionally excluded: callers list exactly what should trigger a reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps])

  useEffect(() => {
    if (!pollMs) return
    const id = setInterval(() => setNonce((n) => n + 1), pollMs)
    return () => clearInterval(id)
  }, [pollMs])

  return { data: state.data, error: state.error, reload: () => setNonce((n) => n + 1) }
}
