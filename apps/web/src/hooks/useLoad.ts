import { useEffect, useRef, useState } from 'react'
import { busyStart } from '../lib/busy'
import { errorText } from '../lib/errors'

/**
 * Loads data when `deps` change, optionally polling, and exposes `reload`. State is only set in
 * promise callbacks, never synchronously in the effect.
 */
export function useLoad<T>(fetcher: (signal: AbortSignal) => Promise<T>, deps: unknown[], pollMs = 0) {
  const [state, setState] = useState<{ data: T | null; error: string }>({ data: null, error: '' })
  const [nonce, setNonce] = useState(0)
  const polled = useRef(false)

  useEffect(() => {
    const ac = new AbortController()
    // A refresh by the poll timer is not something the user waits for; everything else is.
    const done = polled.current ? () => {} : busyStart()
    polled.current = false
    fetcher(ac.signal)
      .then((data) => setState({ data, error: '' }))
      .catch((e) => {
        if ((e as Error).name !== 'AbortError') setState((s) => ({ ...s, error: errorText(e) }))
      })
      .finally(done)
    return () => {
      ac.abort()
      done()
    }
    // The fetcher is intentionally excluded: callers list exactly what should trigger a reload.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps])

  useEffect(() => {
    if (!pollMs) return
    const id = setInterval(() => {
      polled.current = true
      setNonce((n) => n + 1)
    }, pollMs)
    return () => clearInterval(id)
  }, [pollMs])

  return { data: state.data, error: state.error, reload: () => setNonce((n) => n + 1) }
}
