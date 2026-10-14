import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { ApiError, fetchMe, login as apiLogin, loginMfa as apiLoginMfa, logout as apiLogout, onUnauthorized, setCsrf } from './api'
import type { Me } from './types'

type State = { status: 'loading' } | { status: 'anon'; expired: boolean } | { status: 'authed'; me: Me }

interface AuthApi {
  state: State
  /** Resolves with null when signed in, or with the token to send together with a code. */
  login: (username: string, password: string) => Promise<{ mfaToken: string } | null>
  loginMfa: (token: string, code: string) => Promise<void>
  refresh: () => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<AuthApi | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ status: 'loading' })

  const accept = useCallback((me: Me) => {
    setCsrf(me.csrf_token)
    setState({ status: 'authed', me })
  }, [])

  useEffect(() => {
    const ac = new AbortController()
    fetchMe(ac.signal)
      .then(accept)
      .catch((e) => {
        if ((e as Error).name === 'AbortError') return
        setCsrf('')
        setState({ status: 'anon', expired: false })
      })
    onUnauthorized(() => {
      setCsrf('')
      setState((s) => (s.status === 'authed' ? { status: 'anon', expired: true } : s))
    })
    return () => {
      ac.abort()
      onUnauthorized(null)
    }
  }, [accept])

  const login = useCallback(async (username: string, password: string) => {
    const r = await apiLogin(username, password)
    if ('mfa_required' in r) return { mfaToken: r.mfa_token }
    accept(r)
    return null
  }, [accept])

  const loginMfa = useCallback(async (token: string, code: string) => {
    accept(await apiLoginMfa(token, code))
  }, [accept])

  const refresh = useCallback(async () => {
    accept(await fetchMe())
  }, [accept])

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) throw e
    }
    setCsrf('')
    setState({ status: 'anon', expired: false })
  }, [])

  const value = useMemo(() => ({ state, login, loginMfa, refresh, logout }), [state, login, loginMfa, refresh, logout])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthApi {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth outside AuthProvider')
  return v
}

/** Role helpers on the current account. */
export function can(me: Me, panelId: string, need: 'view' | 'operate' | 'admin'): boolean {
  if (me.account.is_owner) return true
  const role = me.memberships.find((m) => m.panel_id === panelId)?.role
  const rank = { viewer: 1, operator: 2, admin: 3 }[role ?? 'viewer'] ?? 0
  if (!role) return false
  return rank >= { view: 1, operate: 2, admin: 3 }[need]
}
