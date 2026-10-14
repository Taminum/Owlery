import { useState, type FormEvent } from 'react'
import { LockKeyhole, ShieldCheck } from 'lucide-react'
import { t } from '../i18n'
import { ApiError } from '../lib/api'
import { useAuth } from '../lib/auth'
import { Field, PrimaryButton, inputCls } from '../components/Modal'

export default function Login({ expired }: { expired: boolean }) {
  const { login, loginMfa } = useAuth()
  const [mfaToken, setMfaToken] = useState('')
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const next = await login(username.trim(), password)
      if (next) {
        setMfaToken(next.mfaToken)
        setPassword('')
        setBusy(false)
      }
    } catch (err) {
      setPassword('') // never keep a rejected password in the form
      if (err instanceof ApiError && err.status === 429) setError(t('auth.rateLimited'))
      else if (err instanceof ApiError && err.code === 'network') setError(t('auth.network'))
      else setError(t('auth.error'))
      setBusy(false)
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await loginMfa(mfaToken, code)
    } catch (err) {
      setCode('')
      if (err instanceof ApiError && err.status === 429) setError(t('auth.rateLimited'))
      else if (err instanceof ApiError && err.code === 'network') setError(t('auth.network'))
      else setError(t('auth.mfa.error'))
      setBusy(false)
    }
  }

  if (mfaToken) {
    return (
      <main className="grid min-h-full place-items-center px-4 py-10">
        <form onSubmit={submitCode} className="w-full max-w-[400px] space-y-5 rounded-card border border-line bg-surface p-6 shadow-2xl" aria-labelledby="mfa-title">
          <div className="space-y-1.5">
            <span className="grid h-11 w-11 place-items-center rounded-full border border-line bg-elevated text-cyan"><ShieldCheck size={20} aria-hidden /></span>
            <h1 id="mfa-title" className="pt-1 text-xl font-semibold">{t('auth.mfa.title')}</h1>
            <p className="text-[13px] text-muted">{t('auth.mfa.subtitle')}</p>
          </div>
          <Field label={t('auth.mfa.code')} htmlFor="mfa-code" hint={t('auth.mfa.hint')}>
            <input id="mfa-code" className={inputCls} value={code} onChange={(e) => setCode(e.target.value)} inputMode="text" autoComplete="one-time-code" spellCheck={false} maxLength={16} data-autofocus required />
          </Field>
          {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
          <PrimaryButton type="submit" disabled={busy || code.trim().length < 6} className="w-full">{busy ? t('auth.submitting') : t('auth.mfa.submit')}</PrimaryButton>
          <button type="button" onClick={() => { setMfaToken(''); setCode(''); setError('') }} className="w-full text-center text-[13px] text-muted hover:text-fg">{t('auth.mfa.back')}</button>
        </form>
      </main>
    )
  }

  return (
    <main className="grid min-h-full place-items-center px-4 py-10">
      <form onSubmit={submit} className="w-full max-w-[400px] space-y-5 rounded-card border border-line bg-surface p-6 shadow-2xl" aria-labelledby="login-title">
        <div className="space-y-1.5">
          <span className="grid h-11 w-11 place-items-center rounded-full border border-line bg-elevated text-cyan"><LockKeyhole size={20} aria-hidden /></span>
          <h1 id="login-title" className="pt-1 text-xl font-semibold">{t('auth.title')}</h1>
          <p className="text-[13px] text-muted">{t('auth.subtitle')}</p>
        </div>
        {expired && <p role="status" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{t('auth.expired')}</p>}
        <Field label={t('auth.username')} htmlFor="login-username">
          <input id="login-username" className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} data-autofocus required />
        </Field>
        <Field label={t('auth.password')} htmlFor="login-password">
          <input id="login-password" className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <PrimaryButton type="submit" disabled={busy || !username || !password} className="w-full">{busy ? t('auth.submitting') : t('auth.submit')}</PrimaryButton>
      </form>
    </main>
  )
}
