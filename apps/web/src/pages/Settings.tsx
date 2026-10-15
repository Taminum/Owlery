import { useState } from 'react'
import { Check, Copy, KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { toDataURL } from 'qrcode'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useApp } from '../lib/context'
import { useLoad } from '../hooks/useLoad'
import { errorText } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import type { AccountRow, AuditRow, Membership, Role, RulesResponse } from '../lib/types'
import { Card, Chip } from '../components/ui'
import AutoClassify from './AutoClassify'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { NotifyTab } from '../components/NotifyTab'

type Tab = 'profile' | 'accounts' | 'rules' | 'autoclassify' | 'notify' | 'audit'

export default function Settings() {
  const { state } = useAuth()
  const [tab, setTab] = useState<Tab>('profile')
  if (state.status !== 'authed') return null
  const owner = state.me.account.is_owner
  const tabs: { id: Tab; label: MsgKey; show: boolean }[] = [
    { id: 'profile', label: 'settings.tab.profile', show: true },
    { id: 'accounts', label: 'settings.tab.accounts', show: owner },
    { id: 'rules', label: 'settings.tab.rules', show: owner },
    { id: 'autoclassify', label: 'settings.tab.autoclassify', show: owner },
    { id: 'notify', label: 'settings.tab.notify', show: owner },
    { id: 'audit', label: 'settings.tab.audit', show: true },
  ]
  return (
    <div className="space-y-5">
      <h1 className="text-[22px] font-semibold leading-8">{t('settings.title')}</h1>
      <div role="tablist" aria-label={t('settings.title')} className="flex flex-wrap gap-1 border-b border-line">
        {tabs.filter((x) => x.show).map((x) => (
          <button key={x.id} role="tab" type="button" id={`tab-${x.id}`} aria-selected={tab === x.id} aria-controls={`panel-${x.id}`} onClick={() => setTab(x.id)}
            className={`-mb-px border-b-2 px-3.5 py-2.5 text-[14px] ${tab === x.id ? 'border-cyan font-medium text-fg' : 'border-transparent text-muted hover:text-fg'}`}>
            {t(x.label)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'profile' && <Profile />}
        {tab === 'accounts' && owner && <Accounts />}
        {tab === 'rules' && owner && <RulesTab />}
        {tab === 'autoclassify' && owner && <AutoClassify />}
        {tab === 'notify' && owner && <NotifyTab />}
        {tab === 'audit' && <Audit />}
      </div>
    </div>
  )
}

function Profile() {
  const { state, logout } = useAuth()
  const { panels } = useApp()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (state.status !== 'authed') return null
  const me = state.me

  async function submit() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/auth/password', { current_password: current, new_password: next })
      setCurrent('')
      setNext('')
      await logout().catch(() => undefined)
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title={t('profile.password')}>
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && current && next) void submit() }}>
          <Field label={t('profile.current')} htmlFor="p-cur"><input id="p-cur" className={inputCls} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
          <Field label={t('profile.new')} hint={t('profile.hint')} htmlFor="p-new"><input id="p-new" className={inputCls} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
          {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
          <PrimaryButton type="submit" disabled={busy || !current || next.length < 12}>{t('profile.submit')}</PrimaryButton>
        </form>
      </Card>
      <Card title={t('mfa.title')}><MfaCard enabled={!!me.mfa_enabled} /></Card>
      <Card title={t('profile.roles')}>
        <p className="mb-3 text-[14px]"><strong className="font-semibold">{me.account.username}</strong> {me.account.is_owner && <Chip tone="cyan">{t('role.owner')}</Chip>}</p>
        {me.account.is_owner ? <p className="text-[13px] text-muted">{t('accounts.ownerHint')}</p> : me.memberships.length === 0 ? <p className="text-[13px] text-muted">{t('profile.noPanels')}</p> : (
          <ul className="space-y-1.5 text-[13px]">
            {me.memberships.map((m) => <li key={m.panel_id} className="flex justify-between gap-3"><span>{panels.find((p) => p.id === m.panel_id)?.name ?? m.panel_id}</span><span className="text-muted">{t(`role.${m.role}` as MsgKey)}</span></li>)}
          </ul>
        )}
      </Card>
    </div>
  )
}

type MfaStep = { kind: 'idle' } | { kind: 'scan'; secret: string; uri: string } | { kind: 'codes'; codes: string[] } | { kind: 'off' }

/** Two-factor sign-in: turn it on with an authenticator app, keep the recovery codes, turn it off. */
function MfaCard({ enabled }: { enabled: boolean }) {
  const { refresh } = useAuth()
  const [step, setStep] = useState<MfaStep>({ kind: 'idle' })
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  async function start() {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ secret: string; uri: string }>('/api/v1/account/mfa/setup', {})
      setQr(await toDataURL(r.uri, { margin: 1, width: 200 }))
      setStep({ kind: 'scan', secret: r.secret, uri: r.uri })
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  async function confirm() {
    setBusy(true)
    setError('')
    try {
      const r = await api.post<{ recovery_codes: string[] }>('/api/v1/account/mfa/enable', { code: code.trim() })
      setCode('')
      setQr('')
      setStep({ kind: 'codes', codes: r.recovery_codes })
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  async function disable() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/account/mfa/disable', { password, code: code.trim() })
      setPassword('')
      setCode('')
      setStep({ kind: 'idle' })
      await refresh()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  if (step.kind === 'codes') {
    const text = step.codes.join('\n')
    return (
      <div className="space-y-3">
        <p role="alert" className="rounded-control border border-amber/40 bg-amber/10 px-3 py-2 text-[13px] text-amber">{t('mfa.codesWarn')}</p>
        <pre aria-label={t('mfa.codes')} className="rounded-control border border-line bg-canvas p-3 font-mono text-[13px] leading-6">{text}</pre>
        <div className="flex gap-2">
          <GhostButton onClick={() => void navigator.clipboard?.writeText(text).then(() => setCopied(true))}>
            <span className="inline-flex items-center gap-2">{copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}{copied ? t('agents.copied') : t('agents.copy')}</span>
          </GhostButton>
          <PrimaryButton onClick={() => { setStep({ kind: 'idle' }); void refresh() }}>{t('mfa.saved')}</PrimaryButton>
        </div>
      </div>
    )
  }

  if (step.kind === 'scan') {
    return (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (!busy && code.trim().length >= 6) void confirm() }}>
        <p className="text-[13px] text-muted">{t('mfa.scan')}</p>
        {qr && <img src={qr} width={200} height={200} alt={t('mfa.qrAlt')} className="rounded-control bg-white p-1" />}
        <div className="text-[13px]"><span className="text-muted">{t('mfa.manual')}: </span><code className="break-all font-mono">{step.secret}</code></div>
        <Field label={t('mfa.code')} htmlFor="mfa-enable-code"><input id="mfa-enable-code" className={inputCls} value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={8} /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex gap-2">
          <PrimaryButton type="submit" disabled={busy || code.trim().length < 6}>{t('mfa.enable')}</PrimaryButton>
          <GhostButton onClick={() => { setStep({ kind: 'idle' }); setCode(''); setQr('') }}>{t('common.cancel')}</GhostButton>
        </div>
      </form>
    )
  }

  if (step.kind === 'off') {
    return (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (!busy && password && code.trim()) void disable() }}>
        <p className="text-[13px] text-muted">{t('mfa.offHint')}</p>
        <Field label={t('profile.current')} htmlFor="mfa-off-pass"><input id="mfa-off-pass" className={inputCls} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <Field label={t('mfa.codeOrRecovery')} htmlFor="mfa-off-code"><input id="mfa-off-code" className={inputCls} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" maxLength={16} /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex gap-2">
          <PrimaryButton type="submit" disabled={busy || !password || !code.trim()}>{t('mfa.disable')}</PrimaryButton>
          <GhostButton onClick={() => { setStep({ kind: 'idle' }); setCode(''); setPassword(''); setError('') }}>{t('common.cancel')}</GhostButton>
        </div>
      </form>
    )
  }

  return (
    <div className="space-y-3">
      <p className="flex items-center gap-2 text-[14px]">
        <ShieldCheck size={16} aria-hidden className={enabled ? 'text-green' : 'text-muted'} />
        {enabled ? t('mfa.on') : t('mfa.off')}
      </p>
      <p className="text-[13px] text-muted">{enabled ? t('mfa.onHint') : t('mfa.offIntro')}</p>
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {enabled
        ? <GhostButton onClick={() => { setError(''); setStep({ kind: 'off' }) }}>{t('mfa.disable')}</GhostButton>
        : <PrimaryButton disabled={busy} onClick={() => void start()}>{t('mfa.start')}</PrimaryButton>}
    </div>
  )
}

/** Rules added by hand. Deleting one brings back the built-in rule for the same domain, if there is one. */
function RulesTab() {
  const { data, error, reload } = useLoad((s) => api.get<RulesResponse>('/api/v1/rules', s), [])
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  async function remove(id: string) {
    setBusy(id)
    setErr('')
    try {
      await api.del(`/api/v1/rules/${id}`)
      reload()
    } catch (e) {
      setErr(errorText(e))
    } finally {
      setBusy('')
    }
  }
  return (
    <Card title={t('rules.title')} note={t('rules.note')}>
      {(error || err) && <p role="alert" className="mb-2 text-[13px] text-red">{error || err}</p>}
      {data && data.rules.length === 0 && <p className="py-4 text-center text-[13px] text-muted">{t('rules.none')}</p>}
      {data && data.rules.length > 0 && (
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('rules.title')}</caption>
          <thead><tr className="text-left text-xs text-muted">
            <th scope="col" className="px-2 py-2 font-medium">{t('rules.pattern')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('rules.service')}</th>
            <th scope="col" className="px-2 py-2 font-medium">{t('sites.category')}</th>
            <th scope="col" className="px-2 py-2" />
          </tr></thead>
          <tbody>
            {data.rules.map((r) => (
              <tr key={r.id} className="border-t border-line/60">
                <td className="px-2 py-2 font-medium">{r.pattern}</td>
                <td className="px-2 py-2 text-muted">{r.service}</td>
                <td className="px-2 py-2">{r.category}</td>
                <td className="px-2 py-2 text-right"><GhostButton className="!h-8 !border-red/50 !px-2.5 !text-xs !text-red" disabled={busy === r.id} onClick={() => void remove(r.id)} aria-label={`${t('rules.delete')}: ${r.pattern}`}>{t('rules.delete')}</GhostButton></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

function MembershipEditor({ value, onChange }: { value: Membership[]; onChange: (v: Membership[]) => void }) {
  const { panels } = useApp()
  const free = panels.filter((p) => !value.some((m) => m.panel_id === p.id))
  return (
    <fieldset className="space-y-2">
      <legend className="mb-1 text-[13px] font-medium">{t('accounts.panels')}</legend>
      {value.map((m, i) => (
        <div key={m.panel_id} className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate text-[13px]">{panels.find((p) => p.id === m.panel_id)?.name ?? m.panel_id}</span>
          <label className="sr-only" htmlFor={`role-${m.panel_id}`}>{t('accounts.role')}</label>
          <select id={`role-${m.panel_id}`} className={`${inputCls} !w-auto`} value={m.role} onChange={(e) => onChange(value.map((x, j) => (j === i ? { ...x, role: e.target.value as Membership['role'] } : x)))}>
            {(['viewer', 'operator', 'admin'] as const).map((r) => <option key={r} value={r}>{t(`role.${r}` as MsgKey)}</option>)}
          </select>
          <button type="button" aria-label={t('common.close')} className="grid h-9 w-9 place-items-center rounded-control text-muted hover:bg-elevated" onClick={() => onChange(value.filter((_, j) => j !== i))}><Trash2 size={15} aria-hidden /></button>
        </div>
      ))}
      {free.length > 0 && (
        <div className="flex items-center gap-2">
          <label className="sr-only" htmlFor="add-panel">{t('accounts.addPanel')}</label>
          <select id="add-panel" className={`${inputCls} !w-auto`} value="" onChange={(e) => e.target.value && onChange([...value, { panel_id: e.target.value, role: 'viewer' }])}>
            <option value="">{t('accounts.addPanel')}…</option>
            {free.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
      )}
      <ul className="space-y-0.5 pt-1 text-xs text-muted">
        {(['viewer', 'operator', 'admin'] as const).map((r) => <li key={r}><strong className="font-medium text-fg/80">{t(`role.${r}` as MsgKey)}</strong>: {t(`accounts.roleHelp.${r}` as MsgKey)}</li>)}
      </ul>
    </fieldset>
  )
}

type AccDialog = { kind: 'create' } | { kind: 'access' | 'password'; account: AccountRow } | null

function Accounts() {
  const { state } = useAuth()
  const { filters } = useApp()
  const accounts = useLoad((signal) => api.get<{ accounts: AccountRow[] }>('/api/v1/accounts', signal), [])
  const rows = accounts.data?.accounts ?? null
  const load = accounts.reload
  const [actionError, setActionError] = useState('')
  const error = actionError || accounts.error
  const [notice, setNotice] = useState('')
  const [dialog, setDialog] = useState<AccDialog>(null)
  if (state.status !== 'authed') return null
  const myId = state.me.account.id

  async function toggle(a: AccountRow) {
    try { await api.patch(`/api/v1/accounts/${a.id}`, { disabled: !a.disabled }); setNotice(t('accounts.saved')); setActionError(''); load() } catch (e) { setActionError(errorText(e)) }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-[16px] font-semibold">{t('accounts.title')}</h2>
        <PrimaryButton onClick={() => setDialog({ kind: 'create' })}><span className="inline-flex items-center gap-2"><Plus size={16} aria-hidden />{t('accounts.add')}</span></PrimaryButton>
      </div>
      <div aria-live="polite">
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        {notice && <p role="status" className="text-[13px] text-green">{notice}</p>}
      </div>
      <div className="overflow-x-auto rounded-card border border-line bg-surface">
        <table className="w-full border-collapse text-[13px]">
          <caption className="sr-only">{t('accounts.title')}</caption>
          <thead><tr className="text-left text-xs text-muted">
            <th scope="col" className="px-4 py-2.5 font-medium">{t('accounts.username')}</th>
            <th scope="col" className="px-2 py-2.5 font-medium">{t('accounts.panels')}</th>
            <th scope="col" className="px-2 py-2.5 font-medium">{t('accounts.lastLogin')}</th>
            <th scope="col" className="px-4 py-2.5" />
          </tr></thead>
          <tbody>
            {rows?.map((a) => (
              <tr key={a.id} className="border-t border-line/60 align-top">
                <td className="px-4 py-2.5"><span className="font-medium">{a.username}</span>{' '}
                  {a.is_owner && <Chip tone="cyan">{t('role.owner')}</Chip>} {a.disabled && <Chip tone="red">{t('accounts.disabled')}</Chip>}</td>
                <td className="px-2 py-2.5 text-muted">{a.is_owner ? '—' : a.memberships.length === 0 ? '—' : a.memberships.map((m) => `${t(`role.${m.role}` as MsgKey)}`).join(', ')}</td>
                <td className="tnum px-2 py-2.5 text-muted">{a.last_login_at ? formatDateTime(a.last_login_at, filters.tz) : t('accounts.neverLoggedIn')}</td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    {!a.is_owner && <GhostButton className="!h-8 !px-2.5 !text-xs" onClick={() => setDialog({ kind: 'access', account: a })}>{t('accounts.editAccess')}</GhostButton>}
                    <GhostButton className="!h-8 !px-2.5 !text-xs" onClick={() => setDialog({ kind: 'password', account: a })}><span className="inline-flex items-center gap-1"><KeyRound size={13} aria-hidden />{t('accounts.resetPassword')}</span></GhostButton>
                    {a.id !== myId && <GhostButton className="!h-8 !px-2.5 !text-xs" onClick={() => void toggle(a)}>{a.disabled ? t('accounts.enable') : t('accounts.disable')}</GhostButton>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {dialog?.kind === 'create' && <CreateAccount onClose={() => setDialog(null)} onDone={() => { setNotice(t('accounts.saved')); load() }} />}
      {dialog?.kind === 'access' && <AccessDialog account={dialog.account} onClose={() => setDialog(null)} onDone={() => { setNotice(t('accounts.saved')); load() }} />}
      {dialog?.kind === 'password' && <ResetPassword account={dialog.account} onClose={() => setDialog(null)} onDone={() => setNotice(t('accounts.saved'))} />}
    </div>
  )
}

function CreateAccount({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [owner, setOwner] = useState(false)
  const [ms, setMs] = useState<Membership[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/accounts', { username: username.trim(), password, is_owner: owner, memberships: owner ? [] : ms })
      setPassword('')
      onDone()
      onClose()
    } catch (e) { setError(errorText(e)); setBusy(false) }
  }
  return (
    <Modal title={t('accounts.add')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && username && password) void submit() }}>
        <Field label={t('accounts.username')} htmlFor="a-user"><input id="a-user" className={inputCls} value={username} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={(e) => setUsername(e.target.value)} data-autofocus /></Field>
        <Field label={t('accounts.password')} hint={t('profile.hint')} htmlFor="a-pass"><input id="a-pass" className={inputCls} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <label className="flex items-start gap-2.5 text-[13px]"><input type="checkbox" className="mt-0.5 accent-cyan" checked={owner} onChange={(e) => setOwner(e.target.checked)} /><span>{t('accounts.owner')}<span className="block text-xs text-muted">{t('accounts.ownerHint')}</span></span></label>
        {!owner && <MembershipEditor value={ms} onChange={setMs} />}
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3"><GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton><PrimaryButton type="submit" disabled={busy || !username || !password}>{t('accounts.create')}</PrimaryButton></div>
      </form>
    </Modal>
  )
}

function AccessDialog({ account, onClose, onDone }: { account: AccountRow; onClose: () => void; onDone: () => void }) {
  const [ms, setMs] = useState<Membership[]>(account.memberships)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit() {
    setBusy(true)
    try { await api.put(`/api/v1/accounts/${account.id}/memberships`, { memberships: ms }); onDone(); onClose() } catch (e) { setError(errorText(e)); setBusy(false) }
  }
  return (
    <Modal title={`${t('accounts.editAccess')}: ${account.username}`} onClose={onClose} busy={busy}>
      <div className="space-y-4">
        <MembershipEditor value={ms} onChange={setMs} />
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3"><GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton><PrimaryButton onClick={() => void submit()} disabled={busy}>{t('common.save')}</PrimaryButton></div>
      </div>
    </Modal>
  )
}

function ResetPassword({ account, onClose, onDone }: { account: AccountRow; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit() {
    setBusy(true)
    try { await api.patch(`/api/v1/accounts/${account.id}`, { password: pw }); setPw(''); onDone(); onClose() } catch (e) { setError(errorText(e)); setBusy(false) }
  }
  return (
    <Modal title={`${t('accounts.resetPassword')}: ${account.username}`} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && pw) void submit() }}>
        <Field label={t('accounts.newPassword')} hint={t('profile.hint')} htmlFor="rp"><input id="rp" className={inputCls} type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} data-autofocus /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3"><GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton><PrimaryButton type="submit" disabled={busy || pw.length < 12}>{t('accounts.resetPassword')}</PrimaryButton></div>
      </form>
    </Modal>
  )
}

const ACTIONS: Record<string, string> = {
  'auth.login': 'Вход', 'auth.logout': 'Выход', 'auth.login_failed': 'Неудачный вход',
  'panel.probe': 'Проверка адреса и токена', 'panel.create': 'Панель подключена', 'panel.test': 'Проверка подключения',
  'panel.update': 'Изменены настройки', 'panel.token_rotate': 'Токен заменён', 'panel.disable': 'Панель отключена', 'panel.enable': 'Панель включена',
  'panel.delete': 'Панель удалена', 'panel.sync': 'Ручная синхронизация',
  'account.create': 'Аккаунт создан', 'account.disable': 'Аккаунт отключён', 'account.enable': 'Аккаунт включён',
  'account.password_reset': 'Пароль сброшен', 'account.password_change': 'Пароль изменён', 'account.memberships': 'Изменён доступ',
}

function Audit() {
  const { panels, filters } = useApp()
  const [panelId, setPanelId] = useState('')
  const q = (before: string) => {
    const p = new URLSearchParams()
    if (panelId) p.set('panel_id', panelId)
    if (before) p.set('before', before)
    return `/api/v1/audit?${p}`
  }
  const first = useLoad((signal) => api.get<{ entries: AuditRow[]; next_before: string }>(q(''), signal), [panelId])
  const [more, setMore] = useState<{ key: string; rows: AuditRow[]; next: string }>({ key: '', rows: [], next: '' })
  const [moreBusy, setMoreBusy] = useState(false)
  const [moreError, setMoreError] = useState('')
  const extra = more.key === panelId ? more : { key: panelId, rows: [], next: first.data?.next_before ?? '' }
  const rows = [...(first.data?.entries ?? []), ...extra.rows]
  const next = extra.rows.length > 0 ? extra.next : first.data?.next_before ?? ''
  const loading = first.data === null && !first.error
  const error = moreError || first.error

  async function loadMore() {
    setMoreBusy(true)
    try {
      const r = await api.get<{ entries: AuditRow[]; next_before: string }>(q(next))
      setMore({ key: panelId, rows: [...extra.rows, ...r.entries], next: r.next_before })
      setMoreError('')
    } catch (e) { setMoreError(errorText(e)) } finally { setMoreBusy(false) }
  }

  const name = (id: string | null) => (id ? panels.find((p) => p.id === id)?.name ?? '—' : '—')
  const detail = (m: Record<string, unknown>) => Object.entries(m).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`).join(' · ')

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <p className="text-[13px] text-muted">{t('audit.note')}</p>
        <div className="w-60">
          <Field label={t('audit.panel')} htmlFor="audit-panel">
            <select id="audit-panel" className={inputCls} value={panelId} onChange={(e) => setPanelId(e.target.value)}>
              <option value="">{t('audit.all')}</option>
              {panels.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </Field>
        </div>
      </div>
      {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
      {!loading && rows.length === 0 && !error && <p className="text-[13px] text-muted">{t('audit.empty')}</p>}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-line bg-surface">
          <table className="w-full border-collapse text-[13px]">
            <caption className="sr-only">{t('audit.title')}</caption>
            <thead><tr className="text-left text-xs text-muted">
              <th scope="col" className="px-4 py-2.5 font-medium">{t('audit.when')}</th>
              <th scope="col" className="px-2 py-2.5 font-medium">{t('audit.who')}</th>
              <th scope="col" className="px-2 py-2.5 font-medium">{t('audit.what')}</th>
              <th scope="col" className="px-2 py-2.5 font-medium">{t('audit.panel')}</th>
              <th scope="col" className="px-4 py-2.5 font-medium">{t('audit.details')}</th>
            </tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-t border-line/60 align-top">
                  <td className="tnum whitespace-nowrap px-4 py-2 text-muted">{formatDateTime(r.ts, filters.tz)}</td>
                  <td className="px-2 py-2">{r.actor_name ?? '—'}</td>
                  <td className="px-2 py-2">{ACTIONS[r.action] ?? r.action}</td>
                  <td className="px-2 py-2 text-muted">{name(r.panel_id)}</td>
                  <td className="max-w-[360px] break-words px-4 py-2 text-xs text-muted">{detail(r.metadata)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {next && <GhostButton disabled={moreBusy} onClick={() => void loadMore()}>{t('audit.more')}</GhostButton>}
    </div>
  )
}

export type { Role }
