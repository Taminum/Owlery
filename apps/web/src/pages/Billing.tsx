import { useState } from 'react'
import { Plus } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { errorText } from '../lib/errors'
import { useAuth } from '../lib/auth'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { DangerButton, Field, GhostButton, Modal, PrimaryButton, inputCls } from '../components/Modal'
import { PageHead, TableSkeleton } from '../components/Analyzer'

interface Bill { id: string; name: string; provider: string; amount: number; currency: string; period_months: number; next_due: string; note: string; last_paid_on: string | null }
interface BillsResponse { bills: Bill[]; monthly: Record<string, number> }

const PERIODS = [1, 3, 6, 12] as const

function daysUntil(due: string): number {
  const today = new Date()
  const a = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate())
  const [y, m, d] = due.split('-').map(Number)
  return Math.round((Date.UTC(y, m - 1, d) - a) / 86_400_000)
}

function dueChip(due: string) {
  const n = daysUntil(due)
  if (n < 0) return <Chip tone="red">{t('bill.due.overdue', { n: -n })}</Chip>
  if (n === 0) return <Chip tone="amber">{t('bill.due.today')}</Chip>
  if (n <= 3) return <Chip tone="amber">{t('bill.due.in', { n })}</Chip>
  return <Chip tone="muted">{t('bill.due.in', { n })}</Chip>
}

const money = (v: number, cur: string) => `${v.toLocaleString('ru-RU', { minimumFractionDigits: 0, maximumFractionDigits: 2 })} ${cur}`

function Edit({ bill, onClose, onDone }: { bill: Bill | null; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(bill?.name ?? '')
  const [provider, setProvider] = useState(bill?.provider ?? '')
  const [amount, setAmount] = useState(bill ? String(bill.amount) : '')
  const [currency, setCurrency] = useState(bill?.currency ?? 'EUR')
  const [period, setPeriod] = useState(bill?.period_months ?? 1)
  const [due, setDue] = useState(bill?.next_due ?? '')
  const [note, setNote] = useState(bill?.note ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const amountNum = Number(amount.replace(',', '.'))
  const valid = name.trim() !== '' && amount.trim() !== '' && Number.isFinite(amountNum) && amountNum >= 0 && /^[A-Za-z]{3}$/.test(currency) && /^\d{4}-\d{2}-\d{2}$/.test(due)

  async function go() {
    setBusy(true)
    setError('')
    const body = { name, provider, amount: amountNum, currency, period_months: period, next_due: due, note }
    try {
      if (bill) await api.put(`/api/v1/billing/${bill.id}`, body)
      else await api.post('/api/v1/billing', body)
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }

  return (
    <Modal title={bill ? t('bill.edit') : t('bill.add')} onClose={onClose} busy={busy}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void go() }}>
        <Field label={t('bill.name')} hint={t('bill.name.hint')} htmlFor="bill-name"><input id="bill-name" data-autofocus className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} /></Field>
        <Field label={t('bill.provider')} htmlFor="bill-provider"><input id="bill-provider" className={inputCls} value={provider} onChange={(e) => setProvider(e.target.value)} maxLength={80} /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label={t('bill.amount')} htmlFor="bill-amount"><input id="bill-amount" className={inputCls} value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" /></Field>
          <Field label={t('bill.currency')} hint={t('bill.currency.hint')} htmlFor="bill-cur"><input id="bill-cur" className={`${inputCls} uppercase`} value={currency} onChange={(e) => setCurrency(e.target.value.slice(0, 3))} spellCheck={false} /></Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label={t('bill.period')} htmlFor="bill-period">
            <select id="bill-period" className={inputCls} value={period} onChange={(e) => setPeriod(Number(e.target.value))}>
              {PERIODS.map((p) => <option key={p} value={p}>{t(`bill.period.${p}` as MsgKey)}</option>)}
            </select>
          </Field>
          <Field label={t('bill.due')} htmlFor="bill-due"><input id="bill-due" type="date" className={inputCls} value={due} onChange={(e) => setDue(e.target.value)} /></Field>
        </div>
        <Field label={t('bill.note')} htmlFor="bill-note"><input id="bill-note" className={inputCls} value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} /></Field>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <PrimaryButton type="submit" disabled={!valid || busy}>{t('bill.save')}</PrimaryButton>
        </div>
      </form>
    </Modal>
  )
}

function Remove({ bill, onClose, onDone }: { bill: Bill; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function go() {
    setBusy(true)
    try {
      await api.del(`/api/v1/billing/${bill.id}`)
      onDone()
      onClose()
    } catch (e) {
      setError(errorText(e))
      setBusy(false)
    }
  }
  return (
    <Modal title={t('bill.delete')} onClose={onClose} busy={busy}>
      <div className="space-y-4">
        <p className="text-[13px]">{t('bill.delete.confirm', { name: bill.name })}</p>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex justify-end gap-3">
          <GhostButton onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
          <DangerButton onClick={() => void go()} disabled={busy}>{t('bill.delete')}</DangerButton>
        </div>
      </div>
    </Modal>
  )
}

export default function Billing() {
  const { state: auth } = useAuth()
  const owner = auth.status === 'authed' && auth.me.account.is_owner
  const q = useLoad((s) => (owner ? api.get<BillsResponse>('/api/v1/billing', s) : Promise.resolve(null)), [owner], 60_000)
  const [editing, setEditing] = useState<Bill | 'new' | null>(null)
  const [removing, setRemoving] = useState<Bill | null>(null)
  const [paying, setPaying] = useState('')
  const [error, setError] = useState('')

  async function paid(b: Bill) {
    setPaying(b.id)
    setError('')
    try {
      await api.post(`/api/v1/billing/${b.id}/paid`)
      q.reload()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setPaying('')
    }
  }

  const data = q.data
  const monthly = data ? Object.entries(data.monthly).map(([c, v]) => money(v, c)).join(' + ') : ''
  return (
    <div className="space-y-4">
      <PageHead title={t('bill.title')} subtitle={t('bill.subtitle')} />
      {(q.error || error) && <p role="alert" className="text-[13px] text-red">{q.error || error}</p>}
      {!data && !q.error && <TableSkeleton />}
      {data && (
        <Card note={monthly ? t('bill.monthly', { sum: monthly }) : undefined}
          right={<PrimaryButton onClick={() => setEditing('new')}><span className="inline-flex items-center gap-1.5"><Plus size={16} aria-hidden />{t('bill.add')}</span></PrimaryButton>}>
          {data.bills.length === 0 ? <p className="py-6 text-center text-[13px] text-muted">{t('bill.empty')}</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <caption className="sr-only">{t('bill.title')}</caption>
                <thead><tr className="text-left text-xs text-muted">
                  <th scope="col" className="px-2 py-2 font-medium">{t('bill.col.name')}</th>
                  <th scope="col" className="px-2 py-2 text-right font-medium">{t('bill.col.amount')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('bill.col.period')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('bill.col.due')}</th>
                  <th scope="col" className="px-2 py-2 font-medium">{t('bill.col.paid')}</th>
                  <th scope="col" className="px-2 py-2" />
                </tr></thead>
                <tbody>
                  {data.bills.map((b) => (
                    <tr key={b.id} className="border-t border-line/60">
                      <td className="px-2 py-2">
                        <span className="font-medium text-fg">{b.name}</span>
                        {b.provider && <span className="ml-2 text-xs text-muted">{b.provider}</span>}
                        {b.note && <span className="block text-xs text-muted">{b.note}</span>}
                      </td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-right">{money(b.amount, b.currency)}</td>
                      <td className="px-2 py-2 text-muted">{t(`bill.period.${b.period_months}` as MsgKey) || `${b.period_months}`}</td>
                      <td className="whitespace-nowrap px-2 py-2"><span className="tnum mr-2">{b.next_due.split('-').reverse().join('.')}</span>{dueChip(b.next_due)}</td>
                      <td className="tnum whitespace-nowrap px-2 py-2 text-muted">{b.last_paid_on ? b.last_paid_on.split('-').reverse().join('.') : '—'}</td>
                      <td className="px-2 py-2">
                        <div className="flex flex-wrap justify-end gap-2">
                          <PrimaryButton onClick={() => void paid(b)} disabled={paying === b.id} title={t('bill.paid.hint')}>{t('bill.paid')}</PrimaryButton>
                          <GhostButton onClick={() => setEditing(b)}>{t('bill.edit')}</GhostButton>
                          <GhostButton onClick={() => setRemoving(b)}>{t('bill.delete')}</GhostButton>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
      {editing && <Edit bill={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onDone={() => q.reload()} />}
      {removing && <Remove bill={removing} onClose={() => setRemoving(null)} onDone={() => q.reload()} />}
    </div>
  )
}
