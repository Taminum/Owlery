import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle2, Circle, CircleDot, ExternalLink, Rocket } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useLoad } from '../hooks/useLoad'
import { Card, Chip } from '../components/ui'
import { GhostButton } from '../components/Modal'
import { PageHead, TableSkeleton } from '../components/Analyzer'

interface Counts {
  panels: number; panels_synced: number; nodes: number; node_agents: number; security_hosts: number; security_agents: number
  awg_servers: number; notify_channels: number; bills: number; dns_maps: number
}

type State = 'done' | 'partial' | 'todo'

interface Step {
  id: string
  state: State
  optional?: boolean
  to: string
  lines: number // how many numbered instructions the step has
  docs?: { href: string; label: MsgKey }
}

const DOCS = 'https://github.com/Taminum/Owlery/blob/master/docs/'

export function steps(c: Counts, mfa: boolean): Step[] {
  const pick = (done: boolean, partial = false): State => (done ? 'done' : partial ? 'partial' : 'todo')
  return [
    { id: 'panel', state: pick(c.panels > 0 && c.panels_synced > 0, c.panels > 0), to: '/panels', lines: 4 },
    { id: 'node', state: pick(c.node_agents > 0, c.nodes > 0), to: '/panels', lines: 4, docs: { href: `${DOCS}AGENT.md`, label: 'start.docs.panels' } },
    { id: 'sec', state: pick(c.security_agents > 0, c.security_hosts > 0), to: '/security', lines: 4, docs: { href: `${DOCS}SECURITY_AGENT.md`, label: 'start.docs.sec' } },
    { id: 'tg', state: pick(c.notify_channels > 0), to: '/settings?tab=notify', lines: 4, docs: { href: `${DOCS}TELEGRAM.md`, label: 'start.docs.tg' } },
    { id: 'pay', state: pick(c.bills > 0), to: '/billing', lines: 3 },
    { id: 'safe', state: pick(mfa), to: '/settings', lines: 3 },
    { id: 'awg', state: pick(c.awg_servers > 0), optional: true, to: '/awg', lines: 2, docs: { href: `${DOCS}AWG_COLLECTOR.md`, label: 'start.docs.awg' } },
    { id: 'dns', state: pick(c.dns_maps > 0), optional: true, to: '/intel', lines: 1 },
  ]
}

const ICON = { done: CheckCircle2, partial: CircleDot, todo: Circle } as const
const TONE = { done: 'text-green', partial: 'text-amber', todo: 'text-muted' } as const

function StepCard({ s, open, onToggle }: { s: Step; open: boolean; onToggle: () => void }) {
  const Icon = ICON[s.state]
  const key = (k: string) => `start.s.${s.id}.${k}` as MsgKey
  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <Icon size={22} aria-hidden className={`mt-0.5 shrink-0 ${TONE[s.state]}`} />
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold leading-5">{t(key('title'))}{s.optional && <span className="ml-2 text-xs font-normal text-muted">{t('start.optional')}</span>}</h2>
            <p className="mt-0.5 text-[13px] text-muted">{t(key('why'))}</p>
            <p className={`mt-1 text-[13px] ${TONE[s.state]}`}>
              <span className="sr-only">{t(s.state === 'done' ? 'start.done' : s.state === 'partial' ? 'start.partial' : 'start.todo')}: </span>
              {s.state === 'done' ? t(key('done')) : s.state === 'partial' ? t(key('partial')) : ''}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <GhostButton onClick={onToggle} aria-expanded={open}>{t('start.howto')}</GhostButton>
          <Link to={s.to} className="inline-flex h-10 items-center rounded-control bg-blue px-4 text-[14px] font-medium text-white hover:brightness-110">{t('start.open')}</Link>
        </div>
      </div>
      {open && (
        <div className="mt-3 border-t border-line pt-3">
          <ol className="list-decimal space-y-1.5 pl-5 text-[13px] leading-5">
            {Array.from({ length: s.lines }, (_, i) => <li key={i}>{t(key(String(i + 1)))}</li>)}
          </ol>
          {s.docs && (
            <a href={s.docs.href} target="_blank" rel="noreferrer noopener" className="mt-3 inline-flex items-center gap-1.5 text-[13px] text-cyan underline-offset-2 hover:underline">
              <ExternalLink size={14} aria-hidden />{t(s.docs.label)} · {t('start.docs')}
            </a>
          )}
        </div>
      )}
    </Card>
  )
}

export default function Start() {
  const { state: auth } = useAuth()
  const owner = auth.status === 'authed' && auth.me.account.is_owner
  const mfa = auth.status === 'authed' && auth.me.mfa_enabled === true
  const q = useLoad((s) => (owner ? api.get<Counts>('/api/v1/onboarding', s) : Promise.resolve(null)), [owner], 20_000)
  const [open, setOpen] = useState<string | null>(null)
  const list = q.data ? steps(q.data, mfa) : []
  const required = list.filter((s) => !s.optional)
  const done = required.filter((s) => s.state === 'done').length
  // The first thing not done is opened for a newcomer; a choice of their own wins.
  const first = list.find((s) => !s.optional && s.state !== 'done')?.id ?? null
  const shown = open ?? first
  return (
    <div className="space-y-4">
      <PageHead title={t('start.title')} subtitle={t('start.subtitle')} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <Chip icon={Rocket} tone={done === required.length ? 'green' : 'cyan'}>{t('start.progress', { done, total: required.length })}</Chip>
            <div className="h-2 w-48 overflow-hidden rounded-full bg-elevated" role="progressbar" aria-valuemin={0} aria-valuemax={required.length} aria-valuenow={done}>
              <div className="h-full rounded-full bg-green" style={{ width: `${required.length ? (done * 100) / required.length : 0}%` }} />
            </div>
          </div>
          {list.map((s) => <StepCard key={s.id} s={s} open={shown === s.id} onToggle={() => setOpen(shown === s.id ? '' : s.id)} />)}
        </>
      )}
    </div>
  )
}

/** A short pointer to the guide, for the places where a newcomer is stuck with nothing to look at. */
export function StartHint() {
  const { state: auth } = useAuth()
  if (!(auth.status === 'authed' && auth.me.account.is_owner)) return null
  return (
    <Card title={t('start.hint.title')} note={t('start.hint.text')}>
      <Link to="/start" className="inline-flex h-10 items-center gap-2 rounded-control bg-blue px-4 text-[14px] font-medium text-white hover:brightness-110"><Rocket size={16} aria-hidden />{t('start.hint.go')}</Link>
    </Card>
  )
}
