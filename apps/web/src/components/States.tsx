import type { LucideIcon } from 'lucide-react'
import { CloudOff, Hourglass, Inbox, Server, ShieldAlert, SlidersHorizontal } from 'lucide-react'
import { t } from '../i18n'
import type { Failure } from '../hooks/useData'
import { Skeleton } from './ui'

function StatePanel({ icon: Icon, tone, title, text, action, onAction, footer }: { icon: LucideIcon; tone: string; title: string; text: string; action: string; onAction: () => void; footer?: string }) {
  return (
    <div role="status" className="flex flex-col items-center rounded-card border border-line bg-surface px-6 py-14 text-center">
      <span className={`mb-4 grid h-12 w-12 place-items-center rounded-full border border-line bg-elevated ${tone}`}>
        <Icon size={22} aria-hidden />
      </span>
      <h2 className="text-lg font-semibold text-fg">{title}</h2>
      <p className="mt-1.5 max-w-md text-[13px] leading-5 text-muted">{text}</p>
      <button type="button" onClick={onAction} className="mt-5 rounded-control border border-line bg-elevated px-4 py-2 text-[13px] font-medium text-fg hover:border-cyan/60">
        {action}
      </button>
      {footer && <p className="tnum mt-3 text-xs text-muted/80">{footer}</p>}
    </div>
  )
}

export function NoData({ onWiden }: { onWiden: () => void }) {
  return <StatePanel icon={Inbox} tone="text-muted" title={t('state.noData.title')} text={t('state.noData.text')} action={t('state.noData.action')} onAction={onWiden} />
}

export function AgentsNotConnected({ onOpenPanels }: { onOpenPanels: () => void }) {
  return <StatePanel icon={Server} tone="text-cyan" title={t('state.agents.title')} text={t('state.agents.text')} action={t('state.agents.action')} onAction={onOpenPanels} />
}

export function SyncPending({ onRetry }: { onRetry: () => void }) {
  return <StatePanel icon={Hourglass} tone="text-amber" title={t('state.pending.title')} text={t('state.pending.text')} action={t('state.pending.action')} onAction={onRetry} />
}

export function FailureState({ failure, onRetry, onReset }: { failure: Failure; onRetry: () => void; onReset: () => void }) {
  const footer = failure.requestId ? t('state.error.id', { id: failure.requestId }) : undefined
  if (failure.kind === 'forbidden') return <StatePanel icon={ShieldAlert} tone="text-red" title={t('state.forbidden.title')} text={t('state.forbidden.text')} action={t('state.forbidden.action')} onAction={onReset} footer={footer} />
  if (failure.kind === 'invalid') return <StatePanel icon={SlidersHorizontal} tone="text-amber" title={t('state.invalid.title')} text={t('state.invalid.text')} action={t('state.invalid.action')} onAction={onReset} footer={footer} />
  return <StatePanel icon={CloudOff} tone="text-red" title={t('state.error.title')} text={t('state.error.text')} action={t('state.error.retry')} onAction={onRetry} footer={footer} />
}

export function OverviewSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label={t('state.loading')}>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[132px]" />)}
      </div>
      <div className="grid gap-4 lg:grid-cols-12">
        <Skeleton className="h-[330px] lg:col-span-8" />
        <Skeleton className="h-[330px] lg:col-span-4" />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-[260px]" /><Skeleton className="h-[260px]" /><Skeleton className="h-[260px]" />
      </div>
    </div>
  )
}
