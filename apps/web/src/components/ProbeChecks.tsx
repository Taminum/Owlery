import { CircleCheck, CircleMinus, CircleX, MinusCircle } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { codeText } from '../lib/errors'
import type { Check } from '../lib/types'

const NAMES: Record<string, MsgKey> = {
  url: 'check.url', connection: 'check.connection', auth: 'check.auth', nodes: 'check.nodes',
  users: 'check.users', stats: 'check.stats', version: 'check.version',
}
const STATUS: Record<Check['status'], MsgKey> = {
  ok: 'check.status.ok', failed: 'check.status.failed', unsupported: 'check.status.unsupported', skipped: 'check.status.skipped',
}

/** Every status is an icon plus a word, never colour alone. */
export function ProbeChecks({ checks }: { checks: Check[] }) {
  return (
    <ol className="divide-y divide-line/70 rounded-control border border-line" aria-label={t('wizard.step.test')}>
      {checks.map((c) => {
        const Icon = c.status === 'ok' ? CircleCheck : c.status === 'failed' ? CircleX : c.status === 'unsupported' ? CircleMinus : MinusCircle
        const tone = c.status === 'ok' ? 'text-green' : c.status === 'failed' ? (c.required ? 'text-red' : 'text-amber') : 'text-muted'
        return (
          <li key={c.name} className="flex items-start gap-3 px-3 py-2.5 text-[13px]">
            <Icon size={18} className={`mt-0.5 shrink-0 ${tone}`} aria-hidden />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-medium text-fg">{NAMES[c.name] ? t(NAMES[c.name]) : c.name}</span>
                <span className="text-xs text-muted">{c.required ? t('check.required') : t('check.optional')}</span>
              </div>
              {c.error_code && <p className="mt-0.5 text-xs text-muted">{codeText(c.error_code)}</p>}
            </div>
            <div className="shrink-0 text-right">
              <div className={tone}>{t(STATUS[c.status])}</div>
              {c.status !== 'skipped' && c.latency_ms > 0 && <div className="tnum text-xs text-muted">{c.latency_ms} мс</div>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
