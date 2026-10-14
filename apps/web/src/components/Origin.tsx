import { t } from '../i18n'

export type OriginKind = 'rule' | 'manual' | 'auto' | 'guess'

const LABEL: Record<OriginKind, string> = { rule: 'origin.rule', manual: 'origin.manual', auto: 'origin.auto', guess: 'origin.guess' }
const TITLE: Record<OriginKind, string> = { rule: 'origin.ruleHint', manual: 'origin.manualHint', auto: 'origin.autoHint', guess: 'origin.guessHint' }

// A small, quiet label that says where a classification comes from.
export function OriginBadge({ origin }: { origin?: string }) {
  if (!origin || !(origin in LABEL)) return null
  const o = origin as OriginKind
  const tone = o === 'guess' ? 'border-amber/40 text-amber' : o === 'auto' ? 'border-cyan/30 text-cyan' : 'border-line text-muted'
  return (
    <span title={t(TITLE[o] as 'origin.ruleHint')} className={`ml-1.5 whitespace-nowrap rounded-full border px-1.5 py-px align-middle text-[11px] ${tone}`}>
      {t(LABEL[o] as 'origin.rule')}
    </span>
  )
}
