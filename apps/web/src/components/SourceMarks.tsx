import { t, type MsgKey } from '../i18n'

const ORDER = ['node', 'router', 'awg'] as const

/** Small marks that say where a row's traffic was seen: the nodes' logs, the router, or an AmneziaWG server. */
export function SourceMarks({ sources }: { sources?: string[] }) {
  const list = ORDER.filter((s) => sources?.includes(s))
  if (list.length === 0) return null
  return (
    <span className="ml-1.5 inline-flex flex-wrap gap-1 align-middle">
      {list.map((s) => (
        <span key={s} title={t(`src.${s}.hint` as MsgKey)} className={`whitespace-nowrap rounded-full border px-1.5 py-px text-[11px] ${s === 'awg' ? 'border-cyan/30 text-cyan' : 'border-line text-muted'}`}>
          {t(`src.${s}` as MsgKey)}
        </span>
      ))}
    </span>
  )
}

/** True when any row got traffic from AmneziaWG: its numbers have caveats worth one line under the table. */
export const hasAwg = (rows: { sources?: string[] }[]) => rows.some((r) => r.sources?.includes('awg'))
