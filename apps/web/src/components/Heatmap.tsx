import { t } from '../i18n'
import { formatInt } from '../lib/format'

const DAYS = ['пн', 'вт', 'ср', 'чт', 'пт', 'сб', 'вс'] as const

/** Weekday x hour grid; the colour is the share of the busiest cell. Each cell has its own text. */
export function Heatmap({ grid, max }: { grid: number[][]; max: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="border-separate border-spacing-[3px] text-[11px]" role="grid" aria-label={t('act.title')}>
        <thead>
          <tr>
            <th className="w-8" />
            {Array.from({ length: 24 }, (_, h) => <th key={h} scope="col" className="w-7 min-w-7 text-center font-normal text-muted">{h % 3 === 0 ? String(h).padStart(2, '0') : ''}</th>)}
          </tr>
        </thead>
        <tbody>
          {grid.map((row, d) => (
            <tr key={d}>
              <th scope="row" className="pr-1 text-right font-normal text-muted">{DAYS[d]}</th>
              {row.map((v, h) => {
                const a = max > 0 && v > 0 ? 0.12 + 0.88 * (v / max) : 0
                return (
                  <td key={h} role="gridcell" title={`${DAYS[d]} ${String(h).padStart(2, '0')}:00 · ${formatInt(v)}`} aria-label={`${DAYS[d]} ${String(h).padStart(2, '0')}:00 ${formatInt(v)}`}
                    className="h-6 w-7 rounded-[4px]" style={{ background: a ? `rgba(81,139,250,${a.toFixed(2)})` : 'var(--color-elevated)' }} />
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
