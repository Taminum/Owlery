import { useEffect, useState } from 'react'
import { t } from '../i18n'
import { useBusy } from '../lib/busy'

/** A thin moving bar at the top of the window while a page or a range change is loading. Quick loads never show it. */
export function BusyBar() {
  const busy = useBusy()
  const [shown, setShown] = useState(false)
  useEffect(() => {
    if (!busy) {
      const off = setTimeout(() => setShown(false), 0)
      return () => clearTimeout(off)
    }
    const on = setTimeout(() => setShown(true), 250)
    return () => clearTimeout(on)
  }, [busy])
  if (!shown || !busy) return null
  return (
    <div className="pointer-events-none fixed inset-x-0 top-0 z-50" role="status" aria-label={t('busy.loading')}>
      <div className="h-[3px] w-full overflow-hidden bg-cyan/15">
        <div className="busy-bar h-full w-1/3 rounded-full bg-cyan" />
      </div>
      <div className="mx-auto mt-2 w-fit rounded-full border border-border bg-elevated px-3 py-1 text-xs text-muted shadow">{t('busy.loading')}</div>
    </div>
  )
}
