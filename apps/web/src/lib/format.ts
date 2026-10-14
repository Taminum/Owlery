const nf = new Intl.NumberFormat('ru-RU')
export const formatInt = (n: number) => nf.format(Math.round(n))
export const formatPct = (n: number) => `${n.toFixed(1).replace('.', ',')}%`

const UNITS = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
export function formatBytes(bytes: number): string {
  let v = bytes
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  const digits = i === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(digits).replace('.', ',')} ${UNITS[i]}`
}

/** Russian plural: plural(1,'нода','ноды','нод') -> 'нода', (2) -> 'ноды', (5) -> 'нод', (11) -> 'нод', (21) -> 'нода'. */
export function plural(n: number, one: string, few: string, many: string): string {
  const a = Math.abs(n) % 100
  const b = a % 10
  if (a > 10 && a < 20) return many
  if (b === 1) return one
  if (b >= 2 && b <= 4) return few
  return many
}

const tzOpt = (tz: string): string | undefined => (tz === 'local' ? undefined : tz)

export function formatClock(iso: string | number, tz: string, withSeconds = false): string {
  const d = typeof iso === 'number' ? new Date(iso * 1000) : new Date(iso)
  return new Intl.DateTimeFormat('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined,
    hour12: false,
    timeZone: tzOpt(tz),
  }).format(d)
}

export function formatAxisTime(ts: number, tz: string, granularitySec: number): string {
  const d = new Date(ts * 1000)
  if (granularitySec >= 3 * 3600) {
    return new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: '2-digit', timeZone: tzOpt(tz) }).format(d)
  }
  return formatClock(ts, tz)
}

export function formatDateTime(iso: string | number, tz: string): string {
  const d = typeof iso === 'number' ? new Date(iso * 1000) : new Date(iso)
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: tzOpt(tz),
  }).format(d)
}

/** Minutes the chosen time zone is ahead of UTC right now ("local" is the browser's own). */
export function tzOffsetMinutes(tz: string, at: Date = new Date()): number {
  if (tz === 'local') return -at.getTimezoneOffset()
  try {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(at)
    const g = (k: string) => Number(parts.find((p) => p.type === k)?.value)
    const asUTC = Date.UTC(g('year'), g('month') - 1, g('day'), g('hour'), g('minute'), g('second'))
    return Math.round((asUTC - Math.floor(at.getTime() / 1000) * 1000) / 60000)
  } catch {
    return 0
  }
}

/** A speed given in bytes per second, shown in bits per second, as network speeds usually are. */
export function formatRate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с']
  let v = bits
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  const digits = i === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(digits).replace('.', ',')} ${units[i]}`
}
