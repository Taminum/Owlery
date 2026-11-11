// The colours of the charts. They mirror the @theme tokens in index.css, but recharts needs literal values, so each one is
// read from the page's own CSS variable at the moment a chart is drawn: a light or Kawaii theme then colours the axes, the
// grid and the series with its own tokens instead of leaving the dark ones on a white card. The literals below are the
// standard dark look, which is also what a place with no styles (a test) gets.
const FALLBACK = {
  canvas: '#0B1018',
  surface: '#151E2B',
  elevated: '#1B2635',
  line: '#2A3646',
  fg: '#E9F0F7',
  muted: '#91A0B2',
  cyan: '#38C7E8',
  blue: '#518BFA',
  green: '#35C995',
  amber: '#F0B95D',
  red: '#F07178',
} as const

type Token = keyof typeof FALLBACK

let cache: { theme: string | null; values: Partial<Record<Token, string>> } = { theme: null, values: {} }

function read(name: Token): string {
  if (typeof document === 'undefined') return FALLBACK[name]
  const el = document.documentElement
  const theme = el.getAttribute('data-kawaii-theme')
  if (cache.theme !== theme) cache = { theme, values: {} }
  const hit = cache.values[name]
  if (hit) return hit
  let v = ''
  try {
    v = getComputedStyle(el).getPropertyValue(`--color-${name}`).trim()
  } catch {
    /* no styles to read */
  }
  const out = v || FALLBACK[name]
  cache.values[name] = out
  return out
}

export const C = {
  get canvas() { return read('canvas') },
  get surface() { return read('surface') },
  get elevated() { return read('elevated') },
  get line() { return read('line') },
  get fg() { return read('fg') },
  get muted() { return read('muted') },
  get cyan() { return read('cyan') },
  get blue() { return read('blue') },
  get green() { return read('green') },
  get amber() { return read('amber') },
  get red() { return read('red') },
}

/** The colours of a chart with several series, in the theme the page has now. */
export const seriesColors = (): string[] => [C.blue, C.amber, C.cyan, C.green, C.red, '#9b8cf5']
