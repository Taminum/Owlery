// Mirrors the @theme tokens in index.css; recharts needs literal values.
export const C = {
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

export const SERIES = [C.blue, C.amber, C.cyan, C.green, C.red, '#9b8cf5'] as const
