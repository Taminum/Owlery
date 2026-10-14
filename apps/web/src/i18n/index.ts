import { ru, type MsgKey } from './ru'

export type { MsgKey }

export function t(key: MsgKey, params?: Record<string, string | number>): string {
  let s: string = ru[key]
  if (params) for (const [k, v] of Object.entries(params)) s = s.replaceAll(`{${k}}`, String(v))
  return s
}
