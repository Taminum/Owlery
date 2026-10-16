// Decides when the mascot may react. It is deliberately quiet: a reaction is rare, never repeats the same mood
// soon, never interrupts typing in a form, and a real alert always goes first.
export type Mood = 'alert' | 'concerned' | 'curious' | 'smug' | 'celebrate' | 'happy' | 'sleepy'

const PRIORITY: Record<Mood, number> = { alert: 3, concerned: 2, curious: 1, smug: 1, celebrate: 1, happy: 0, sleepy: 0 }

export interface DirectorOptions {
  globalGapMs: number // between any two reactions
  alertGapMs: number // an alert may follow the previous reaction sooner
  moodCooldownMs: number // the same mood again
}

export const DEFAULT_DIRECTOR: DirectorOptions = { globalGapMs: 90_000, alertGapMs: 10_000, moodCooldownMs: 10 * 60_000 }

export class Director {
  private lastAny = -Infinity
  private lastMood = new Map<Mood, number>()
  constructor(private opts: DirectorOptions = DEFAULT_DIRECTOR) {}

  /** Returns true, and remembers it, when the mood may be shown now. */
  allow(mood: Mood, now: number, o: { typing: boolean; busy: boolean }): boolean {
    const critical = PRIORITY[mood] >= 3
    if (o.typing && !critical) return false
    if (o.busy && !critical) return false // something is already on stage
    if (now - this.lastAny < (critical ? this.opts.alertGapMs : this.opts.globalGapMs)) return false
    const last = this.lastMood.get(mood)
    if (last !== undefined && now - last < (critical ? this.opts.moodCooldownMs / 5 : this.opts.moodCooldownMs)) return false
    this.lastAny = now
    this.lastMood.set(mood, now)
    return true
  }
}

/** The mood an alert kind calls for. */
export function moodForAlert(kind: string): Mood {
  switch (kind) {
    case 'sec_tls':
    case 'user_expiry':
    case 'user_traffic':
    case 'bill_due':
      return 'concerned'
    case 'dns_change':
      return 'curious'
    default:
      return 'alert'
  }
}
