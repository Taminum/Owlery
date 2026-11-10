import { describe, expect, it } from 'vitest'
import { formatDateTime, sourceLabel } from '../lib/format'

describe('small things that make a page readable', () => {
  const now = new Date('2026-11-10T12:00:00Z')
  it('a date from another year says the year, one from this year does not', () => {
    expect(formatDateTime('2026-09-09T10:30:00Z', 'UTC', now)).toBe('09.09, 10:30')
    expect(formatDateTime('2025-09-09T10:30:00Z', 'UTC', now)).toBe('09.09.2025, 10:30')
    expect(formatDateTime('2027-01-02T10:30:00Z', 'UTC', now)).toBe('02.01.2027, 10:30')
  })
  it('the year is the one in the chosen zone, not the browser\'s', () => {
    // 23:30 on New Year's Eve in UTC is already next year in Yekaterinburg (UTC+5)
    expect(formatDateTime('2026-12-31T23:30:00Z', 'Asia/Yekaterinburg', now)).toBe('01.01.2027, 04:30')
  })
  it('a source is named for a person and keeps the technical name for the tooltip', () => {
    expect(sourceLabel('agent_access_log+router_clash_api')).toEqual({ text: 'журналы нод и роутер', title: 'agent_access_log+router_clash_api' })
    expect(sourceLabel('something_new')).toEqual({ text: 'something_new', title: 'something_new' })
  })
})
