import { afterEach, describe, expect, it } from 'vitest'
import { C, seriesColors } from '../lib/colors'

afterEach(() => {
  document.documentElement.removeAttribute('data-kawaii-theme')
  document.documentElement.style.removeProperty('--color-muted')
})

describe('the colours of the charts', () => {
  it('are the standard dark ones where the page has no styles to read', () => {
    expect(C.muted).toBe('#91A0B2')
    expect(C.green).toBe('#35C995')
    expect(seriesColors()).toHaveLength(6)
  })

  it('follow the theme of the page: a value read from the page replaces the dark one, and is read again when the theme changes', () => {
    document.documentElement.style.setProperty('--color-muted', '#765868')
    document.documentElement.setAttribute('data-kawaii-theme', 'sakura_light')
    expect(C.muted).toBe('#765868') // the light theme's own, not the dark one on a white card
    document.documentElement.style.setProperty('--color-muted', '#b7aacd')
    document.documentElement.setAttribute('data-kawaii-theme', 'kawaii_dark')
    expect(C.muted).toBe('#b7aacd')
    document.documentElement.removeAttribute('data-kawaii-theme')
    document.documentElement.style.removeProperty('--color-muted')
    expect(C.muted).toBe('#91A0B2') // and back to the standard look
  })
})
