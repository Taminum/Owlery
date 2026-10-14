// Shared helpers for the browser scripts. Secrets are read from ./secrets and never printed.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { chromium } from 'playwright-core'

export const secretsDir = process.env.SECRETS_DIR ?? path.resolve('../../secrets')
export const secret = (name) => readFileSync(path.join(secretsDir, name), 'utf8').trim()

export const launch = () => chromium.launch({ channel: process.env.BROWSER_CHANNEL ?? 'msedge' })

export async function newPage(browser, { width = 1440, height = 900 } = {}) {
  const ctx = await browser.newContext({ viewport: { width, height }, locale: 'ru-RU', timezoneId: 'Asia/Yekaterinburg' })
  const page = await ctx.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Intentional 4xx/5xx from negative tests show up as resource errors.
    if (/Failed to load resource/.test(text)) return
    errors.push(text)
  })
  return { ctx, page, errors }
}

export async function login(page, base, username = 'owner', password = secret('owner_password')) {
  await page.goto(base, { waitUntil: 'networkidle' })
  await page.getByLabel('Логин').fill(username)
  await page.getByLabel('Пароль').fill(password)
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('link', { name: 'Обзор' }).waitFor({ timeout: 15000 })
}
