// Interaction smoke test against a running stack:  node scripts/smoke.mjs [baseUrl]
import { chromium } from 'playwright-core'
import assert from 'node:assert/strict'

const base = process.argv[2] ?? 'http://localhost:8088'
const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL ?? 'msedge' })
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ru-RU' })).newPage()
const total = async () => Number((await page.locator('[aria-label="Принятые соединения"] .tnum').first().innerText()).replace(/\D/g, ''))
const step = (m) => console.log('ok -', m)

await page.goto(base, { waitUntil: 'networkidle' })
await page.waitForSelector('[aria-label="Принятые соединения"]')
const all = await total()
assert.ok(all > 0)
step(`all panels: ${all} connections, demo banner visible: ${await page.getByText('ДЕМО-ДАННЫЕ').first().isVisible()}`)

await page.selectOption('#panel-select', { label: 'Рабочая' })
await page.waitForFunction(() => location.search.includes('panels='))
await page.waitForTimeout(500)
const work = await total()
assert.ok(work < all, 'work panel alone must be smaller than all panels')
assert.equal(await page.getByText('4 (OpenWrt)').count(), 0, 'home-only user must not appear in the work panel view')
step(`panel=Рабочая: ${work} connections, no home users, url=${page.url().replace(base, '')}`)

await page.getByRole('button', { name: 'Ноды' }).click()
await page.getByLabel('work-1').click() // router applies URL changes in a transition; wait on the URL, not the box
await page.waitForFunction(() => location.search.includes('nodes='))
await page.waitForTimeout(500)
const oneNode = await total()
assert.ok(oneNode < work, 'a single node must be smaller than the whole panel')
step(`node=work-1: ${oneNode} connections`)

await page.keyboard.press('Escape')
await page.selectOption('#panel-select', { label: 'Домашняя' })
await page.waitForTimeout(600)
assert.ok(!page.url().includes('nodes='), 'switching panel must clear nodes of the other panel')
step('switching to Домашняя cleared the work-1 selection')

await page.getByRole('button', { name: '1h' }).click()
await page.waitForFunction(() => location.search.includes('range=1h'))
step('range 1h reflected in URL')

await page.reload({ waitUntil: 'networkidle' })
await page.waitForSelector('[aria-label="Принятые соединения"]')
assert.equal(await page.locator('#panel-select option:checked').innerText(), 'Домашняя')
step('state restored from URL after reload')

await page.getByRole('link', { name: 'Пользователи' }).click()
await page.getByText('Раздел в разработке').waitFor()
assert.ok(page.url().includes('panels='), 'scope must survive navigation')
step('placeholder page keeps the filter scope')

await browser.close()
console.log('smoke passed')
