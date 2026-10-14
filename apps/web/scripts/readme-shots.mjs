// Screenshots for the README, taken from the dev stack:  node scripts/readme-shots.mjs [baseUrl] [outDir]
// Needs the demo panels (SEED_DEMO) and, for the analyzer pages, the invented traffic from `cmd/demodata`.
// Secrets are read from ./secrets and never printed.
import { mkdir } from 'node:fs/promises'
import path from 'node:path'
import { launch, login, newPage } from './session.mjs'

const base = process.argv[2] ?? 'http://localhost:8088'
const out = process.argv[3] ?? '../../docs/screenshots'
const DEMO = '11111111-1111-4111-8111-111111111111'
const VPN = '33333333-3333-4333-8333-333333333333' // "Demo VPN", filled by cmd/demodata
const PAGES = [
  ['overview', `/?panels=${DEMO}`],
  ['sites', `/sites?panels=${VPN}`],
  ['domains', `/domains?panels=${VPN}`],
  ['awg', `/awg?panels=${VPN}`],
  ['nodes', `/nodes?panels=${DEMO}`],
  ['panels', '/panels'],
]

await mkdir(out, { recursive: true })
const browser = await launch()
const { ctx, page } = await newPage(browser, { width: 1920, height: 1080 })
await login(page, base)
const shot = async (name) => {
  await page.waitForTimeout(1500)
  await page.screenshot({ path: path.join(out, `${name}.png`) })
  console.log('shot', name)
}
for (const [name, url] of PAGES) {
  await page.goto(`${base}${url}`, { waitUntil: 'networkidle' })
  await shot(name)
}
await page.goto(`${base}/intel?panels=${DEMO}`, { waitUntil: 'networkidle' })
await page.getByPlaceholder(/домен, IP/).fill('example.com')
await page.getByRole('button', { name: 'Проверить' }).click()
await page.waitForTimeout(9000)
await shot('intel')
await ctx.close()
await browser.close()
