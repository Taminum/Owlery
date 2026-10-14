// Screenshots for the README, taken from the demo stack:  node scripts/readme-shots.mjs [baseUrl] [outDir]
// Demo data only (SEED_DEMO); secrets are read from ./secrets and never printed.
import { mkdir } from 'node:fs/promises'
import path from 'node:path'
import { launch, login, newPage } from './session.mjs'

const base = process.argv[2] ?? 'http://localhost:8088'
const out = process.argv[3] ?? '../../docs/screenshots'
const DEMO = '11111111-1111-4111-8111-111111111111'
const PAGES = [
  ['overview', `/?panels=${DEMO}`],
  ['sites', `/sites?panels=${DEMO}`],
  ['domains', `/domains?panels=${DEMO}`],
  ['users', `/users?panels=${DEMO}`],
  ['nodes', `/nodes?panels=${DEMO}`],
  ['intel', `/intel?panels=${DEMO}`],
  ['awg', `/awg?panels=${DEMO}`],
  ['panels', '/panels'],
]

await mkdir(out, { recursive: true })
const browser = await launch()
const { ctx, page } = await newPage(browser, { width: 1440, height: 900 })
await login(page, base)
for (const [name, url] of PAGES) {
  await page.goto(`${base}${url}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1200)
  await page.screenshot({ path: path.join(out, `${name}.png`) })
  console.log('shot', name)
}
await ctx.close()
await browser.close()
