// Visual QA against the running stack:  node scripts/screenshots.mjs [baseUrl] [outDir]
// Signs in with the dev owner (password read from ./secrets, never printed) and captures the
// main screens, the overview at the four design sizes, and checks for sideways overflow.
import { mkdir } from 'node:fs/promises'
import path from 'node:path'
import { launch, login, newPage, secret } from './session.mjs'

const base = process.argv[2] ?? 'http://localhost:8088'
const out = process.argv[3] ?? '../../docs/screenshots/m1'
const DEMO_HOME = '11111111-1111-4111-8111-111111111111'
const SIZES = [
  { name: '1440x900', width: 1440, height: 900 },
  { name: '1920x1080', width: 1920, height: 1080 },
  { name: '768x1024', width: 768, height: 1024 },
  { name: '390x844', width: 390, height: 844 },
]

await mkdir(out, { recursive: true })
const browser = await launch()
let failed = false

async function shot(page, errors, name, size) {
  await page.waitForTimeout(500)
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  const file = path.join(out, `${name}-${size}.png`)
  await page.screenshot({ path: file, fullPage: true })
  console.log(`${name}-${size}: overflowX=${overflow}px errors=${errors.length}`)
  if (overflow > 0 || errors.length) {
    failed = true
    errors.forEach((e) => console.log('  console error:', e.split('\n')[0]))
    errors.length = 0
  }
}

// Signed-out screen.
for (const s of [SIZES[0], SIZES[3]]) {
  const { ctx, page, errors } = await newPage(browser, s)
  await page.goto(base, { waitUntil: 'networkidle' })
  await page.getByRole('heading', { name: 'Вход в RemnaScope' }).waitFor()
  await shot(page, errors, 'login', s.name)
  await ctx.close()
}

// Overview (demo scope) at all four sizes.
for (const s of SIZES) {
  const { ctx, page, errors } = await newPage(browser, s)
  await login(page, base)
  await page.goto(`${base}/?panels=${DEMO_HOME}`, { waitUntil: 'networkidle' })
  await page.getByLabel('Принятые соединения', { exact: true }).waitFor()
  await shot(page, errors, 'overview-demo', s.name)
  await ctx.close()
}

// Real panels have no events yet: the honest state.
{
  const { ctx, page, errors } = await newPage(browser, SIZES[0])
  await login(page, base)
  await page.getByText('Сбор событий ещё не подключён').waitFor()
  await shot(page, errors, 'overview-no-agents', SIZES[0].name)
  await ctx.close()
}

// Panels, the wizard, settings.
for (const s of [SIZES[0], SIZES[3]]) {
  const { ctx, page, errors } = await newPage(browser, s)
  await login(page, base)
  await page.goto(`${base}/panels`, { waitUntil: 'networkidle' })
  await page.getByRole('heading', { name: 'Панели Remnawave' }).waitFor()
  await page.waitForTimeout(800)
  await shot(page, errors, 'panels', s.name)

  if (s === SIZES[0]) {
    await page.getByRole('button', { name: /Добавить панель/ }).click()
    const wiz = page.getByRole('dialog', { name: 'Подключение панели' })
    await shot(page, errors, 'wizard-1-connection', s.name)
    await wiz.getByLabel('Название').fill('Home (mock)')
    await wiz.getByLabel('Адрес панели (HTTPS)').fill('https://mock-home.demo.test:8443')
    await wiz.getByLabel('API-токен').fill(secret('mock_home_token'))
    await wiz.getByLabel(/CA администратора/).check()
    await wiz.getByRole('button', { name: 'Далее' }).click()
    await shot(page, errors, 'wizard-2-collection', s.name)
    await wiz.getByRole('button', { name: 'Далее' }).click()
    await wiz.getByText('Подключение проверено').waitFor({ timeout: 30000 })
    await shot(page, errors, 'wizard-3-test', s.name)
    await wiz.getByRole('button', { name: 'Отмена' }).click() // nothing is saved by the wizard until step 4

    await page.goto(`${base}/settings`, { waitUntil: 'networkidle' })
    await page.getByRole('tab', { name: 'Аккаунты и доступ' }).click()
    await page.getByRole('cell', { name: 'owner' }).first().waitFor()
    await shot(page, errors, 'settings-accounts', s.name)
    await page.getByRole('tab', { name: 'Журнал аудита' }).click()
    await page.getByText('Вход').first().waitFor()
    await shot(page, errors, 'settings-audit', s.name)
  }
  await ctx.close()
}

await browser.close()
process.exit(failed ? 1 : 0)
