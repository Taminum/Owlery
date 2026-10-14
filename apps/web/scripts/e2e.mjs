// End-to-end run against the running compose stack:  node scripts/e2e.mjs [baseUrl]
// It uses the mock panels, creates its own panel and viewer account (unique names), and cleans up.
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { launch, login, newPage, secret } from './session.mjs'

const base = process.argv[2] ?? 'http://localhost:8088'
const tag = randomBytes(3).toString('hex')
const panelName = `E2E ${tag}`
const viewerName = `e2e-viewer-${tag}`
const viewerPassword = randomBytes(18).toString('base64url') // never printed
const step = (m) => console.log('ok -', m)

const browser = await launch()
try {
  const o = await newPage(browser)
  const page = o.page

  // 1. Sign in: a wrong password gets the generic message and clears the field.
  await page.goto(base, { waitUntil: 'networkidle' })
  await page.getByLabel('Логин').fill('owner')
  await page.getByLabel('Пароль').fill('definitely-not-the-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByText('Неверный логин или пароль').waitFor()
  assert.equal(await page.getByLabel('Пароль').inputValue(), '')
  step('wrong password: generic error, field cleared')
  await login(page, base)
  step('owner signed in')

  // 2. Real panels have no events yet; a demo panel shows clearly labelled demo data.
  await page.getByText('Сбор событий ещё не подключён').waitFor()
  assert.equal(await page.getByText('ДЕМО-ДАННЫЕ').count(), 0, 'no demo banner while no demo data is shown')
  step('overview over real panels says "collection not connected" and shows no numbers')
  await page.selectOption('#panel-select', { label: 'Домашняя (демо)' })
  await page.getByText('ДЕМО-ДАННЫЕ').first().waitFor()
  await page.getByLabel('Принятые соединения', { exact: true }).waitFor()
  step('demo panel selected: numbers appear with the DEMO banner')

  // 3. Connect a panel through the wizard (mock panel with its own CA).
  await page.getByRole('link', { name: 'Панели' }).click()
  await page.getByRole('button', { name: /Добавить панель/ }).click()
  const wiz = page.getByRole('dialog', { name: 'Подключение панели' })
  await wiz.getByLabel('Название').fill(panelName)
  await wiz.getByLabel('Адрес панели (HTTPS)').fill('https://mock-home.demo.test:8443')
  const tokenField = wiz.getByLabel('API-токен')
  assert.equal(await tokenField.getAttribute('type'), 'password')
  await tokenField.fill(secret('mock_home_token'))
  await wiz.getByRole('button', { name: 'Далее' }).click()
  await wiz.getByRole('button', { name: 'Далее' }).click()
  // Without the admin CA the mock's certificate must be rejected.
  await wiz.getByText('Сертификат не прошёл проверку').waitFor({ timeout: 30000 })
  assert.ok(await wiz.getByRole('button', { name: 'Далее' }).isDisabled(), 'cannot continue after a failed required check')
  step('untrusted certificate is refused and blocks saving')
  await wiz.getByRole('button', { name: 'Назад' }).click()
  await wiz.getByRole('button', { name: 'Назад' }).click()
  await wiz.getByLabel(/CA администратора/).check()
  await wiz.getByRole('button', { name: 'Далее' }).click()
  await wiz.getByRole('button', { name: 'Далее' }).click()
  await wiz.getByText('Подключение проверено').waitFor({ timeout: 30000 })
  await wiz.getByRole('button', { name: 'Далее' }).click()
  await wiz.getByText(/home-a, home-b, home-c/).waitFor()
  await wiz.getByRole('button', { name: 'Сохранить панель' }).click()
  await page.getByRole('dialog', { name: 'Панель сохранена' }).waitFor()
  await page.getByRole('button', { name: 'Закрыть', exact: true }).last().click()
  const card = page.locator('section', { has: page.getByRole('heading', { name: panelName, exact: true }) })
  await card.waitFor()
  step(`panel "${panelName}" created through the wizard`)

  // 4. The first scheduled sync discovers the nodes and users on its own.
  await page.waitForFunction((name) => {
    const h = [...document.querySelectorAll('h2')].find((x) => x.textContent === name)
    return h && /3\s*ноды/.test(h.closest('section').textContent) && /5\s*пользовател/.test(h.closest('section').textContent)
  }, panelName, { timeout: 60000, polling: 1000 })
  step('background sync found 3 nodes and 5 users')

  // The token is nowhere on the page.
  const html = await page.content()
  assert.ok(!html.includes(secret('mock_home_token')), 'token must not be in the page')
  step('token is not in the page HTML')

  // 5. Test, manual sync, history, token rotation.
  await card.getByRole('button', { name: 'Проверить' }).click()
  await page.getByRole('dialog', { name: /Проверка пройдена/ }).waitFor()
  await page.getByRole('button', { name: 'Закрыть', exact: true }).last().click()
  await card.getByRole('button', { name: 'Синхронизировать' }).click()
  await page.getByText('Синхронизация запущена.').waitFor()
  await card.getByRole('button', { name: 'История' }).click()
  await page.getByRole('dialog', { name: /История синхронизаций/ }).waitFor()
  assert.ok((await page.getByRole('dialog').locator('tbody tr').count()) >= 2)
  await page.getByRole('button', { name: 'Закрыть', exact: true }).last().click()
  step('connection test, manual sync and history work')

  await card.getByRole('button', { name: 'Заменить токен' }).click()
  const rot = page.getByRole('dialog', { name: /Заменить API-токен/ })
  await rot.getByLabel('API-токен').fill('a-wrong-token-that-the-panel-rejects')
  await rot.getByRole('button', { name: 'Проверить и заменить' }).click()
  await rot.getByText('Панель отклонила токен.').waitFor({ timeout: 30000 })
  await rot.getByLabel('API-токен').fill(secret('mock_home_token'))
  await rot.getByRole('button', { name: 'Проверить и заменить' }).click()
  await page.getByText('Токен заменён.').waitFor({ timeout: 30000 })
  step('rotation: a bad token is rejected, the good one replaces it')

  // 6. Create a viewer who sees only this panel.
  await page.getByRole('link', { name: 'Настройки' }).click()
  await page.getByRole('tab', { name: 'Аккаунты и доступ' }).click()
  await page.getByRole('button', { name: 'Новый аккаунт' }).click()
  const acc = page.getByRole('dialog', { name: 'Новый аккаунт' })
  await acc.getByLabel('Логин').fill(viewerName)
  await acc.getByLabel('Пароль').fill(viewerPassword)
  await acc.getByLabel('Добавить панель').selectOption({ label: panelName })
  await acc.getByRole('button', { name: 'Создать аккаунт' }).click()
  await page.getByRole('cell', { name: viewerName }).waitFor()
  step('viewer account created and bound to one panel')

  await page.getByRole('tab', { name: 'Журнал аудита' }).click()
  await page.getByText('Панель подключена').first().waitFor()
  const audit = await page.locator('table').last().innerText()
  assert.ok(!audit.includes(secret('mock_home_token')) && !audit.includes(viewerPassword), 'audit must not hold secrets')
  step('audit shows the actions and holds no secrets')

  // 7. The viewer's view: one panel, no actions, no owner areas.
  await page.getByRole('button', { name: 'Аккаунт' }).click()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await page.getByRole('heading', { name: 'Вход в RemnaScope' }).waitFor()
  const v = await newPage(browser)
  await login(v.page, base, viewerName, viewerPassword)
  await v.page.getByRole('link', { name: 'Панели' }).click()
  await v.page.getByRole('heading', { name: panelName, exact: true }).waitFor()
  assert.equal(await v.page.getByRole('heading', { level: 2 }).count(), 1, 'the viewer sees exactly one panel')
  assert.equal(await v.page.getByRole('button', { name: /Добавить панель|Проверить|Синхронизировать|Заменить токен|Удалить/ }).count(), 0)
  const options = await v.page.locator('#panel-select option').allInnerTexts()
  assert.deepEqual(options.filter((x) => !/Все доступные/.test(x)), [panelName], 'only the assigned panel is selectable')
  await v.page.goto(`${base}/settings`, { waitUntil: 'networkidle' })
  assert.equal(await v.page.getByRole('tab', { name: 'Аккаунты и доступ' }).count(), 0)
  step('viewer: one panel, no actions, no accounts tab, selector limited')
  await v.ctx.close()

  // 8. Clean up: remove the panel (purge) and disable the viewer. The owner signed out in step 7.
  await login(page, base)
  await page.getByRole('link', { name: 'Панели' }).click()
  await page.getByRole('heading', { name: panelName, exact: true }).waitFor()
  await page.locator('section', { has: page.getByRole('heading', { name: panelName, exact: true }) }).getByRole('button', { name: 'Удалить' }).click()
  const del = page.getByRole('dialog', { name: /Удалить панель/ })
  await del.getByLabel(/Введите название панели/).fill(panelName)
  await del.getByLabel(/Удалить всё/).check()
  await del.getByRole('button', { name: 'Удалить панель' }).click()
  await page.getByRole('heading', { name: panelName, exact: true }).waitFor({ state: 'detached' })
  await page.getByRole('link', { name: 'Настройки' }).click()
  await page.getByRole('tab', { name: 'Аккаунты и доступ' }).click()
  const row = page.getByRole('row', { name: new RegExp(viewerName) })
  await row.getByRole('button', { name: 'Отключить' }).click()
  await row.getByText('отключён').waitFor()
  step('cleanup: panel purged, viewer disabled')

  assert.deepEqual(o.errors, [], 'no console errors')
  console.log('e2e passed')
} finally {
  await browser.close()
}
