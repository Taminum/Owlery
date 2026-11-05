import { cleanup, render } from '@testing-library/react'
import { writeFileSync } from 'node:fs'
import { AgentSetupDialog, type AgentOpts } from '../components/AgentSetup'

const opts: AgentOpts = { shell: true, web: true, desk: false, scr: false, adm: false, blk: false, probe: false, upd: false }

function blocks(mode: 'install' | 'update', o: AgentOpts): string[] {
  cleanup()
  render(<AgentSetupDialog mode={mode} token="TEST-TOKEN" initial={o} initialOS="linux" onClose={() => {}} />)
  return Array.from(document.querySelectorAll('pre')).map((p) => p.textContent ?? '')
}

describe('Установка агента на Linux', () => {
  it('is one block that starts with sudo and carries the secret', () => {
    const all = blocks('install', opts)
    const one = all.find((b) => b.startsWith("sudo bash <<'OWLERY'"))
    expect(one).toBeDefined()
    expect(one).toContain("echo 'TEST-TOKEN' > /etc/remnascope/secagent.token")
    expect(one!.trimEnd().endsWith('OWLERY')).toBe(true)
    expect(one).toContain('systemctl is-active remnascope-secagent')
    expect(one).toContain('-allow-web')
    expect(one).toContain('if systemctl cat fail2ban')
    if (process.env.OWL_DUMP) writeFileSync(process.env.OWL_DUMP, one!)
  })

  it('leaves the shell service out when the terminal is not allowed', () => {
    const one = blocks('install', { ...opts, shell: false, web: false }).find((b) => b.startsWith('sudo bash'))!
    expect(one).not.toContain('systemctl enable --now remnascope-shell')
    expect(one).not.toContain('-allow-web')
    expect(one).not.toContain('remnascope-shell')
  })

  it('updates under sudo too', () => {
    const one = blocks('update', opts).find((b) => b.startsWith('sudo bash'))
    expect(one).toBeDefined()
    expect(one).toContain('remnascope-containers-list')
  })
})

describe('Обновление агента с панели', () => {
  it('puts the flag and the root helper into the Linux install block only when it is allowed', () => {
    const on = blocks('install', { ...opts, upd: true }).find((b) => b.startsWith('sudo bash'))!
    expect(on).toContain('-allow-update')
    expect(on).toContain('remnascope-secagent-update.path')
    expect(on).toContain('enable --now remnascope-secagent-update.path')
    const off = blocks('install', opts).find((b) => b.startsWith('sudo bash'))!
    expect(off).not.toContain('-allow-update')
    expect(off).not.toContain('remnascope-secagent-update')
  })

  it('takes the helper off a machine whose update block does not allow it, and adds it where it does', () => {
    const on = blocks('update', { ...opts, upd: true }).find((b) => b.startsWith('sudo bash'))!
    expect(on).toContain('-allow-update')
    expect(on).toContain('remnascope-secagent-update.service')
    const off = blocks('update', opts).find((b) => b.startsWith('sudo bash'))!
    expect(off).not.toContain('-allow-update')
    expect(off).toContain('disable --now remnascope-secagent-update.path')
  })
})
