import { useEffect, useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { api, ApiError } from '../lib/api'
import { errorText } from '../lib/errors'
import { isNewer } from '../lib/semver'
import { formatDateTime } from '../lib/format'
import { useLoad } from '../hooks/useLoad'
import type { SecAgent } from '../lib/types'
import { Card, Chip } from './ui'
import { DangerButton, GhostButton, Modal, PrimaryButton } from './Modal'

// The permissions a machine gives Owlery, by the capability its agent announces. They are switched on the machine
// itself, by the command this dialog builds: Owlery can never give them to itself.
export interface AgentOpts { shell: boolean; web: boolean; desk: boolean; scr: boolean; adm: boolean; blk: boolean; probe: boolean; upd: boolean }
type OS = 'linux' | 'windows'

const CAP: Record<keyof AgentOpts, string> = { shell: 'shell', web: 'web', desk: 'desktop', scr: 'remote', adm: 'admin', blk: 'ip_block', probe: 'probe', upd: 'self_update' }

export function optsFromCaps(caps: string[]): AgentOpts {
  return { shell: caps.includes(CAP.shell), web: caps.includes(CAP.web), desk: caps.includes(CAP.desk), scr: caps.includes(CAP.scr), adm: caps.includes(CAP.adm), blk: caps.includes(CAP.blk), probe: caps.includes(CAP.probe), upd: caps.includes(CAP.upd) }
}

const RELEASES = 'https://github.com/Taminum/Owlery/releases/latest/download'

export function Code({ children }: { children: string }) {
  return <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-control border border-line bg-elevated p-3 font-mono text-[12px]">{children}</pre>
}

function winFlags(o: AgentOpts): string {
  return `${o.shell ? ' -allow-shell' : ''}${o.desk ? ' -allow-desktop' : ''}${o.scr ? ' -allow-screen' : ''}${o.adm ? ' -allow-admin' : ''}${o.blk ? ' -allow-block' : ''}${o.web ? ' -allow-web' : ''}${o.upd ? ' -allow-update' : ''}${o.probe ? ' -probe' : ''}`
}

// The Linux unit gets its flags from a drop-in of its own. Its name sorts last, so it wins over older drop-ins
// (a hand-made probe.conf, say) that also set ExecStart.
function linuxDropIn(host: string, o: AgentOpts): string {
  return `mkdir -p /etc/systemd/system/remnascope-secagent.service.d
cat > /etc/systemd/system/remnascope-secagent.service.d/zz-owlery.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/remnascope-secagent -server wss://${host} -token-file /etc/remnascope/secagent.token -helper-socket /run/remnascope-sec/f2b.sock -state-dir /var/lib/remnascope-secagent${o.web ? ' -allow-web' : ''}${o.upd ? ' -allow-update' : ''}${o.probe ? ' -probe' : ''}
EOF`
}

// The root helper that installs an update the agent fetched: a path unit that starts a one-shot service. Without the permission
// the units are not there (an update block takes them off a machine that had them).
function linuxUpdateUnits(on: boolean, removeWhenOff: boolean): string {
  if (on) {
    return `cp deploy/secagent/remnascope-secagent-update.path deploy/secagent/remnascope-secagent-update.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now remnascope-secagent-update.path`
  }
  return removeWhenOff ? 'systemctl disable --now remnascope-secagent-update.path 2>/dev/null || true; rm -f /etc/systemd/system/remnascope-secagent-update.path /etc/systemd/system/remnascope-secagent-update.service' : ''
}

function linuxShell(host: string, on: boolean): string {
  return on
    ? `sed 's#wss://SCOPE_HOST#wss://${host}#' deploy/secagent/remnascope-shell.service > /etc/systemd/system/remnascope-shell.service
systemctl daemon-reload && systemctl enable --now remnascope-shell`
    : `systemctl disable --now remnascope-shell 2>/dev/null || true; rm -f /etc/systemd/system/remnascope-shell.service`
}

/**
 * The whole Linux install as one block: one `sudo`, so the password is asked once. It is safe to run again: users and files
 * that exist are kept, and Fail2ban is only touched when the machine has it.
 */
function linuxInstallBlock(host: string, token: string, o: AgentOpts): string {
  return `sudo bash <<'OWLERY'
set -e
id remnascope-sec >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-sec
id remnascope-f2b >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-f2b
install -d -m 0755 /etc/remnascope && umask 077 && echo '${token}' > /etc/remnascope/secagent.token
chown root:remnascope-sec /etc/remnascope/secagent.token && chmod 0640 /etc/remnascope/secagent.token
cd /tmp
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64) A=arm64 ;; *) echo "unsupported processor"; exit 1 ;; esac
curl -fLO ${RELEASES}/remnascope-secagent-linux-$A
curl -fLO ${RELEASES}/remnascope-deploy-files.tar.gz
tar -xzf remnascope-deploy-files.tar.gz
install -m 0755 remnascope-secagent-linux-$A /usr/local/bin/remnascope-secagent
sed 's#wss://SCOPE_HOST#wss://${host}${o.web ? ' -allow-web' : ''}${o.upd ? ' -allow-update' : ''}#' deploy/secagent/remnascope-secagent.service > /etc/systemd/system/remnascope-secagent.service
cp deploy/secagent/remnascope-secagent-f2b.service /etc/systemd/system/
if systemctl cat fail2ban >/dev/null 2>&1; then
mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/remnascope.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/fail2ban/fail2ban.sock ] && break; sleep 1; done; chgrp remnascope-f2b /run/fail2ban/fail2ban.sock && chmod 0660 /run/fail2ban/fail2ban.sock"
EOF
systemctl daemon-reload && systemctl restart fail2ban
fi
install -m 0755 deploy/secagent/remnascope-containers-list /usr/local/sbin/
cp deploy/secagent/remnascope-containers-list.service deploy/secagent/remnascope-containers-list.timer /etc/systemd/system/
${o.shell ? linuxShell(host, true) : ''}
${linuxUpdateUnits(o.upd, false)}
systemctl daemon-reload
systemctl enable --now remnascope-containers-list.timer remnascope-secagent-f2b remnascope-secagent
systemctl restart remnascope-secagent${o.shell ? ' remnascope-shell' : ''}
sleep 3
systemctl is-active remnascope-secagent
OWLERY`
}

function CopyCode({ children }: { children: string }) {
  const [done, setDone] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(children)
      setDone(true)
      window.setTimeout(() => setDone(false), 2000)
    } catch {
      setDone(false)
    }
  }
  return (
    <div className="relative">
      <button type="button" onClick={() => void copy()} className="absolute right-2 top-2 h-7 rounded-control border border-line bg-surface px-2.5 text-xs text-muted hover:text-fg">
        {done ? t('agent.copied') : t('agent.copy')}
      </button>
      <Code>{children}</Code>
    </div>
  )
}

function Check({ on, set, label, hint }: { on: boolean; set: (v: boolean) => void; label: MsgKey; hint: MsgKey }) {
  return (
    <div>
      <label className="flex items-center gap-2 text-[13px]">
        <input type="checkbox" checked={on} onChange={(e) => set(e.target.checked)} />
        <span>{t(label)}</span>
      </label>
      <p className="mt-0.5 text-xs text-muted">{t(hint)}</p>
    </div>
  )
}

/**
 * Install (with a fresh secret) or update (keeping the machine's secret) the agent, with the permissions ticked here.
 * The update replaces the program and the flags and restarts the agent; nothing needs revoking.
 */
export function AgentSetupDialog({ mode, token, initial, initialOS, onClose }: {
  mode: 'install' | 'update'; token?: string; initial: AgentOpts; initialOS: OS; onClose: () => void
}) {
  const [os, setOS] = useState<OS>(initialOS)
  const [o, setO] = useState<AgentOpts>(initial)
  const set = (k: keyof AgentOpts) => (v: boolean) => setO({ ...o, [k]: v })
  const host = window.location.host
  return (
    <Modal title={t(mode === 'install' ? 'sec.onb.title' : 'agent.update.title')} onClose={onClose} wide>
      <div className="space-y-3 text-[13px]">
        <div role="tablist" aria-label={t('sec.onb.os')} className="flex gap-2">
          {(['linux', 'windows'] as const).map((x) => (
            <button key={x} role="tab" type="button" aria-selected={os === x} onClick={() => setOS(x)}
              className={`h-8 rounded-control border px-3 text-[13px] ${os === x ? 'border-cyan bg-elevated text-fg' : 'border-line text-muted hover:text-fg'}`}>{x === 'linux' ? 'Linux' : 'Windows'}</button>
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Check on={o.shell} set={set('shell')} label="sec.onb.shell" hint="sec.onb.shellHint" />
          <Check on={o.web} set={set('web')} label="sec.onb.web" hint="sec.onb.webHint" />
          <Check on={o.upd} set={set('upd')} label="sec.onb.update" hint="sec.onb.updateHint" />
          {os === 'windows' && <Check on={o.desk} set={set('desk')} label="sec.onb.desk" hint="sec.onb.deskHint" />}
          {os === 'windows' && <Check on={o.scr} set={set('scr')} label="sec.onb.screen" hint="sec.onb.screenHint" />}
          {os === 'windows' && <Check on={o.adm} set={set('adm')} label="sec.onb.admin" hint="sec.onb.adminHint" />}
          {os === 'windows' && <Check on={o.blk} set={set('blk')} label="sec.onb.block" hint="sec.onb.blockHint" />}
          {mode === 'update' && <Check on={o.probe} set={set('probe')} label="agent.probe" hint="agent.probeHint" />}
        </div>

        {mode === 'update' && os === 'linux' && (
          <>
            <p>{t('agent.update.linux')}</p>
            <CopyCode>{`sudo bash <<'OWLERY'
set -e
cd /tmp
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64) A=arm64 ;; *) echo "unsupported processor"; exit 1 ;; esac
curl -fLO ${RELEASES}/remnascope-secagent-linux-$A
curl -fLO ${RELEASES}/remnascope-deploy-files.tar.gz
tar -xzf remnascope-deploy-files.tar.gz
install -m 0755 remnascope-secagent-linux-$A /usr/local/bin/remnascope-secagent
install -m 0755 deploy/secagent/remnascope-containers-list /usr/local/sbin/
${linuxDropIn(host, o)}
${linuxShell(host, o.shell)}
${linuxUpdateUnits(o.upd, true)}
systemctl daemon-reload && systemctl restart remnascope-secagent-f2b remnascope-secagent
systemctl is-active remnascope-secagent
OWLERY`}</CopyCode>
            <p className="text-muted">{t('agent.update.keeps')}</p>
          </>
        )}
        {mode === 'update' && os === 'windows' && (
          <>
            <p>{t('agent.update.windows')}</p>
            <Code>{`$ErrorActionPreference = 'Stop'
$d = "$env:ProgramData\\Owlery"
if (Get-Service OwlerySecAgent -ErrorAction SilentlyContinue) { & "$d\\secagent.exe" uninstall | Out-Null }
# The screen and file helpers are this same program, started in a person's session; they keep the file in use.
Get-Process secagent -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$d\\*" } | Stop-Process -Force
$a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Invoke-WebRequest "${RELEASES}/remnascope-secagent-windows-$a.exe" -OutFile "$d\\secagent.exe" -UseBasicParsing
& "$d\\secagent.exe" install -server "wss://${host}" -token-file "$d\\secagent.token"${winFlags(o)}
Get-Service OwlerySecAgent`}</Code>
            <p className="text-muted">{t('agent.update.keeps')}</p>
          </>
        )}

        {mode === 'install' && os === 'windows' && (
          <>
            <p className="text-muted">{t('sec.onb.win.intro')}</p>
            <p>{t('sec.onb.win.s1')}</p>
            <Code>{`$ErrorActionPreference = 'Stop'
$d = "$env:ProgramData\\Owlery"
New-Item -ItemType Directory -Force $d | Out-Null
if (Get-Service OwlerySecAgent -ErrorAction SilentlyContinue) { & "$d\\secagent.exe" uninstall | Out-Null }
# The screen and file helpers are this same program, started in a person's session; they keep the file in use.
Get-Process secagent -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$d\\*" } | Stop-Process -Force
Set-Content -Path "$d\\secagent.token" -Value '${token}' -NoNewline -Encoding ascii
icacls "$d\\secagent.token" /inheritance:r /grant:r "*S-1-5-18:R" "*S-1-5-32-544:F" | Out-Null
$a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Invoke-WebRequest "${RELEASES}/remnascope-secagent-windows-$a.exe" -OutFile "$d\\secagent.exe" -UseBasicParsing
& "$d\\secagent.exe" install -server "wss://${host}" -token-file "$d\\secagent.token"${winFlags(o)}`}</Code>
            <p>{t('sec.onb.win.s2')}</p>
            <Code>{`Get-Service OwlerySecAgent
Get-Content "$env:ProgramData\\Owlery\\secagent.log" -Tail 5`}</Code>
            <p className="text-muted">{t('sec.onb.win.done')}</p>
          </>
        )}
        {mode === 'install' && os === 'linux' && (
          <>
            <p>{t('sec.onb.one')}</p>
            <CopyCode>{linuxInstallBlock(host, token ?? '', o)}</CopyCode>
            <p className="text-xs text-muted">{t('sec.onb.oneHint')}</p>
            <details className="border-t border-line pt-3">
              <summary className="cursor-pointer text-muted hover:text-fg">{t('sec.onb.stepwise')}</summary>
              <div className="mt-3 space-y-3">
            <p className="text-muted">{t('sec.onb.intro')}</p>
            <p>{t('sec.onb.s1')}</p>
            <Code>{'useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-sec\nuseradd --system --no-create-home --shell /usr/sbin/nologin remnascope-f2b'}</Code>
            <p>{t('sec.onb.s2')}</p>
            <Code>{`install -d -m 0755 /etc/remnascope && umask 077 && echo '${token}' > /etc/remnascope/secagent.token && chown root:remnascope-sec /etc/remnascope/secagent.token && chmod 0640 /etc/remnascope/secagent.token`}</Code>
            <p>{t('sec.onb.s3')}</p>
            <Code>{`cd /tmp
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64) A=arm64 ;; *) echo "unsupported processor"; exit 1 ;; esac
curl -fLO ${RELEASES}/remnascope-secagent-linux-$A
curl -fLO ${RELEASES}/remnascope-deploy-files.tar.gz
tar -xzf remnascope-deploy-files.tar.gz`}</Code>
            <p>{t('sec.onb.s4')}</p>
            <Code>{`install -m 0755 remnascope-secagent-linux-$A /usr/local/bin/remnascope-secagent
sed 's#wss://SCOPE_HOST#wss://${host}${o.web ? ' -allow-web' : ''}#' deploy/secagent/remnascope-secagent.service > /etc/systemd/system/remnascope-secagent.service
cp deploy/secagent/remnascope-secagent-f2b.service /etc/systemd/system/`}</Code>
            <p>{t('sec.onb.s5')}</p>
            <Code>{`mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/remnascope.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/fail2ban/fail2ban.sock ] && break; sleep 1; done; chgrp remnascope-f2b /run/fail2ban/fail2ban.sock && chmod 0660 /run/fail2ban/fail2ban.sock"
EOF
systemctl daemon-reload && systemctl restart fail2ban
systemctl enable --now remnascope-secagent-f2b remnascope-secagent`}</Code>
            <p className="text-muted">{t('sec.onb.s5hint')}</p>
            {o.shell && (
              <>
                <p>{t('sec.onb.shellStep')}</p>
                <Code>{`${linuxShell(host, true)} && systemctl restart remnascope-secagent`}</Code>
              </>
            )}
            <p>{t('sec.onb.s6')}</p>
            <Code>{`install -m 0755 deploy/secagent/remnascope-containers-list /usr/local/sbin/
cp deploy/secagent/remnascope-containers-list.service deploy/secagent/remnascope-containers-list.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now remnascope-containers-list.timer`}</Code>
            <p>{t('sec.onb.s7')}</p>
            <Code>{`systemctl is-active remnascope-secagent
journalctl -u remnascope-secagent -n 5 --no-pager`}</Code>
            <p className="text-muted">{t('sec.onb.done')}</p>
              </div>
            </details>
          </>
        )}
      </div>
      <div className="mt-4 flex justify-end">
        <PrimaryButton onClick={onClose}>{t(mode === 'install' ? 'sec.agent.tokenSaved' : 'agent.update.done')}</PrimaryButton>
      </div>
    </Modal>
  )
}

/** What the update button says when the server or the agent refused: in words, with the agent's own reason when it gave one. */
export function updateErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case 'update_failed': return t('agent.err.failed', { why: e.message })
      case 'agent_offline': return t('agent.err.offline')
      case 'up_to_date': return t('agent.err.upToDate')
      case 'update_not_allowed': return t('agent.updateNeedsPermission')
      case 'no_release_info': return t('agent.err.noRelease')
      // A reason this page has no words for is shown as it came, so it can be told to whoever looks after the panel.
      default: return `${errorText(e)} (${e.status} ${e.code}${e.message && e.message !== e.code ? `: ${e.message}` : ''})`
    }
  }
  return errorText(e)
}

const PERMS: { key: keyof AgentOpts; label: MsgKey }[] = [
  { key: 'shell', label: 'agent.perm.shell' }, { key: 'web', label: 'agent.perm.web' }, { key: 'desk', label: 'agent.perm.desk' },
  { key: 'scr', label: 'agent.perm.scr' }, { key: 'adm', label: 'agent.perm.adm' }, { key: 'blk', label: 'agent.perm.blk' }, { key: 'probe', label: 'agent.perm.probe' }, { key: 'upd', label: 'agent.perm.upd' },
]

/**
 * The machine's agent in one place: whether it is connected, its version, what the machine allows Owlery to do, and
 * the ways to install it, update it (with other permissions) or revoke it.
 */
export function AgentBlock({ vpsId, canEdit, hostOS }: { vpsId: string; canEdit: boolean; hostOS?: string }) {
  const { data, error, reload } = useLoad((s) => api.get<{ agent: SecAgent | null }>(`/api/v1/security/vps/${vpsId}/agent`, s), [vpsId], 15_000)
  const [token, setToken] = useState('')
  const [updating, setUpdating] = useState(false)
  const [confirm, setConfirm] = useState(false)
  const [err, setErr] = useState('')
  // The error of the update button is shown by the button, not up in the corner of the card.
  const [updErr, setUpdErr] = useState('')
  const [pushing, setPushing] = useState(false)
  // The newest release, asked of the server (which asks GitHub at most every ten minutes), and an update that is under way.
  const latest = useLoad((s) => api.get<{ version: string }>('/api/v1/agent/latest', s), [], 600_000)
  const [run, setRun] = useState<{ to: string; since: number; failed: boolean } | null>(null)
  const agent = data?.agent ?? null
  const newest = latest.data?.version ?? ''
  const hasNew = !!agent && isNewer(newest, agent.agent_version)
  const canPush = hasNew && !!agent?.online && agent.capabilities.includes('self_update')
  const done = !!run && !!agent && agent.agent_version === run.to
  useEffect(() => {
    if (!run || run.failed || done) return
    const id = window.setInterval(() => {
      reload()
      setRun((r) => (r && Date.now() - r.since > 5 * 60_000 ? { ...r, failed: true } : r))
    }, 3000)
    return () => window.clearInterval(id)
  }, [run, done, reload])
  async function pushUpdate() {
    setUpdErr('')
    setPushing(true)
    try {
      await api.post(`/api/v1/security/vps/${vpsId}/agent/update`, { version: newest })
      setRun({ to: newest, since: Date.now(), failed: false })
    } catch (e) {
      setUpdErr(updateErrorText(e))
    } finally {
      setPushing(false)
    }
  }
  const os: OS = /windows/i.test(hostOS ?? '') ? 'windows' : 'linux'
  const opts = optsFromCaps(agent?.capabilities ?? [])

  async function create() {
    setErr('')
    try {
      const r = await api.post<{ token: string }>(`/api/v1/security/vps/${vpsId}/agent`)
      setToken(r.token)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }
  async function revoke() {
    setConfirm(false)
    setErr('')
    try {
      await api.del(`/api/v1/security/vps/${vpsId}/agent`)
      reload()
    } catch (e) {
      setErr(errorText(e))
    }
  }

  return (
    <Card title={t('sec.agent')} note={t('sec.agent.onlyConn')}>
      {(error || err) && <p role="alert" className="mb-2 text-[13px] text-red">{error || err}</p>}
      {data && !agent && <p className="text-[13px] text-muted">{t('sec.agent.none')}</p>}
      {agent && (
        <div className="space-y-2 text-[13px]">
          <div className="flex flex-wrap items-center gap-3">
            <Chip tone={agent.online ? 'green' : 'muted'}>{agent.last_seen ? (agent.online ? t('sec.agent.online') : t('sec.agent.offline')) : t('sec.agent.waiting')}</Chip>
            {agent.agent_version && <span className="text-muted">{agent.agent_version.startsWith('v') ? '' : 'v'}{agent.agent_version}{agent.hostname ? ` · ${agent.hostname}` : ''}</span>}
            {hasNew && !run && <Chip tone="amber">{t('agent.newVersion', { v: newest })}</Chip>}
            {run && !run.failed && !done && <Chip tone="amber">{t('agent.updating')}</Chip>}
            {done && <Chip tone="green">{t('agent.updated', { v: run!.to })}</Chip>}
            {run?.failed && !done && <Chip tone="red">{t('agent.updateFailed')}</Chip>}
          </div>
          {run && !run.failed && !done && <p className="text-xs text-muted">{t('agent.updatingNote', { from: agent.agent_version ?? '', to: run.to })}</p>}
          {agent.last_seen && <p className="tnum text-muted">{t('sec.agent.lastSeen')}: {formatDateTime(agent.last_seen, 'local')}</p>}
          {agent.last_seen && (
            <div>
              <p className="mb-1 text-xs text-muted">{t('agent.perms')}</p>
              <div className="flex flex-wrap gap-1.5">
                {PERMS.map((p) => <Chip key={p.key} tone={opts[p.key] ? 'cyan' : 'muted'}>{opts[p.key] ? '✓ ' : '✕ '}{t(p.label)}</Chip>)}
              </div>
            </div>
          )}
        </div>
      )}
      {canEdit && data && (
        <div className="mt-3 flex flex-wrap gap-3">
          {!agent && <PrimaryButton onClick={() => void create()}>{t('sec.agent.create')}</PrimaryButton>}
          {canPush && !run && <PrimaryButton onClick={() => void pushUpdate()} disabled={pushing}>{pushing ? t('agent.sending') : t('agent.updateTo', { v: newest })}</PrimaryButton>}
          {agent && (canPush && !run ? <GhostButton onClick={() => setUpdating(true)}>{t('agent.update')}</GhostButton> : <PrimaryButton onClick={() => setUpdating(true)}>{t('agent.update')}</PrimaryButton>)}
          {agent && <GhostButton onClick={() => setConfirm(true)}>{t('sec.agent.revoke')}</GhostButton>}
        </div>
      )}
      {pushing && <p role="status" className="mt-2 text-[13px] text-amber">{t('agent.sendingNote')}</p>}
      {updErr && <p role="alert" className="mt-2 text-[13px] text-red">{updErr}</p>}
      {canEdit && canPush && !run && !pushing && !updErr && <p className="mt-2 text-xs text-muted">{t('agent.updateHelp')}</p>}
      {canEdit && hasNew && !canPush && !run && <p className="mt-2 text-xs text-muted">{t('agent.updateNeedsPermission')}</p>}
      {token && <AgentSetupDialog mode="install" token={token} initial={{ shell: true, web: true, desk: true, scr: false, adm: false, blk: false, probe: false, upd: true }} initialOS={os} onClose={() => setToken('')} />}
      {updating && <AgentSetupDialog mode="update" initial={opts} initialOS={os} onClose={() => setUpdating(false)} />}
      {confirm && (
        <Modal title={t('sec.agent.revoke')} onClose={() => setConfirm(false)}>
          <p className="text-[13px] text-muted">{t('agent.revokeWarn')}</p>
          <div className="mt-4 flex justify-end gap-3">
            <GhostButton onClick={() => setConfirm(false)}>{t('common.cancel')}</GhostButton>
            <DangerButton onClick={() => void revoke()}>{t('sec.agent.revoke')}</DangerButton>
          </div>
        </Modal>
      )}
    </Card>
  )
}
