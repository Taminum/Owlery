# Security agent (`secagent`)

The security agent reports a VPS's security state to Owlery: **Fail2ban**, **listening sockets** and
**firewall rules**. It also carries out a **ban or unban of one address** when the owner asks for it. It is
separate from the Xray log agent: its own binary, its own credential, its own channel (`/ingest/security/v1`).

## What it does and does not do

- Reads: `ss -H -tulnp`, `nft list ruleset`, `iptables-save`, and Fail2ban through the helper (below). Every
  command runs without a shell, with a fixed argument list, a 10 second timeout and a cap on its output.
- Connects outward over `wss://`. It listens on nothing.
- Reports every 30 seconds. A report is a whole snapshot, so a missed one costs freshness, not data.
- The server can send it **one kind of request**: ban or unban one address in one jail. Anything else, or a
  request when the host has not enabled this, is refused; a message of any other type ends the session.
- UFW is not read on its own: it is a front end over nftables/iptables and its rules show up there.

## What the screen means

Each category has its own state and the time it was taken. The agent being **online** says only that the
connection is alive.

| State | Meaning |
|---|---|
| `agent_required` | No agent has been created for this server. Nothing is known. |
| `waiting` | The agent exists but has not delivered this category yet. |
| `ok` | Read successfully at the time shown. |
| `stale` | The agent stopped refreshing it (over 2 minutes). The last known state is shown with its own time. |
| `not_installed`, `stopped` | The tool is absent, or Fail2ban is not running. |
| `permission_denied` | The agent was not allowed to read it. The previous state is **not** assumed to hold. |
| `unsupported`, `error` | `ss` is missing, or the output could not be understood. |

The journal records a change only when two consecutive reads differ. The first read of a category is a
baseline and produces no events. A read that fails is never treated as "everything was lifted": bans are
compared only when both reads succeeded. Ban/unban events seen this way carry `source: state_diff`: the
time is when the change was *noticed*, not when Fail2ban acted. Fail2ban's own bans are kept out of the
firewall comparison (they are the Fail2ban events), so a ban does not look like a firewall change.

## Install

The agent needs no root. Fail2ban is handled by a second, equally small service, the **helper**, which is the
only process that touches Fail2ban's socket.

1. In Owlery open **Безопасность → your server → Создать агента**. The secret is shown once, and the window
   lists these steps with it filled in.
2. On the VPS:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-sec
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-f2b
   sudo install -d -m 0755 /etc/remnascope
   echo '<id.secret>' | sudo tee /etc/remnascope/secagent.token >/dev/null
   sudo chown root:remnascope-sec /etc/remnascope/secagent.token && sudo chmod 0640 /etc/remnascope/secagent.token
   sudo install -m 0755 remnascope-secagent-linux-amd64 /usr/local/bin/remnascope-secagent
   sudo cp remnascope-secagent.service remnascope-secagent-f2b.service /etc/systemd/system/   # edit SCOPE_HOST first
   ```
3. Give the helper (and nobody else) Fail2ban's socket. A systemd drop-in for `fail2ban.service`,
   `/etc/systemd/system/fail2ban.service.d/remnascope.conf`:
   ```ini
   [Service]
   ExecStartPost=/bin/sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/fail2ban/fail2ban.sock ] && break; sleep 1; done; chgrp remnascope-f2b /run/fail2ban/fail2ban.sock && chmod 0660 /run/fail2ban/fail2ban.sock"
   ```
   then `sudo systemctl daemon-reload && sudo systemctl restart fail2ban`.
4. Start both: `sudo systemctl enable --now remnascope-secagent-f2b remnascope-secagent`.

5. Optional, for container names on the resources page (the agent has no access to Docker, so it would show
   a container by its short id): a small root timer writes the list of running containers for it.
   ```sh
   sudo install -m 0755 remnascope-containers-list /usr/local/sbin/
   sudo cp remnascope-containers-list.service remnascope-containers-list.timer /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now remnascope-containers-list.timer
   ```
   It runs `docker ps` and writes `/run/remnascope-sec/containers.tsv` (short id and name, nothing else, names
   checked against a strict pattern), readable by the agent's group. Without it everything else works.

The binary and the units are attached to each release (`deploy/secagent` in the deploy-files archive).

Without Fail2ban, or without wanting ban/unban, install only the agent: drop `-helper-socket` and `-state-dir`
from the unit. The sockets and firewall are read as before; Fail2ban is then read by the agent directly and
needs its own access to the socket.

## Privileges

- **The agent** runs as `remnascope-sec` with three capabilities: `CAP_NET_ADMIN` (read the firewall) and
  `CAP_SYS_PTRACE` plus `CAP_DAC_READ_SEARCH` (so `ss -p` can name a socket's process; without them sockets are
  still listed and the screen says process names are unavailable). It has **no access to Fail2ban's socket**.
- **The helper** runs as `remnascope-f2b`, which is in the group that owns Fail2ban's socket, with no capabilities
  and a closed sandbox. It answers on a Unix socket reachable only by the agent's group. It offers four
  operations and nothing else: `status`, `status <jail>`, `set <jail> banip <ip>`, `set <jail> unbanip <ip>`.
  It validates the jail against a fixed pattern and against Fail2ban's own list, parses the address, refuses
  loopback, unspecified, multicast and broadcast, and reads the jail again to verify what it did.
- Nothing runs as root except Fail2ban itself. A defect in the agent cannot ban or read more than the helper's
  four operations allow, and the helper never passes text it was given to a command except as a parsed address
  or a name that matched the pattern.

## Ban and unban

Only the **owner** can ask (the permission is `security.fail2ban.manage`; a role on a panel does not carry it). The
request is validated on the server, goes out over the agent's live connection, and is carried out by the agent
through the helper.

- **Confirmation, with the consequences.** Banning your own address, a non-public address, or one of the
  server's own addresses needs an explicit acknowledgement.
- **No queue.** If the agent is not connected, or its last read of Fail2ban is not fresh, the request fails
  at once with a reason. Nothing waits to be sent later, so a command can never run after the situation that
  prompted it has changed.
- **At most once.** Each command has an ID. The agent writes the ID down *before* it runs anything, so a retry,
  a replay, or a restart in the middle cannot run it twice; a command that waited more than its 30 seconds
  before starting is refused. Repeating a request with the same `idempotency_key` returns the same command.
- **Honest outcomes.** `executed` means the helper ran the command and read the jail again and found the
  address as wanted. `already_done` means nothing needed changing. If the agent could not verify, or does not
  answer in time, the command is `unknown`, never "executed"; the next read of Fail2ban then settles it as
  `confirmed_by_state`, or as `failed` if the address is still not as wanted well after the deadline.
- **Audit.** The intent (who, which server, jail, address, request ID) and the outcome are both in the audit
  log. Neither contains a secret or command output.

An address banned or unbanned this way also appears in the journal as a Fail2ban event a moment later, from
the state comparison.

## Running as a checker

An agent started with `-probe` also lets the server ask it to connect to a public TCP port or read a TLS
certificate, so that a target can be seen from a machine that is not the target. It is off by default and
is a decision of the host's owner: it makes that host dial public addresses on the server's request. It
never dials a private, loopback or link-local address, never sends data on a TCP probe, and runs at most
four probes at once.

To turn it on, add a systemd drop-in that repeats `ExecStart` with `-probe` appended (see
`deploy/secagent/probe.conf.example`) and restart the service. The agent then announces `probe` on its next
connection; see [SECURITY_CHECKS.md](SECURITY_CHECKS.md) for how the server uses it.

## Limits of this version

- Fail2ban history comes from comparing states, not from its log. Besides the full read every 30 seconds, the
  agent asks Fail2ban for its single list of banned addresses every 5 seconds (`fail2ban-client banned`,
  through the helper) and reads and sends Fail2ban in full as soon as that list moved, so a ban or an unban is
  named within seconds. A Fail2ban that does not have that listing falls back to the 30-second read. A ban and
  an unban between two comparisons is still not *named*; it is counted: Fail2ban's own ban counter is compared
  between reads, and when it grew by more than the new addresses that are visible, the journal records
  `fail2ban.bans_unobserved` with the number. Naming those would need read access to Fail2ban's log, which is
  a privilege decision for the host owner (the log is readable by root and group `adm`), not something this
  agent asks for on its own.
- Firewall rules are stored as canonical text (counters, handles, timestamps and Fail2ban's bans removed).
  The screen reads them into tables, chains and policies, and compares two stored readings line by line;
  it does not interpret what a rule allows. Whether a port is really open is for the external check to say.
- Listening sockets are the host's own. Containers with their own network namespace may not appear.
- Ban and unban act on Fail2ban's jails only. Nothing in Owlery changes the firewall.

## Terminal (optional)

A machine can allow Owlery to open its console from the server card (tab "Терминал"). It is the machine's decision,
made when the agent is installed:

- **Linux.** The agent is not root, so it cannot give a useful shell. A separate helper,
  `remnascope-shell.service`, runs as root and opens the shells; the agent only hands it a session id over the
  socket `/run/remnascope-shell/shell.sock` (group `remnascope-sec`). The agent offers a terminal only while that
  socket exists. Without the helper the machine cannot be given a terminal from Owlery at all, even by someone who
  took over Owlery itself. Remove the helper (`systemctl disable --now remnascope-shell`) to take the permission back.
- **Windows.** The service runs as the system; `secagent.exe install ... -allow-shell` allows the terminal
  (PowerShell). Reinstall without the flag to take it back.

For each session the machine connects back to `/ingest/security/v1/shell` with its own credential, so terminal
bytes never share a connection with the reports. Owlery writes what the machine prints to a recording as it arrives
(`RECORDS_DIR`, one file per session, at most 50 MB each) and puts opening and closing, with the duration, into the
audit log. Only the owner and administrators of a linked panel can open a terminal.

## Remote desktop (optional, Windows)

`secagent.exe install ... -allow-desktop` lets Owlery open the machine's own remote desktop (RDP on 127.0.0.1:3389,
or VNC on :5900) in the browser, tab "Рабочий стол" of the server card. The agent dials out twice for each session,
to Owlery and to the local port, and listens on nothing, so the desktop port can stay closed to the whole network.
In Owlery the stream goes through guacd (the `guacd` service of the stack, `GUACD_ADDR`), which reaches the tunnel
through a one-off port on the API that accepts only guacd. The Windows login is typed for each connection and never
stored: the page trades it for a ticket that is good for one connection within a minute. Opening and closing go to
the audit log; the picture itself is not recorded.

## Screen sharing (optional, Windows)

Tab "Экран" of the server card shows the screen of the person at the machine, live, and takes the administrator's mouse
and keyboard, like a remote assistant; it is not a replacement for the RDP tab. It is on only when the machine says so:
`secagent.exe install ... -allow-screen` (the box "Разрешить показ экрана" in the install dialog). That install writes a
secret and downloads ffmpeg; there is nothing else to put on the machine.

The helper is not a separate program — it is the agent binary run as `secagent screen-helper`, the same way the Linux
terminal helper is `secagent shell-helper`. The agent is a system service in session 0 and cannot see any desktop, so
when a session is asked for it launches itself as the helper into the signed-in person's own session, as the system
account (`WTSGetActiveConsoleSessionId` + a session-stamped copy of its token + `CreateProcessAsUser`). Running as the
system account, and moving each screen grab and each click onto whichever desktop is receiving input (`OpenInputDesktop`
+ `SetThreadDesktop`), is what lets it reach the secure desktop as well — UAC prompts and the lock screen — and drive
windows opened "as administrator", which a tool running with the person's ordinary rights cannot. If nobody is signed
in, there is no session to launch into and Owlery says so.

Which session is shown: the one of a person signed in at the physical console; otherwise the first session with somebody
signed in and connected, which is where an administrator working over remote desktop sits (on a server that is the usual
case, and the console is empty); with nobody signed in anywhere, the console's sign-in screen. Each session has its own
helper on its own loopback port (47821 plus the session number). A session whose screen cannot be read at all is
reported to the page after about two seconds rather than left "connecting".

The helper listens on 127.0.0.1 only and accepts a connection only after the shared secret written at install, readable
by the system account and administrators alone — the boundary that stops any other local process from driving the screen.
The agent dials out to Owlery for each session and relays bytes to the helper; Owlery relays them to the browser. The
picture is H.264: this process captures each frame (GDI, so it can follow onto the secure desktop, which DXGI Desktop
Duplication cannot) and feeds it to `ffmpeg.exe` installed next to the helper, which encodes it; the browser decodes with
WebCodecs. Without ffmpeg it falls back to JPEG pictures.

While a session is open the helper shows an icon in the person's notification area; its menu has "Прекратить показ",
which ends the session at once. Opening and closing go to the audit log (`screen.open`, `screen.close`); the screen is
never recorded.

## Web services (optional)

`-allow-web` (on Linux in the unit's `ExecStart`, on Windows `secagent.exe install ... -allow-web`) lets Owlery open
web services bound to 127.0.0.1 on the machine, such as an admin panel, at an address of their own:
`https://<name>.<SERVICES_DOMAIN>` (tab "Службы" of the server card). Only the machine's own loopback is reachable,
not its local network. The agent dials out to Owlery and to `127.0.0.1:<port>` for each connection
(`/ingest/security/v1/proxy`) and listens on nothing.

Each service has an origin of its own, so its pages cannot read Owlery's cookies or call its API. Owlery's session
cookie never reaches a service: a visit without the service's own cookie is sent to Owlery, which checks the person
(owner or administrator of a linked panel) and returns them with a one-minute ticket; the service host trades it for
an 8-hour cookie of its own, which is removed from every request before it reaches the panel. Opening a service is
in the audit log (`web.open`). Caddy gets a certificate for a service's name when it is first opened, and only after
Owlery confirms the name is a published service; this needs a wildcard DNS record `*.<SERVICES_DOMAIN>` pointing at
the server. A name is never reused, even after the service is removed, so an old link cannot lead to another panel.

## Management of a Windows machine (optional)

Tab "Управление" of the server card looks at the machine and changes it without showing anything on its screen: the
agent does the work, as the system account. Sections: processes (end one), services (start, stop, restart, change how
it starts), startup entries (the Run keys and the Startup folders: remove, add), user sessions (disconnect, sign out),
the event log (System, Application, Security, by level) and network connections with the process that owns each.

It is on only when the machine was installed with `secagent.exe install ... -allow-admin` (the box "Разрешить
управление"), because it is as strong as the terminal. Each change asks for a confirmation in the page and is written to
the audit log as `manage.<operation>` with what was asked, before the machine is told. Looking is not recorded.

Refused by the agent whatever the page asks: ending the system's own processes (csrss, lsass and the like), stopping or
disabling the agent's own service, removing anything that is not a Run-key value or a file in a Startup folder, and
reading event logs other than System, Application and Security. A request goes over the agent's existing connection and
is answered on it (not a new connection); an answer is capped at 900 KB.
