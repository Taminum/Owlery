# Security agent (`secagent`)

The security agent reports a VPS's security state to RemnaScope: **Fail2ban**, **listening sockets** and
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

1. In RemnaScope open **Безопасность → your server → Создать агента**. The secret is shown once, and the window
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

## Limits of this version

- No journal tailing yet: Fail2ban history comes from comparing states every 30 seconds, so a ban and an
  unban between two reads is missed.
- Firewall rules are stored as canonical text (counters, handles, timestamps and Fail2ban's bans removed),
  not as a structured model; the change view is "the rules changed", without a line diff.
- Listening sockets are the host's own. Containers with their own network namespace may not appear.
- Ban and unban act on Fail2ban's jails only. Nothing in RemnaScope changes the firewall.
