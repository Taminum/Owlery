# Security agent (`secagent`)

The security agent reports a VPS's security state to RemnaScope: **Fail2ban**, **listening sockets** and
**firewall rules**. It is separate from the Xray log agent: its own binary, its own credential, its own
channel (`/ingest/security/v1`).

## What it does and does not do

- Reads only. Every command runs without a shell, with a fixed argument list, a 10 second timeout and a
  cap on its output: `fail2ban-client status [jail]`, `ss -H -tulnp`, `nft list ruleset`, `iptables-save`.
- Connects outward over `wss://`. It listens on nothing.
- The server can send it nothing but acknowledgements. A message of any other type ends the session, so a
  compromised server cannot make it run anything. (Manual ban/unban is a later stage and will arrive as a
  separate, narrow helper, not through this channel.)
- Reports every 30 seconds. A report is a whole snapshot, so a missed one costs freshness, not data.
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
compared only when both reads succeeded. Ban/unban events seen this way carry `source: state_diff` — the
time is when the change was *noticed*, not when Fail2ban acted.

## Install

1. In RemnaScope open **Безопасность → your server → Создать агента**. The secret is shown once.
2. On the VPS:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin remnascope-sec
   sudo install -d -m 0755 /etc/remnascope
   echo '<id.secret>' | sudo tee /etc/remnascope/secagent.token >/dev/null
   sudo chown root:remnascope-sec /etc/remnascope/secagent.token && sudo chmod 0640 /etc/remnascope/secagent.token
   sudo install -m 0755 remnascope-secagent-linux-amd64 /usr/local/bin/remnascope-secagent
   sudo cp remnascope-secagent.service /etc/systemd/system/    # edit SCOPE_HOST first
   sudo systemctl daemon-reload && sudo systemctl enable --now remnascope-secagent
   ```
   The binary and the unit are attached to each release (`deploy/secagent` in the deploy-files archive).

## Privileges

The unit runs as an unprivileged user with three capabilities:

- `CAP_NET_ADMIN` to read the firewall (`nft`, `iptables-save`);
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` so `ss -p` can name the process that owns a socket. Without
  them the sockets are still listed and the screen says process names are unavailable.

**Fail2ban needs a decision from you.** Its control socket belongs to root, and a non-root user cannot use
it. Until you choose, the Fail2ban tab shows `permission_denied`; nothing else is affected. Options, from
the narrowest:

1. Give the socket to a group the agent is in (a systemd drop-in for `fail2ban.service` with
   `ExecStartPost=/bin/chgrp remnascope-sec /run/fail2ban/fail2ban.sock` and `chmod 0660`). The socket
   accepts every Fail2ban command, so this lets that user ban and unban locally; weigh that.
2. A sudoers rule allowing exactly `fail2ban-client status` and `fail2ban-client status *` — not a general
   rule — and a wrapper. This is not shipped yet.

Do not run the agent as root to avoid the question: it would work, and it would also mean a defect in the
agent is a root defect.

## Limits of this version

- No journal tailing yet: Fail2ban history comes from comparing states every 30 seconds, so a ban and an
  unban between two reads is missed.
- Firewall rules are stored as canonical text (counters, handles and timestamps removed), not as a
  structured model; the change view is "the rules changed", without a line diff.
- Listening sockets are the host's own. Containers with their own network namespace may not appear.
- Open ports seen from outside, TLS certificates and manual ban/unban are later stages.
