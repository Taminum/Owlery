# Installing the agent on a Remnawave node

Applying it is a change on a production server, so do it node by node, starting with the least busy one.

## What it does and does not do
- Follows `/var/log/xray/current` inside the `remnanode` container with `tail -n 0 -F` and ships
  the lines to RemnaScope over `wss://`. It only reads.
- Does **not** change the container, its mounts, its config, or Docker. No restart, no recreate.
- Keeps unsent lines in a bounded spool (default 256 MiB). If that fills up, it drops new lines
  and **reports the exact number** to the server; loss is never silent.
- Holds a credential that opens exactly one door: sending lines for one node. It is revocable in the UI.

## Why `docker exec`, and how the privilege is limited
The log is not mounted on the host (`/var/log/xray/current` exists only inside the container).
Reading it means running `docker exec`, which needs Docker access. Docker group membership is
root-equivalent, so the agent user is **not** put in it. Instead a sudoers rule lets that one user run
that one command, with fixed arguments:

```
# /etc/sudoers.d/remnascope-agent   (mode 0440, check with: visudo -cf /etc/sudoers.d/remnascope-agent)
remnascope ALL=(root) NOPASSWD: /usr/bin/docker exec remnanode tail -n 0 -F /var/log/xray/current
```

A compromised agent could therefore tail that one file and nothing more. The trade-off: the unit
cannot set `NoNewPrivileges=yes` (sudo is setuid); every other sandbox option is on.
The alternative, a read-only bind mount of the log directory, would need `remnanode` to be
recreated and is not used.

## Steps (per node)
1. In RemnaScope: Panels, the panel, **Агенты**, **Создать агента** for the node. Copy the token
   (shown once).
2. On the node, as root:
```
useradd --system --home /var/lib/remnascope-agent --shell /usr/sbin/nologin remnascope
install -d -m 0755 /etc/remnascope
install -m 0640 -o root -g remnascope /dev/stdin /etc/remnascope/agent.token   # paste the token, then Ctrl-D
install -m 0755 remnascope-agent /usr/local/bin/remnascope-agent               # build: see below
printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/bin/docker exec remnanode tail -n 0 -F /var/log/xray/current' > /etc/sudoers.d/remnascope-agent
chmod 0440 /etc/sudoers.d/remnascope-agent && visudo -cf /etc/sudoers.d/remnascope-agent
install -m 0644 remnascope-agent.service /etc/systemd/system/      # set SCOPE_HOST first
systemctl daemon-reload && systemctl enable --now remnascope-agent
```
3. Check: `journalctl -u remnascope-agent -n 20` shows `connected`; the Agents dialog shows the node as
   running with a growing line count.

Build the binary: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o remnascope-agent ./cmd/agent`.

## Rollback (removes everything the install added)
```
systemctl disable --now remnascope-agent
rm -f /etc/systemd/system/remnascope-agent.service /etc/sudoers.d/remnascope-agent /usr/local/bin/remnascope-agent
rm -rf /etc/remnascope /var/lib/remnascope-agent && userdel remnascope && systemctl daemon-reload
```
Then revoke the agent in RemnaScope. The VPN is untouched by any of this.

## Before the first real node
- RemnaScope must be reachable from the node over HTTPS with a valid certificate, and the reverse
  proxy must pass WebSocket upgrades on `/ingest/` (the bundled nginx config does).
- Start with the least busy node. Watch CPU of the `docker exec` process: `tail -F` on a ~10 MiB
  rotating file is cheap, but the first hour is the time to find out.
- Known limit: lines written while the agent or `docker exec` is down are not seen; the agent
  reports a `source_restart` gap each time that happens.
