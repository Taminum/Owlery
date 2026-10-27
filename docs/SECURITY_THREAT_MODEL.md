# Threat model: Security module and DNS Map

This covers the server-security module (agent, helper, external checks, journal, alerts) and the DNS Map. The
general model for the rest of Owlery is in [SECURITY.md](SECURITY.md). What follows is what was built, what
it defends against, and what it does not.

## Assets

- The hosts the module watches, and their Fail2ban: a wrong ban can lock a person out, a wrong unban lets an
  attacker back in.
- The agent credential of each server (`<agent id>.<secret>`): whoever holds it speaks as that agent.
- The picture the module gives the owner. A false "all is well" is worse than no picture.
- The Owlery server's network position: it dials out to public addresses for checks and DNS.

## Actors and their reach

| Actor | Can | Cannot |
|---|---|---|
| Owner | everything, including ban/unban and opting a server in to the port scan | read an agent's secret again after issue |
| Admin of a linked panel | see and edit a server linked to that panel, issue/revoke its agent, add endpoints, toggle the scan | ban/unban (owner only in this version), see servers not linked to their panels |
| Viewer/operator of a linked panel | read | change anything |
| A security agent | report snapshots for its own server, answer commands and probes sent to it | read another server's data, ask the server for anything, have its commands run for another server |
| The Owlery server | send ban/unban to an agent that announced `fail2ban_ban`, send probes to one that announced `probe` | run anything else on an agent: there is no other message that does something |
| A compromised agent host | lie about its own server; answer probes with chosen results | affect another server, run commands on Owlery, make Owlery dial a private address (checks run on the server's own dialer, probes only reach agents that chose to be checkers) |

## Boundaries and what holds them

**Agent to server.** Outbound WSS only; the agent listens on nothing. Authentication is a bearer secret, stored
hashed, compared in constant time; an unknown id costs the same as a wrong secret. A revoked or archived server's
agent is cut at its next message. Snapshots carry an epoch and a sequence number, are acknowledged only after
commit, and a replayed sequence is acknowledged but not stored twice. Every payload is parsed with unknown fields
refused and bounded in size and count; a malformed one ends the session instead of being stored.

**Server to agent.** Exactly three messages exist: `command` (ban or unban one address in one jail), `probe` (a
TCP connect or a TLS handshake against one host and port), and the acknowledgements. None carries free text that
becomes a shell argument.

- *Commands.* A command has a server-chosen UUID, a deadline, and is delivered over the live connection or not at
  all: nothing is queued for later. The agent re-validates every field, writes the ID to disk before running,
  refuses an ID it has seen (also after a restart) and refuses one that arrives later than its time to live. The
  helper, a separate unprivileged service on a Unix socket, is the only process that touches Fail2ban's socket; it
  accepts five fixed operations, checks the jail against a pattern and the address as an IP, refuses loopback,
  unspecified, multicast and broadcast, runs `fail2ban-client` with a fixed argument list and no shell, and reads
  the state back to say whether the result is as wanted. An answer the agent could not verify is stored as
  unknown, never as success. Only the agent the command was sent to can settle it, and only once.
- *Probes.* A probe is only ever sent to an agent whose host switched `-probe` on. The agent dials public
  addresses only (private, loopback and link-local are refused on the agent itself, whatever the server asks),
  sends no data on a TCP probe, never turns certificate verification off for its verdict, runs at most four at
  once, and bounds its answer. The server takes back only a known verdict, counts certificate days from its own
  clock, and falls back to its own check when the answer is refused, late or not a verdict.

**Operator to server.** Existing session auth, CSRF and RBAC. A server is visible to the owner and to roles on a
panel it is linked to; one with no links is the owner's alone. Every list, detail, history, diff, event and
lookup is scoped by the same predicate, so a panel role cannot read another server by id. Ban/unban is
owner-only, needs an idempotency key and a confirmation in the UI, is rate-limited, and both the intent and the
outcome are in the audit log. Nothing in the module changes a firewall.

**Server to the internet (checks and DNS).**

- *No "check any host".* A check target must be an address or domain registered on that server. A hostname is
  resolved by the checker and only public addresses are dialled; the address actually connected to is checked
  again in the dial hook, so a name that moves to a private address between lookup and connect (rebinding) is
  refused.
- *No arbitrary payload.* TCP checks send nothing. TLS handshakes are made only for configured endpoints, for
  endpoints a known listener or registered domain presented a certificate on at a well-known TLS port, and never
  for SSH, mail-submission or other non-TLS ports.
- *Bounded discovery.* The port scan is off by default, per server, a fixed list of about sixty ports, on that
  server's registered IP addresses only, at most four connects at once with a pause, once a day.
- *DNS.* Its own small client on `dnsmessage`; resolvers are fixed (1.1.1.1, 8.8.8.8), authoritative servers are
  contacted only at public addresses; the number of names per study is capped.

## What a result means (and does not)

- "Reachable" is *from the vantage that was recorded*. A result from the Owlery server itself is marked not
  independent, because the server cannot know that it is not the machine being checked. A result from a checker
  is independent only when the checker is not the target's server and the address it connected to is not its own.
- A timeout or a filtered port is "no answer", not "closed". Only a refusal from the asked address says closed.
- A port that is not on a list was not looked at. "Nothing found" by the scan means nothing among those ports on
  those addresses at that moment.
- Firewall rules are shown and compared as text. Nothing here says that a rule allows or blocks a port; shadowing,
  other namespaces and rules loaded elsewhere are invisible to a text reader.
- DNSSEC is never reported as validated: the module does not validate a chain, and says "not checked".
- A change in DNS is reported only when both resolvers agree, and a record that flips often is marked volatile and
  raises no alert.
- Overview "healthy" means nothing alarming among what is read and checked, with the coverage next to it.
  Nothing read and nothing checked is "unknown", never healthy.

## Threats considered and where they land

| Threat | Mitigation | Residual |
|---|---|---|
| Stolen agent token | revoke at once from the UI; secret shown once; file readable by root and the agent's group only | the holder can send false snapshots until revoked, and answer for its own server |
| Compromised Owlery server | agent accepts only ban/unban and probes, never runs a shell; helper validates again | an attacker with the server can ban chosen addresses on hosts whose agents have `fail2ban_ban`, and can have `-probe` hosts connect to public addresses |
| Forged or replayed command | one-time ID persisted before execution, TTL, only the addressed agent can answer | none known |
| Command to a wrong host | commands are keyed by the agent's VPS; the answer must come from that agent | none known |
| SSRF through checks | registered targets only, public addresses only, dial-time address check, bounded concurrency | a registered domain whose records an attacker controls can make Owlery connect to *its* public addresses |
| Probe as a scanner from an agent | opt-in per host, public addresses only, no payload, four at once | an owner who enables `-probe` accepts that |
| Alert flood | state-based alerts keyed on `(kind, subject)`; journal events from state differences with a silent baseline; one notice per expiry threshold | none known |
| False green | stale data is called stale, no agent is "no agent", a failed read is its own state, overview has an explicit unknown | a host whose agent is up but whose Fail2ban was replaced by something lying is read as it reports |
| Secrets in logs, audit or UI | tokens are not logged; audit holds ids and outcomes, not output; responses never echo a secret after issue | none known |
| Retention surprises | 180 days applies to the module's own history only; audit log and analytics are untouched | none |

## Not covered

- The security of the monitored hosts themselves. This is a visibility tool, not a hardening tool.
- Fail2ban's log. Bans are named from state comparisons every five seconds (see SECURITY_AGENT.md); a ban and
  unban between two comparisons is counted, not named.
- Anything on Windows, macOS or non-systemd Linux. The agent targets systemd Linux with Fail2ban, `ss`, and
  nftables or iptables.
- Multi-tenant isolation beyond panel scopes: this is one owner's tool with panel roles, not a hosted service.
