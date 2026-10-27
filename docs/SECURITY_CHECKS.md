# External checks: public ports and TLS certificates

Owlery checks a VPS from the outside: whether known TCP ports answer, and what certificate a TLS endpoint
presents. This is separate from the security agent, which reads the host from the inside.

## Where the check runs from

Each result says where it was made from (`vantage`), and whether that is **independent** of the checked
server:

- **A checker.** A security agent whose host was set up with `-probe` announces the `probe` capability. The
  server asks it, over its live connection, to connect to a TCP port or to read a TLS certificate, and takes
  its answer. The vantage is `agent:<server id>` with the checker's name. It is independent only when the
  checker is not the checked server and the address it actually connected to is not one of the checker's own.
  A server is never checked by an agent that lives on it.
- **The Owlery server itself** (vantage `api_server`), when no checker qualifies, is connected, or answers
  in time. This is **not an independent point of view**: if the API runs on the VPS being checked, a result
  says the port answers *from that machine*, not that it is reachable from the internet. The UI says so.

The checker is chosen automatically among the connected ones; with several, the oldest enrolled that is not
the target goes first. The server does not trust an agent's answer beyond its shape: a result that is not one
of the known verdicts is dropped and the check is made from the server, and the number of days left on a
certificate is counted from the server's clock.

The agent re-checks every request itself: it dials public addresses only (a private, loopback or link-local
target is refused there too, whatever the server asks), runs at most four probes at once, sends no data on a
TCP probe, and never turns certificate verification off for its verdict.

## What is checked

- **Known TCP endpoints, hourly.** The set is: ports the operator added, and non-loopback TCP listeners
  reported by the agent, each on the server's registered addresses (a wildcard listener on `0.0.0.0` is checked
  on the IPv4 addresses, on `::` on the IPv6 ones, either on registered domains). A listener that disappears
  disables its candidate; the history stays. **Other ports are not scanned.** A port that is not in the list is
  not "closed", it is not looked at. A discovery scan of unknown ports exists but is **off** until a server is opted in (below).
- **TLS endpoints, daily.** Only endpoints the operator adds. Not every port 443 is HTTPS, so nothing is guessed.
  The handshake sends the SNI (the domain, or the one you give for an IP); the chain is verified against the
  system trust store and the name is checked. For an untrusted (for example self-signed) certificate the dates
  and fingerprint are still recorded. An address with no SNI is not name-checked, and the screen says so.
- **Only registered addresses.** A target must be an IP or domain registered on that server, and must resolve
  to public addresses. Loopback, private, link-local and metadata addresses are refused at dial time, on the
  address actually connected to. There is no "check any host".
- **Manual check.** "Проверить сейчас" makes a server's endpoints due; one request per kind every 30 seconds.

## Results

| TCP result | Meaning |
|---|---|
| `reachable` | A connection completed (nothing was sent). |
| `refused` | The address answered with a refusal. |
| `timeout` | No answer in 5 seconds. **Not** "closed": a filter, a slow host or a lost packet look the same. |
| `filtered_or_unknown` | No route or the network refused. Inconclusive. |
| `error` | Not checked: the address is not allowed, or the name did not resolve. |

TLS verdicts: `ok`, `expired`, `untrusted`, `hostname_mismatch`, `invalid`, `handshake_error` (not TLS, or the
handshake failed), `unreachable`, `error`. An expired certificate is `expired` even if it is also self-signed:
the dates are a fact whether or not the chain is trusted.

## Journal events

Events are written when something changes, never on each check.

- `port.public_reachable`: an endpoint that did not answer now does. **Critical** if the port was not marked
  expected, info if it was. The first observation of an endpoint is a baseline and produces nothing.
- `port.public_lost`: an endpoint that answered no longer does; the event says whether that is conclusive (a
  refusal) or not (a timeout).
- `tls.expiry_threshold`: once each at 30, 14, 7 and 3 days left. A renewal starts the thresholds over.
- `tls.expired`, `tls.validation_error`, `tls.validation_recovered`, `tls.renewed`, `tls.fingerprint_changed`.
  Problems are reported on the first look as well: a certificate with five days left is worth knowing at once.
  A different certificate that outlasts the old one is a rotation (`tls.renewed`, info), not an alarm.

Notifications through the existing alerts page are a later stage: alerts are panel-scoped and a manually
created server may have no panel.

## Finding endpoints nobody listed

Two mechanisms, both bounded, neither a general scanner.

**TLS endpoints found by a handshake.** Each round, a few candidates are handshaken with: a *registered
domain* on port 443, and a *known listener* (a port endpoint that answered) on a well-known TLS port (443,
8443, 9443, 4443, 7443, 2053, 2083, 2087, 2096, 993, 995, 465, 636, 853, 8883). Only a presented certificate
confirms TLS and adds an endpoint (`source: auto`, journal event `tls.discovered`); a refusal or a timeout adds
nothing. A candidate that was tried is left alone for three days. SSH, SMTP-submission and other non-TLS
ports are never handshaken with, because a handshake sent to them only fills their logs with complaints.

**The opt-in port scan.** Off by default and per server (`discovery_scan`). When on, once a day, a fixed list
of about sixty common service ports is tried on that server's registered **IP addresses** (never a domain,
never an address that is not registered), at most four at a time with a pause between attempts, from a checker
when there is one. Ports that answer and are not yet an endpoint of that server are added as
`source: discovered`, not expected, with a journal event `port.discovered` (warning). A port number the server
already has an endpoint for, under any name, is not added again. The scan is a list, not a range: it never walks
1-65535, and a port outside the list is not looked at, so "nothing found" never means "nothing open".
