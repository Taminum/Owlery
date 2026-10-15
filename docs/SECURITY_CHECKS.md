# External checks: public ports and TLS certificates

RemnaScope checks a VPS from the outside: whether known TCP ports answer, and what certificate a TLS endpoint
presents. This is separate from the security agent, which reads the host from the inside.

## Where the check runs from

From the **RemnaScope server itself** (vantage `api_server`). That is **not an independent point of view**:
if the API runs on the VPS being checked, a result says the port answers *from that machine*, not that it is
reachable from the internet. Every result carries the vantage and the UI says so. A checker outside the
checked servers can be added later; until then, treat "reachable" as "reachable from the API host".

## What is checked

- **Known TCP endpoints, hourly.** The set is: ports the operator added, and non-loopback TCP listeners
  reported by the agent, each on the server's registered addresses (a wildcard listener on `0.0.0.0` is checked
  on the IPv4 addresses, on `::` on the IPv6 ones, either on registered domains). A listener that disappears
  disables its candidate; the history stays. **Other ports are not scanned.** A port that is not in the list is
  not "closed", it is not looked at. A discovery scan of unknown ports is not implemented and is off.
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
