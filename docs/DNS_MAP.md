# DNS Map

DNS Map is a tab of **Network Intel** (`/intel?view=dns`). It collects the DNS records of a domain that can be
observed from outside, draws how they link, and keeps a history of what changed. It is the owner's, like the rest
of Network Intel: it makes the server send DNS queries into the world.

## What it is, and what it is not

**It is not the zone.** Ordinary DNS queries cannot list every name in a zone, and RemnaScope does not try to
(no zone transfer, no guessing of subdomains). A map holds the *records it was able to observe*, for a set of
names it knows about, and every screen says so ("известные имена, а не вся зона"). A name that is not in the map
is not looked at, which is different from not existing.

Where the names come from (each name carries its source):

| Source | Meaning |
|---|---|
| `apex`, `www` | The domain itself and `www.` under it. |
| `manual_name` | Names the owner added; only names inside the domain are accepted. |
| `existing_intel` | Names Network Intel found in public certificates (Certificate Transparency). Off by default, switched on per map. It finds only names that had a certificate. |
| `cname_target` | A name a CNAME pointed to, inside the domain. |

## What is asked

- For the **apex**: `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `CAA`, `DS`, `DNSKEY`, and `TXT` of `_dmarc.<apex>`.
- For every other name: `A` and `AAAA`. A CNAME is read from the chain in the answer.
- Limits: at most 60 names per run, 6 questions at a time, a timeout per question, a cap on answers. A run never
  follows names out of the domain.

Who is asked: **two public recursive resolvers** (1.1.1.1 and 8.8.8.8), because the server's own resolver address
is not known from inside a container, and a fixed pair lets every fact say who answered. For the apex the
**authoritative servers** of the zone are asked directly as well (at most 4, only if their address is public).

## How a result is judged

Each question is put to both resolvers, and once more if they disagree.

| Outcome | Meaning |
|---|---|
| `answer` | There is a record. |
| `nodata` | The name exists, no record of that type. |
| `nxdomain` | The name does not exist. |
| `servfail`, `refused`, `timeout`, `error` | The server did not give a usable answer. This says nothing about the record. |

A record set is **confirmed** only when both resolvers gave the same complete answer. Only a confirmed record set
can move what the map knows:

- a timeout, a server failure, a refusal, one resolver's word, or a disagreement is kept as "last observed" with
  both resolvers' views, and **never** adds or removes a record;
- a record is called gone ("больше не наблюдается") only by a confirmed `nodata` or `nxdomain`, and it is marked,
  not erased;
- the first run is a **baseline**: it explains nothing.

## DNSSEC and mail policy

There is no validator. DNSSEC status is always **not checked**: `DS` and `DNSKEY` are shown as records that were
found, and the AD bit of a resolver is not treated as validation. SPF and DMARC are *recognised* (a TXT that starts
`v=spf1`, a TXT at `_dmarc` that starts `v=DMARC1`) so that a change in them is called what it is. A record found
is not called correct, and DKIM is not looked for (its selectors cannot be listed).

## History and alerts

Changes are recorded as `dns.record_added`, `dns.record_removed`, `dns.value_changed`, `dns.mx_changed`,
`dns.ns_changed`, `dns.spf_changed`, `dns.dmarc_changed`, and for the check itself `dns.check_failed` and
`dns.check_recovered`. A TTL change alone is not a change.

Record sets that change back and forth (CDN, round-robin, propagation, geo-balancing) are marked **volatile** after
three changes in a week: they stay in the history and never raise an alert.

Two kinds of alert join the alerts page, both the owner's and attached to no panel:

- `dns_check_failed`: the last run could not settle even SOA, NS and A of the apex. The data it had is kept.
- `dns_change`: an important confirmed change (NS, MX, SPF, DMARC, a record that vanished, a changed single value)
  in the last day. Address records being added is part of normal life and is not an alert.

## Schedule and retention

A map is checked every 24 hours by default (6 hours to 7 days), with 5% jitter, and on request ("Проверить
сейчас", at most once a minute per map). A run is carried out by a worker, never inside a request, and is a
database row from its start; a run left unfinished by a restart is closed as `failed (interrupted)`.

Changes and run records are kept **180 days**, purged hourly in batches. This is separate from Security's
retention and does not touch the audit log, the maps themselves or the current record sets.

## Not in this version

A DNS provider API and zone-file import (they are what would make "full zone" true), DNSSEC validation, a full
SPF/DMARC evaluator, DKIM selector discovery, per-resolver configuration in the UI.
