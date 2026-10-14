import gzip, struct, sys, collections, ipaddress

path = sys.argv[1]
data = gzip.open(path, 'rb').read()
magic = struct.unpack('<I', data[:4])[0]
assert magic in (0xa1b2c3d4, 0xa1b23c4d), hex(magic)
snaplen, link = struct.unpack('<II', data[16:24])
SUBNET = ipaddress.ip_network('10.8.1.0/24')

off = 24
pk = 0
t0 = t1 = None
# flows keyed by (client, proto, dst, dport)
flows = collections.defaultdict(lambda: {'up': 0, 'down': 0, 'pk': 0, 'name': None, 'how': None, 'syn': False})
dns_map = collections.defaultdict(dict)  # client -> ip -> (name, ts)
dns_q = collections.Counter()
dns_servers = collections.Counter()
per_client = collections.defaultdict(lambda: collections.Counter())
sni_seen = 0
sni_parse_fail = 0
tls_first = 0
quic_bytes = 0
total_bytes = 0
ipv6_pk = 0


def parse_name(buf, i):
    labels = []
    jumped = False
    ret = None
    for _ in range(60):
        if i >= len(buf):
            return None, i
        n = buf[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(buf):
                return None, i
            ptr = ((n & 0x3F) << 8) | buf[i + 1]
            if ret is None:
                ret = i + 2
            i = ptr
            jumped = True
            continue
        labels.append(buf[i + 1:i + 1 + n].decode('ascii', 'replace'))
        i += 1 + n
    return '.'.join(labels), (ret if ret is not None else i)


def parse_dns(payload, client, ts, is_response):
    if len(payload) < 12:
        return
    qd, an = struct.unpack('>HH', payload[4:8])
    i = 12
    qname = None
    for _ in range(qd):
        name, i = parse_name(payload, i)
        if name is None:
            return
        qname = name
        i += 4
    if not is_response:
        dns_q[client] += 1
        return
    for _ in range(an):
        name, i = parse_name(payload, i)
        if name is None or i + 10 > len(payload):
            return
        rtype, _cls, _ttl, rdlen = struct.unpack('>HHIH', payload[i:i + 10])
        i += 10
        rd = payload[i:i + rdlen]
        i += rdlen
        if rtype == 1 and rdlen == 4:
            dns_map[client][str(ipaddress.IPv4Address(rd))] = (qname, ts)
        elif rtype == 28 and rdlen == 16:
            dns_map[client][str(ipaddress.IPv6Address(rd))] = (qname, ts)


def parse_sni(p):
    # p = TCP payload beginning at a TLS record
    if len(p) < 6 or p[0] != 22 or p[5] != 1:
        return None
    try:
        i = 5 + 4 + 2 + 32  # record hdr, handshake hdr, version, random
        sidlen = p[i]; i += 1 + sidlen
        cs = struct.unpack('>H', p[i:i + 2])[0]; i += 2 + cs
        cm = p[i]; i += 1 + cm
        ext_total = struct.unpack('>H', p[i:i + 2])[0]; i += 2
        end = min(len(p), i + ext_total)
        while i + 4 <= end:
            et, el = struct.unpack('>HH', p[i:i + 4]); i += 4
            if et == 0 and el >= 5:
                nl = struct.unpack('>H', p[i + 3:i + 5])[0]
                return p[i + 5:i + 5 + nl].decode('ascii', 'replace')
            i += el
    except Exception:
        return 'PARSEFAIL'
    return None


while off + 16 <= len(data):
    ts_s, ts_us, incl, orig = struct.unpack('<IIII', data[off:off + 16])
    off += 16
    pkt = data[off:off + incl]
    off += incl
    ts = ts_s + ts_us / 1e6
    t0 = ts if t0 is None else t0
    t1 = ts
    pk += 1
    if link == 101 or link == 12:
        ip = pkt
    elif link == 1:
        ip = pkt[14:]
    else:
        continue
    if not ip:
        continue
    ver = ip[0] >> 4
    if ver == 6:
        ipv6_pk += 1
        continue
    if ver != 4 or len(ip) < 20:
        continue
    ihl = (ip[0] & 15) * 4
    proto = ip[9]
    total = struct.unpack('>H', ip[2:4])[0]
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    s_in = ipaddress.ip_address(src) in SUBNET
    d_in = ipaddress.ip_address(dst) in SUBNET
    total_bytes += total
    l4 = ip[ihl:]
    sport = dport = 0
    payload = b''
    if proto in (6, 17) and len(l4) >= 8:
        sport, dport = struct.unpack('>HH', l4[:4])
        if proto == 6 and len(l4) >= 20:
            doff = (l4[12] >> 4) * 4
            payload = l4[doff:]
        else:
            payload = l4[8:]
    if s_in and not d_in:  # client -> internet
        client, remote, rport = src, dst, dport
        key = (client, proto, remote, rport)
        f = flows[key]
        f['up'] += total; f['pk'] += 1
        per_client[client]['up_bytes'] += total
        if proto == 6 and len(l4) >= 14 and (l4[13] & 2) and not (l4[13] & 16):
            f['syn'] = True
        if proto == 17 and dport == 53:
            dns_servers[remote] += 1
            parse_dns(payload, client, ts, False)
        if proto == 17 and dport == 443:
            quic_bytes += total
        if proto == 6 and dport == 80 and payload[:4] in (b'GET ', b'POST', b'HEAD', b'PUT ') and f['name'] is None:
            for line in payload.split(bytes([13, 10]))[1:20]:
                if line[:5].lower() == b'host:':
                    f['name'], f['how'] = line[5:].strip().decode('ascii', 'replace').split(':')[0], 'http'
                    break
        if proto == 6 and dport == 443 and payload and f['name'] is None:
            tls_first += 1
            n = parse_sni(payload)
            if n and n != 'PARSEFAIL':
                f['name'], f['how'] = n, 'sni'; sni_seen += 1
            elif n == 'PARSEFAIL':
                sni_parse_fail += 1
    elif d_in and not s_in:  # internet -> client
        client, remote, rport = dst, src, sport
        key = (client, proto, remote, rport)
        f = flows[key]
        f['down'] += total; f['pk'] += 1
        per_client[client]['down_bytes'] += total
        if proto == 17 and sport == 53:
            parse_dns(payload, client, ts, True)

dur = (t1 - t0) if t0 else 0
# resolve names for flows by DNS where SNI is missing
for (client, proto, remote, rport), f in flows.items():
    if f['name'] is None and remote in dns_map.get(client, {}):
        f['name'], f['how'] = dns_map[client][remote][0], 'dns'

tot_flow_bytes = sum(f['up'] + f['down'] for f in flows.values())
named = sum(f['up'] + f['down'] for f in flows.values() if f['name'])
by_sni = sum(f['up'] + f['down'] for f in flows.values() if f['how'] == 'sni')
by_dns = sum(f['up'] + f['down'] for f in flows.values() if f['how'] == 'dns')
nflows = len(flows)
nnamed = sum(1 for f in flows.values() if f['name'])
web = [f for k, f in flows.items() if k[1] in (6, 17) and k[3] in (443, 80)]
web_bytes = sum(f['up'] + f['down'] for f in web)
web_named = sum(f['up'] + f['down'] for f in web if f['name'])
dns_clients = len(dns_q)
clients = len(per_client)
print(f'capture: {pk} packets, {dur:.0f} s, snaplen {snaplen}, link {link}; ipv6 packets skipped: {ipv6_pk}')
print(f'tunnel clients seen: {clients}; clients whose DNS queries were visible: {dns_clients}')
print(f'flows: {nflows}; bytes in flows: {tot_flow_bytes/1e6:.1f} MB')
print(f'flows with a name: {nnamed}/{nflows} ({100*nnamed/max(nflows,1):.0f}%), bytes with a name: {100*named/max(tot_flow_bytes,1):.0f}%')
print(f'  named by SNI: {100*by_sni/max(tot_flow_bytes,1):.0f}% of bytes; named by DNS answer: {100*by_dns/max(tot_flow_bytes,1):.0f}% of bytes')
print(f'web (443/80) flows: {len(web)}, bytes share {100*web_bytes/max(tot_flow_bytes,1):.0f}% of all; of those bytes named: {100*web_named/max(web_bytes,1):.0f}%')
print(f'QUIC (udp/443) share of all bytes: {100*quic_bytes/max(total_bytes,1):.0f}%  (cannot be named without decrypting the first packet)')
print(f'TLS ClientHello seen: {tls_first}, with SNI: {sni_seen}, parse failures: {sni_parse_fail}')
print(f'DNS servers used by clients (distinct): {len(dns_servers)}; DNS packets to port 53: {sum(dns_servers.values())}')
dot = sum(1 for k in flows if k[1] == 6 and k[3] == 853)
print(f'DNS-over-TLS (tcp/853) flows: {dot}')
print('per tunnel address: up/down MB, dns queries seen, flows named share')
for c, v in sorted(per_client.items(), key=lambda kv: -(kv[1]['up_bytes'] + kv[1]['down_bytes'])):
    cf = [f for k, f in flows.items() if k[0] == c]
    cb = sum(f['up'] + f['down'] for f in cf)
    cn = sum(f['up'] + f['down'] for f in cf if f['name'])
    print(f'  {c}: up {v["up_bytes"]/1e6:.1f} / down {v["down_bytes"]/1e6:.1f} MB, dns queries {dns_q.get(c,0)}, named {100*cn/max(cb,1):.0f}% of its bytes')
# accuracy: for flows named by both SNI and DNS, how often do they agree on the registrable-ish suffix
agree = disagree = 0
for (client, proto, remote, rport), f in flows.items():
    if f['how'] == 'sni' and remote in dns_map.get(client, {}):
        a = f['name'].lower().split('.')[-2:]
        b = dns_map[client][remote][0].lower().split('.')[-2:]
        if a == b:
            agree += 1
        else:
            disagree += 1
print(f'cross-check on flows with both SNI and DNS: agree {agree}, differ {disagree} (differing is normal for CDNs: DNS names a CNAME chain, SNI names the site)')

new = {k: f for k, f in flows.items() if f['syn']}
old = {k: f for k, f in flows.items() if k[1] == 6 and not f['syn']}
nb = sum(f['up'] + f['down'] for f in new.values()); nn = sum(f['up'] + f['down'] for f in new.values() if f['name'])
ob = sum(f['up'] + f['down'] for f in old.values())
print('--- only TCP flows that START inside the window (handshake visible) ---')
print(f'new TCP flows: {len(new)}; named: {sum(1 for f in new.values() if f["name"])}/{len(new)} ({100*sum(1 for f in new.values() if f["name"])/max(len(new),1):.0f}%) ; bytes named: {100*nn/max(nb,1):.0f}%')
print(f'TCP flows that began BEFORE the window (no handshake to read): {len(old)}, carrying {100*ob/max(tot_flow_bytes,1):.0f}% of all bytes')
nonamed = [k for k,f in new.items() if not f['name']]
import collections as C
print('new flows with no name, by destination port:', dict(C.Counter(k[3] for k in nonamed).most_common(4)))
