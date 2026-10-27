-- Owlery 0013: two more categories, found missing by the first automatic-classification dry run
-- (DNS resolvers and VPN providers had no fitting home and fell into "Поиск и сервисы").
-- Built-in rules only; custom rules and the owner's own domains are not touched.

INSERT INTO service_rules (rule_version, pattern, service, confidence, category) VALUES
 -- VPN and privacy
 (1,'mullvad.net','Mullvad','high','VPN и приватность'),(1,'protonvpn.com','Proton VPN','high','VPN и приватность'),
 (1,'nordvpn.com','NordVPN','high','VPN и приватность'),(1,'nordcdn.com','NordVPN','medium','VPN и приватность'),
 (1,'expressvpn.com','ExpressVPN','high','VPN и приватность'),(1,'surfshark.com','Surfshark','high','VPN и приватность'),
 (1,'windscribe.com','Windscribe','high','VPN и приватность'),(1,'privateinternetaccess.com','Private Internet Access','high','VPN и приватность'),
 (1,'ipvanish.com','IPVanish','high','VPN и приватность'),(1,'cyberghostvpn.com','CyberGhost','high','VPN и приватность'),
 (1,'tunnelbear.com','TunnelBear','high','VPN и приватность'),(1,'hide.me','hide.me','high','VPN и приватность'),
 (1,'adguard-vpn.com','AdGuard VPN','high','VPN и приватность'),(1,'amnezia.org','Amnezia','high','VPN и приватность'),
 (1,'wireguard.com','WireGuard','high','VPN и приватность'),(1,'openvpn.net','OpenVPN','high','VPN и приватность'),
 (1,'getoutline.org','Outline','high','VPN и приватность'),(1,'torproject.org','Tor','high','VPN и приватность'),
 (1,'signal.org','Signal','high','Мессенджеры'),
 -- DNS resolvers and network tools
 (1,'dns.google','Google Public DNS','high','DNS и сеть'),(1,'quad9.net','Quad9','high','DNS и сеть'),
 (1,'nextdns.io','NextDNS','high','DNS и сеть'),(1,'adguard-dns.com','AdGuard DNS','high','DNS и сеть'),
 (1,'opendns.com','OpenDNS','high','DNS и сеть'),(1,'one.one.one.one','Cloudflare DNS','high','DNS и сеть'),
 (1,'controld.com','Control D','high','DNS и сеть'),(1,'dns.sb','DNS.SB','high','DNS и сеть'),
 (1,'dnsleaktest.com','DNS leak test','high','DNS и сеть'),(1,'bash.ws','DNS leak test','medium','DNS и сеть'),
 (1,'cloudflare-dns.com','Cloudflare','high','DNS и сеть'),(1,'dnscrypt.info','DNSCrypt','high','DNS и сеть'),
 (1,'ntp.org','NTP','high','DNS и сеть'),(1,'pool.ntp.org','NTP','high','DNS и сеть'),
 (1,'fast.com','Fast.com','high','Инструменты и знания'),(1,'speedtest.net','Speedtest','high','Инструменты и знания')
ON CONFLICT (rule_version, pattern) DO UPDATE SET category = EXCLUDED.category;
