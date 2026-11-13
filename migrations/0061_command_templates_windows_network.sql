-- The Windows set, like the Linux one, leaned on what the panel already watches (disks, memory, processor, services, uptime). Those
-- go, and network commands take their place.
DELETE FROM command_templates WHERE os = 'windows' AND name IN ('Диски', 'Память', 'Кто ест память', 'Кто грузит процессор', 'Службы, которые должны работать', 'Сколько работает');

INSERT INTO command_templates (os, name, command, note, danger) VALUES
 ('windows', 'Внешний адрес', $$Invoke-RestMethod -Uri https://api.ipify.org$$, 'С какого адреса машина выходит в интернет', false),
 ('windows', 'Адреса и адаптеры', $$Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | Format-Table -AutoSize; Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress | Format-Table -AutoSize$$, '', false),
 ('windows', 'Маршруты', $$Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 20 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -AutoSize$$, 'Куда уходит трафик, шлюз по умолчанию', false),
 ('windows', 'Пинг до интернета', 'ping -n 4 1.1.1.1', 'Есть ли связь по адресу, без DNS', false),
 ('windows', 'Пинг по имени', 'ping -n 4 google.com', 'Если адрес пингуется, а имя нет, виноват DNS', false),
 ('windows', 'DNS: что настроено', $$Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | Format-Table -AutoSize$$, '', false),
 ('windows', 'DNS: разрешить имя', 'Resolve-DnsName google.com', '', false),
 ('windows', 'Трассировка', 'tracert -d 1.1.1.1', 'Где по пути пропадают пакеты', false),
 ('windows', 'Проверка порта', 'Test-NetConnection 1.1.1.1 -Port 443', 'Заменить адрес и порт на нужные', false),
 ('windows', 'Соединения: сводка', $$Get-NetTCPConnection | Group-Object State | Select-Object Count,Name | Format-Table -AutoSize$$, 'Сколько соединений и в каких состояниях', false),
 ('windows', 'Кто подключён сейчас', $$Get-NetTCPConnection -State Established | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 15 Count,Name | Format-Table -AutoSize$$, 'Внешние адреса с наибольшим числом соединений', false),
 ('windows', 'Кто зашёл по RDP', $$Get-NetTCPConnection -LocalPort 3389 -State Established | Select-Object RemoteAddress,RemotePort | Format-Table -AutoSize$$, 'Адреса, с которых сейчас открыт удалённый стол', false),
 ('windows', 'Трафик по адаптерам', $$Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedDiscardedPackets,OutboundDiscardedPackets | Format-Table -AutoSize$$, 'Счётчики с запуска адаптера', false),
 ('windows', 'Файрвол: профили', $$Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize$$, '', false);
