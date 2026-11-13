-- The Linux set leaned on things the panel already watches (containers, memory, processor, failed services, Fail2ban, time). Those
-- go, and network commands take their place.
DELETE FROM command_templates WHERE os = 'linux' AND name IN ('Контейнеры', 'Память', 'Кто грузит процессор', 'Упавшие службы', 'Fail2ban: кто забанен', 'Время');

INSERT INTO command_templates (os, name, command, note, danger) VALUES
 ('linux', 'Внешний адрес', $$curl -s https://ifconfig.me; echo$$, 'С какого адреса машина выходит в интернет', false),
 ('linux', 'Адреса и интерфейсы', 'ip -br addr', '', false),
 ('linux', 'Маршруты', $$ip route
ip -6 route$$, 'Куда уходит трафик, шлюз по умолчанию', false),
 ('linux', 'Пинг до интернета', 'ping -c 4 1.1.1.1', 'Есть ли связь по адресу, без DNS', false),
 ('linux', 'Пинг по имени', 'ping -c 4 google.com', 'Если адрес пингуется, а имя нет, виноват DNS', false),
 ('linux', 'DNS: что настроено', $$resolvectl status 2>/dev/null | head -25 || cat /etc/resolv.conf$$, '', false),
 ('linux', 'DNS: разрешить имя', 'getent hosts google.com', '', false),
 ('linux', 'Трассировка', $$traceroute -n 1.1.1.1 || tracepath -n 1.1.1.1$$, 'Где по пути пропадают пакеты', false),
 ('linux', 'Соединения: сводка', 'ss -s', 'Сколько соединений и в каких состояниях', false),
 ('linux', 'Кто подключён сейчас', $$ss -tn state established | awk 'NR>1{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -15$$, 'Внешние адреса с наибольшим числом соединений', false),
 ('linux', 'Трафик по интерфейсам', 'ip -s link', 'Счётчики пакетов, ошибок и потерь', false),
 ('linux', 'Туннели WireGuard и AmneziaWG', $$wg show 2>/dev/null; awg show 2>/dev/null$$, 'Когда в последний раз был обмен с каждым узлом', false),
 ('linux', 'Правила файрвола', $$nft list ruleset 2>/dev/null | head -80 || iptables -S$$, '', false),
 ('linux', 'NAT', 'iptables -t nat -S | head -40', 'Подмена адресов и проброс портов', false);
