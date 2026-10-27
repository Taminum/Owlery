# Сборщик AmneziaWG на хосте (этап 1, только чтение)

Что это: второй экземпляр агента Owlery на хосте с контейнерами AmneziaWG (`awg-host`). Раз в минуту он запускает один фиксированный скрипт и отправляет результат в Owlery. В странице «AmneziaWG» появляются серверы, устройства, состояние и счётчики.

**Что он видит и отправляет:** имена контейнеров и интерфейсов, порт, **названия** параметров обфускации (без значений), публичные ключи устройств, имена клиентов, адреса в туннеле, счётчики байт, время последнего обмена ключами.
**Чего он не видит и не отправляет:** приватные ключи (сервера и клиентов), PSK, адреса и порты, с которых клиенты подключаются, содержимое трафика.
**Что он не может:** изменять что-либо. Скрипт только читает; агент не получает оболочки и Docker-сокета, ему разрешена ровно одна команда через sudo.

Контейнеры AWG, панель Amnezia и существующий агент логов **не затрагиваются**: ничего не перезапускается, новый агент ставится рядом под другим именем.

## Файлы

| Файл | Куда ставится | Зачем |
|---|---|---|
| `remnascope-awg-snapshot` | `/usr/local/sbin/` (root, 0755) | читает `awg show …` и две строки таблицы клиентов |
| `remnascope-agent-awg` | `/usr/local/bin/` (root, 0755) | тот же агент, новая сборка с режимом AmneziaWG |
| `remnascope-awg.service` | `/etc/systemd/system/` | запуск от пользователя `remnascope`, с песочницей |
| `/etc/sudoers.d/remnascope-awg` | sudoers | разрешает пользователю `remnascope` запускать только скрипт |
| `/etc/remnascope/awg.token` | токен нового агента | выдаётся в Owlery (см. шаг 1) |

## Установка одной командой

`deploy/agent/awg/install.sh` делает все шаги ниже за один проход и ничего сверх них: скачивает файлы релиза и сверяет их с `SHA256SUMS`, создаёт пользователя `remnascope`, токен, настройки помощника, правила sudo (по одному точному правилу на помощника), службу агента и по службе датчика на контейнер. Контейнеры, их конфиги и Docker он не трогает. Повторный запуск безопасен.

```bash
# токен выдаётся в Owlery (Ноды → агенты → вид «awg») и показывается один раз
curl -fsSLO https://github.com/Taminum/Owlery/releases/latest/download/remnascope-deploy-files.tar.gz
tar -xzf remnascope-deploy-files.tar.gz deploy/agent/awg/install.sh
sudo sh deploy/agent/awg/install.sh --server wss://scope.example.com/ingest/v1 --token-file ./awg.token      --endpoint-host 203.0.113.10 --managed "amnezia-awg2 amnezia-awg3"
```

Важные параметры: `--managed` перечисляет контейнеры, в которых Owlery может добавлять и отзывать устройства (без него агент только читает); `--sense` по умолчанию совпадает с ним; `--endpoint-host` попадает в клиентские конфиги. `--stage DIR` пишет всё в каталог без `systemctl` (для проверки), `--uninstall` убирает установленное. Проверка скрипта без сервера: `sh deploy/agent/awg/test/test-install.sh`.

## Срок жизни и лимит трафика устройства

Владелец может задать устройству дату, до которой оно действует, и/или лимит трафика (скачано плюс отправлено, считается с момента, когда лимит задан, с теми же поправками на перезапуски, что и остальные счётчики). Кнопка «Лимиты» есть в строке устройства на сервере, которым Owlery управляет (`MANAGED`).

- Исполняет это Owlery, а не сервер AmneziaWG: раз в минуту проверка находит устройства, у которых срок вышел или лимит исчерпан, и отправляет тот же `revoke`, что и кнопка «Отозвать». Не больше 20 за минуту; агент не на связи: попытка повторится в следующую минуту.
- **Отозванное устройство вернуть нельзя**: ключи удаляются вместе с ним, устройство надо создать заново. Окно с лимитами говорит об этом.
- В списке видно срок, расход и причину автоматического отзыва; в журнал операций и в аудит пишется `awg.auto_revoke` с причиной (`expired` или `traffic_limit`).
- Задавать и снимать лимиты может только владелец: `PUT /api/v1/awg/peers/{id}/limits` с `expires_at` и `traffic_limit_bytes` (оба можно `null`).

## Создание и удаление контейнера (помощник `remnascope-awg-container`)

Ставится только с `--container-admin`; по умолчанию его нет и правила sudo для него нет. Он создаёт контейнер в раскладке официального клиента Amnezia (`amnezia-awg*`, `/opt/amnezia/awg/awg0.conf`, сеть `amnezia-dns-net`), поэтому приложения Amnezia продолжают работать с таким сервером, а снимок, управление и датчик видят его сразу.

- `install <контейнер> <порт> <подсеть /24 в 10.0.0.0/8>`: скрипты сервера берутся из репозитория Amnezia по **закреплённому коммиту**, каждый файл сверяется с SHA-256, записанным в самом помощнике (GPL-код Amnezia в наш репозиторий не копируется). Отказывается, если контейнер, порт или подсеть уже заняты. После создания проверяет, что интерфейс `awg0` поднялся, иначе откатывает всё созданное. Добавляет контейнер в `MANAGED`, `SENSE` и `CONTAINERS` и включает датчик.
- `remove <контейнер> yes-delete-all-devices`: только для контейнера из `MANAGED` и только с этим словом подтверждения; удаляет контейнер и образ **вместе со всеми устройствами в нём** (конфиг лежит внутри контейнера).
- `export <контейнер>`: только для контейнера из `MANAGED`, который запущен; печатает `RESULT` и строки `FILE<TAB>имя<TAB>base64` для фиксированного набора файлов (`awg0.conf`, ключи сервера, `wireguard_psk.key`, `clientsTable`). Это секреты: агент отдаёт их серверу, а тот шифрует парольной фразой и не хранит.
- `restore <контейнер>`: читает такие же `FILE`-строки из stdin и создаёт контейнер с теми же ключами и параметрами. Имена и размер файлов проверяются, а `awg0.conf` пропускается через белый список ключей (`PostUp`, `PreUp`, `PostDown` отклоняются: `awg-quick` выполнил бы их как команды). Порт и подсеть берутся из самого конфига; занятые порт или подсеть отклоняются так же, как при `install`.
- Не ставит Docker и не меняет файрвол хоста.
- **Из интерфейса:** на странице «AmneziaWG» владелец видит хосты. Если на хосте установлен помощник (флаг `--container-admin` у установщика, он же задаёт `REMNASCOPE_AWG_CONTAINER` у службы агента), снимок сообщает об этом, и появляется кнопка «Установить контейнер»; у контейнеров в раскладке Amnezia есть «Удалить сервер» с вводом имени для подтверждения. Обе операции только для владельца, пишутся в аудит и не возвращают ничего секретного. Агент проверяет поля ещё раз и без `REMNASCOPE_AWG_CONTAINER` отказывает в обеих.
- Проверка на настоящем Docker: `sh deploy/agent/awg/test/test-container.sh` (создаёт и удаляет одноразовый контейнер).

## Шаги

1. **В Owlery** создать агента: Узлы → awg-host → «Агенты» → вид «awg» (имя, например, `awg-awg-host`). Токен показывается один раз.
2. **Сборка** (на этом компьютере): `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o remnascope-agent-awg ./cmd/agent`
3. **Копирование на сервер** (три файла в домашний каталог пользователя с sudo, затем установка):

```bash
# на сервере, от root; файлы лежат рядом
install -m 0755 -o root -g root remnascope-awg-snapshot /usr/local/sbin/remnascope-awg-snapshot
install -m 0755 -o root -g root remnascope-agent-awg /usr/local/bin/remnascope-agent-awg
install -m 0640 -o root -g remnascope /dev/stdin /etc/remnascope/awg.token      # вставить токен, затем Ctrl-D
printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-snapshot' > /etc/sudoers.d/remnascope-awg
chmod 0440 /etc/sudoers.d/remnascope-awg && visudo -cf /etc/sudoers.d/remnascope-awg
install -m 0644 remnascope-awg.service /etc/systemd/system/remnascope-awg.service
systemctl daemon-reload && systemctl enable --now remnascope-awg
```

4. **Проверка до включения** (без запуска службы): `sudo -u remnascope sudo -n /usr/local/sbin/remnascope-awg-snapshot | cut -c1-120`. Должны быть строки `I`, `P`, `N` и **ни одного** слова `PrivateKey` или `PresharedKey`. Если контейнеры называются иначе, поправить `CONTAINERS` в начале скрипта.
5. **Проверка после:** `systemctl status remnascope-awg` и страница «AmneziaWG» в Owlery: через минуту должны появиться устройства.

## Откат (убирает всё, что добавил сборщик)

```bash
systemctl disable --now remnascope-awg
rm -f /etc/systemd/system/remnascope-awg.service /etc/sudoers.d/remnascope-awg /usr/local/bin/remnascope-agent-awg /usr/local/sbin/remnascope-awg-snapshot /etc/remnascope/awg.token
rm -rf /var/lib/remnascope-awg
systemctl daemon-reload
```

В Owlery агент можно отозвать там же, где он создан. История счётчиков в базе остаётся.

## Проверка скрипта без сервера

`sh deploy/agent/awg/test/test.sh` запускает скрипт против подставного `docker` и проверяет, что вывод правильный и в нём нет секретов.

# Управление устройствами (этап 2)

Включается отдельно и **только для контейнеров, перечисленных в `/etc/remnascope/awg-manage.conf`**. По умолчанию выключено: без этого файла и без drop-in агент отказывает на любую команду, а в Owlery кнопок нет.

## Что умеет и чего не умеет

- **Добавить устройство** (`remnascope-awg-manage add <контейнер> <имя>`): находит свободный адрес, создаёт ключи прямо на хосте, добавляет устройство на живой интерфейс (`awg set`), дописывает блок `[Peer]` в `awg0.conf` (с комментарием `# remnascope: <имя>`), проверяет, что устройство появилось, и печатает клиентскую конфигурацию. Конфигурация содержит закрытый ключ устройства: она показывается один раз в Owlery и нигде не хранится (ни на хосте, ни в базе, ни в логах).
- **Отозвать устройство** (`... revoke <контейнер> <публичный ключ>`): убирает его с живого интерфейса и вырезает только его блок из `awg0.conf`.
- **Не умеет** ничего другого: не пересоздаёт ключи сервера, не трогает остальные устройства, не удаляет контейнеры и файлы, не принимает произвольных путей и команд. Перед каждым изменением делается копия `awg0.conf.bak.remnascope.<время>` рядом с конфигом (внутри контейнера).
- Все аргументы проверяются **в трёх местах**: в API, в агенте и в самом скрипте; контейнер должен быть в списке `MANAGED`.
- Все операции пишутся в аудит Owlery (кто, что, чем кончилось; без ключей и конфигураций).
- Старая панель Amnezia не видит устройства, добавленные Owlery, в своей таблице (мы её не правим); сами устройства работают.

## Включение

Файлы: `remnascope-awg-manage` (в `/usr/local/sbin/`, root, 0755), `awg-manage.conf` (в `/etc/remnascope/`, root, 0644), правило sudo и drop-in для службы.

```bash
install -m 0755 -o root -g root remnascope-awg-manage /usr/local/sbin/remnascope-awg-manage
printf '%s\n' 'MANAGED="amnezia-awg3"' 'ENDPOINT_HOST="203.0.113.10"' 'DNS="1.1.1.1, 1.0.0.1"' > /etc/remnascope/awg-manage.conf
chmod 0644 /etc/remnascope/awg-manage.conf
printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-manage' > /etc/sudoers.d/remnascope-awg-manage
chmod 0440 /etc/sudoers.d/remnascope-awg-manage && visudo -cf /etc/sudoers.d/remnascope-awg-manage
install -d /etc/systemd/system/remnascope-awg.service.d
printf '%s\n' '[Service]' 'Environment="REMNASCOPE_AWG_MANAGE=/usr/bin/sudo -n /usr/local/sbin/remnascope-awg-manage"' > /etc/systemd/system/remnascope-awg.service.d/manage.conf   # кавычки обязательны: иначе systemd разрежет значение по пробелам
systemctl daemon-reload && systemctl restart remnascope-awg
```

Обновлённые `remnascope-awg-snapshot` и `remnascope-agent-awg` ставятся так же, как в первой части (из этапа 1).

## Выключение и откат

```bash
rm -f /etc/systemd/system/remnascope-awg.service.d/manage.conf && systemctl daemon-reload && systemctl restart remnascope-awg   # управление выключено
rm -f /etc/sudoers.d/remnascope-awg-manage /usr/local/sbin/remnascope-awg-manage /etc/remnascope/awg-manage.conf               # и убрано совсем
```

Добавленные устройства остаются на сервере, пока их не отозвать (кнопкой «Отозвать» до выключения). Копии конфигов `awg0.conf.bak.remnascope.*` остаются внутри контейнера.

## Проверка без сервера

`bash deploy/agent/awg/test/test-manage.sh` (нужен bash) запускает скрипт против песочницы, которая изображает контейнер: проверяет добавление, отзыв, повторное использование адреса, отказы на плохие аргументы (ничего не меняется), откат при ошибке применения и то, что закрытый ключ клиента не остаётся на «сервере».

# Датчик трафика (этап 4)

Данные датчика входят в общие списки **«Сайты»** и **«Домены и сервисы»** , а в фильтре «Чей трафик» есть группа «AmneziaWG» (весь сервер или одно устройство): название сайта (когда его сказал открытый трафик), IP и порт, байты, устройство в «Кто ходил».

## Что он делает и чего не делает

- Смотрит **только заголовки пакетов** на интерфейсе `awg0` внутри контейнера. Из содержимого берёт только названия: имя сервера в TLS-рукопожатии (SNI), заголовок `Host` в обычном HTTP, ответы DNS. Пакеты и содержимое не хранит ни на хосте (на диск ничего не пишется), ни в Owlery.
- Не видит адреса страниц, пути и всё, что внутри шифрования; не даёт названий для QUIC, DoH, ECH; за Router виден один адрес на всё устройство.
- Раз в минуту отправляет сводку по потокам: устройство (адрес в туннеле), назначение, байты, название и его источник. Owlery хранит **суммы по часам** 30 дней (старше удаляется само). В списках это строки с меткой источника: данные AmneziaWG не складываются с данными узлов и роутера (это другой путь трафика, двойного счёта нет). Особенности: «соединения» по AmneziaWG это новые соединения за час (долгая загрузка, начатая раньше, даёт байты, но не соединение); «заходы» по AmneziaWG не считаются (час активности не равен заходу); в видах, суженных до человека, узла или входа, строк AmneziaWG нет, потому что они не принадлежат ни пользователю панели, ни устройству за роутером, ни входу узла.
- Запускается от root только чтобы открыть пакетный сокет в сетевом пространстве контейнера, затем **навсегда отказывается от root** (пользователь `nobody`, запрет повышать права). Живёт в узкой песочнице systemd. Если остановится, туннели не затрагиваются.
- Контейнеры AWG и панель не перезапускаются и не меняются.

## Файлы

| Файл | Куда |
|---|---|
| `remnascope-awg-sensor` (собирается из `cmd/awgsensor`) | `/usr/local/sbin/` (root, 0755) |
| `remnascope-awg-sensor-run` | `/usr/local/sbin/` (root, 0755): запускает датчик только для контейнеров из `SENSE` в `/etc/remnascope/awg-manage.conf` |
| `remnascope-awg-sensor@.service` | `/etc/systemd/system/` (шаблон: по экземпляру на контейнер) |
| drop-in агента `sensor.conf` | `/etc/systemd/system/remnascope-awg.service.d/`: каталог для сокета и переменные |

## Включение

```bash
install -m 0755 -o root -g root remnascope-awg-sensor /usr/local/sbin/remnascope-awg-sensor
install -m 0755 -o root -g root remnascope-awg-sensor-run /usr/local/sbin/remnascope-awg-sensor-run
install -m 0644 'remnascope-awg-sensor@.service' /etc/systemd/system/
# какие контейнеры наблюдать: добавить строку SENSE в настройки хоста
printf '%s\n' 'SENSE="amnezia-awg2 amnezia-awg3"' >> /etc/remnascope/awg-manage.conf
# агент слушает локальный сокет, куда датчики присылают сводки
printf '%s\n' '[Service]' 'RuntimeDirectory=remnascope-awg' 'RuntimeDirectoryMode=0750' \
  'Environment="REMNASCOPE_AWG_SENSOR_SOCKET=/run/remnascope-awg/sensor.sock"' \
  'Environment="REMNASCOPE_AWG_SENSOR_CONTAINERS=amnezia-awg2,amnezia-awg3"' > /etc/systemd/system/remnascope-awg.service.d/sensor.conf
systemctl daemon-reload && systemctl restart remnascope-awg
systemctl enable --now remnascope-awg-sensor@amnezia-awg2 remnascope-awg-sensor@amnezia-awg3
```

Проверка: `systemctl status 'remnascope-awg-sensor@*'` и блок «Куда ходят устройства» в Owlery (данные появляются через минуту-две).

## Выключение

```bash
systemctl disable --now remnascope-awg-sensor@amnezia-awg2 remnascope-awg-sensor@amnezia-awg3
rm -f /etc/systemd/system/remnascope-awg.service.d/sensor.conf /etc/systemd/system/remnascope-awg-sensor@.service /usr/local/sbin/remnascope-awg-sensor /usr/local/sbin/remnascope-awg-sensor-run
sed -i '/^SENSE=/d' /etc/remnascope/awg-manage.conf
systemctl daemon-reload && systemctl restart remnascope-awg
```

Собранные суммы в Owlery остаются и сами удаляются через 30 дней.

## Проверка без сервера

- `sh deploy/agent/awg/test/test-sensor-run.sh`: запускающий скрипт стартует датчик только для разрешённых контейнеров и только с фиксированными аргументами.
- Разбор пакетов и накопитель проверяют `go test ./internal/awgsensor` (включая фаззинг: `go test ./internal/awgsensor -fuzz FuzzParsers`).
- Проверка захвата на настоящем Linux: интерфейс в отдельном сетевом пространстве, пакеты через него, вывод датчика.
