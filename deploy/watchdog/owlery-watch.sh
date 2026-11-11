#!/bin/sh
# Who watches the watcher: run this on ANOTHER machine, from cron every 2 minutes. It asks Owlery's /healthz and, when there is no
# answer for 10 minutes, writes to Telegram; it writes again when Owlery is back. It keeps its state in a small file.
#   */2 * * * * /opt/owlery-watch/owlery-watch.sh
# Settings in /opt/owlery-watch/env (chmod 600):  URL=https://<owlery>/healthz   TOKEN=<bot token>   CHAT=<chat id>
set -u
. "$(dirname "$0")/env"
state="$(dirname "$0")/state"
now=$(date +%s)
send() { curl -fsS --max-time 15 "https://api.telegram.org/bot${TOKEN}/sendMessage" --data-urlencode "chat_id=${CHAT}" --data-urlencode "text=$1" >/dev/null 2>&1 || true; }
if curl -fsS --max-time 10 -o /dev/null "$URL"; then
  if [ -f "$state" ]; then
    read -r since told < "$state"
    [ "$told" = 1 ] && send "✅ Owlery снова отвечает (молчал $(( (now - since) / 60 )) мин)."
    rm -f "$state"
  fi
  exit 0
fi
if [ ! -f "$state" ]; then echo "$now 0" > "$state"; exit 0; fi
read -r since told < "$state"
if [ "$told" = 0 ] && [ $(( now - since )) -ge 600 ]; then
  send "🔴 Owlery не отвечает уже $(( (now - since) / 60 )) мин. Проверьте сервер."
  echo "$since 1" > "$state"
fi
