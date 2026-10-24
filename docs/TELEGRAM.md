# Telegram: notifications and bot commands

RemnaScope can tell you what is wrong, and answer when you ask, through a Telegram bot of your own.
It talks to `api.telegram.org` only (outbound, no webhook, nothing to open on the server).

## Connect a bot
1. In Telegram, ask `@BotFather` for a new bot (`/newbot`) and copy the token.
2. Open your bot and press **Start** (the bot cannot write to a chat that never wrote to it).
3. In RemnaScope: **Settings → Notifications**. Paste the token, press *Find the chat*, pick yours, and connect.
   A channel is saved only after a test message really reached the chat.
4. The token and the chat id are encrypted with the master key like a panel token. The page never gets them back:
   it shows only the end of the chat id and how the last send went.

## What arrives
- **Alerts** as they open and as they close (the same ones as on the *Оповещения* page). What was already open when
  the channel was added is not announced.
- **A daily summary** at the hour you choose: the whole cluster (as `/stats`) and what happened in the last 24 hours.

## Fine tuning (per channel, the *Настроить* button)
| Setting | What it does |
|---|---|
| Groups | Switch whole groups off: agents and probes, panels, security, server resources, DDoS, AmneziaWG, DNS, subscriptions, payments. |
| Closings | Say or do not say that a problem closed. |
| Quiet hours | From–to in the channel's time zone. Only urgent alerts come in that time (DDoS, a stopped AmneziaWG container, a panel that cannot be synced, a silent agent or probe); the rest is held and comes after. An alert that closed meanwhile is never announced. |
| Reminders | Repeat an alert that is still open every 1, 3, 6, 12 or 24 hours. |
| Commands | Whether the bot answers commands in this chat. |
| Mute | Quiet for 1, 8 or 24 hours (or `/mute N`); urgent alerts still come. |

## Commands
Write them to the bot in the chat of the channel. Anyone else's message is ignored.

| Command | Answer |
|---|---|
| `/stats` | The summary of the cluster: servers online, alerts, average CPU and memory, monthly cost, every server with CPU, memory, disk, Fail2ban, the nearest certificate, AmneziaWG devices, subscriptions about to end, payments due. |
| `/servers` | Each server with CPU, memory, disk and network, connections and load. |
| `/alerts` | The open alerts and how long they have been open. |
| `/bans` | Fail2ban on each server: banned now, in total, bans in the last day. |
| `/certs` | The watched certificates, the nearest to expire first. |
| `/pay` | The payments list and what it costs a month. |
| `/awg` | AmneziaWG servers and how many devices are online. |
| `/users` | Subscriptions ending soon or near their traffic limit. |
| `/dns` | The watched domains and their last check. |
| `/mute N`, `/unmute` | Quiet for N hours (1 to 336); back to normal. |
| `/help` | The list. |

## What the bot will and will not do
- It answers from the channel's own chat only, ignores messages older than two minutes (written while the server was
  down) and what was written before it started, and takes at most twelve commands a minute.
- It reads; the one thing a command changes is the mute. It cannot ban an address or change a setting.
- Switch it off for a channel with the *Commands* checkbox; the alerts go on.
