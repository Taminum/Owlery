-- RemnaScope 0007: sites and categories.
--
-- site = the registrable domain of a destination host (computed by the application with the
-- public suffix list and stored, so aggregation does not need it). Categories hang on the same
-- domain rules as services. Classification is by DOMAIN only; an IP is never given a category.

ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS category text;
ALTER TABLE connection_events ADD COLUMN IF NOT EXISTS site text;
ALTER TABLE device_connections ADD COLUMN IF NOT EXISTS site text;
CREATE INDEX IF NOT EXISTS connection_events_site_ts ON connection_events (panel_id, site, ts DESC) WHERE site IS NOT NULL;
CREATE INDEX IF NOT EXISTS device_connections_site ON device_connections (panel_id, site, started_at DESC) WHERE site IS NOT NULL;

-- Categories for the services that already have rules.
UPDATE service_rules SET category = v.category FROM (VALUES
 ('Google','Поиск и сервисы'),('YouTube','Видео и стриминг'),('Telegram','Мессенджеры'),('Apple','Системные и обновления'),
 ('Cloudflare','CDN и инфраструктура'),('Microsoft','Системные и обновления'),('Meta','Соцсети'),('WhatsApp','Мессенджеры'),
 ('Netflix','Видео и стриминг'),('Spotify','Музыка'),('TikTok','Соцсети'),('X (Twitter)','Соцсети'),('Discord','Мессенджеры'),
 ('GitHub','Разработка'),('Amazon','Магазины'),('Amazon cloud','CDN и инфраструктура'),('Steam','Игры'),('Twitch','Видео и стриминг'),
 ('Yandex','Поиск и сервисы'),('VK','Соцсети'),('OpenAI','ИИ'),('Anthropic','ИИ'),('PlayStation','Игры'),('Xbox','Игры'),
 ('Speedtest','Инструменты и знания'),('Wikipedia','Инструменты и знания'),('Reddit','Соцсети'),
 ('CDN (Akamai)','CDN и инфраструктура'),('CDN (Fastly)','CDN и инфраструктура'),('RuTube','Видео и стриминг'),
 ('Одноклассники','Соцсети'),('Сбер','Банки и госуслуги'),('Госуслуги','Банки и госуслуги'),
 ('Авито','Магазины'),('Wildberries','Магазины'),('Ozon','Магазины')
) AS v(service, category) WHERE service_rules.service = v.service;

-- More well-known sites. Pattern matches the domain itself and its subdomains.
INSERT INTO service_rules (rule_version, pattern, service, confidence, category) VALUES
 -- video and streaming
 (1,'vimeo.com','Vimeo','high','Видео и стриминг'),(1,'dailymotion.com','Dailymotion','high','Видео и стриминг'),
 (1,'kinopoisk.ru','Кинопоиск','high','Видео и стриминг'),(1,'ivi.ru','ivi','high','Видео и стриминг'),
 (1,'okko.tv','Okko','high','Видео и стриминг'),(1,'hbomax.com','Max','high','Видео и стриминг'),(1,'max.com','Max','medium','Видео и стриминг'),
 (1,'disneyplus.com','Disney+','high','Видео и стриминг'),(1,'bamgrid.com','Disney+','high','Видео и стриминг'),
 (1,'hulu.com','Hulu','high','Видео и стриминг'),(1,'crunchyroll.com','Crunchyroll','high','Видео и стриминг'),
 (1,'kick.com','Kick','high','Видео и стриминг'),(1,'bilibili.com','Bilibili','high','Видео и стриминг'),
 (1,'hdrezka.ag','HDRezka','high','Видео и стриминг'),(1,'rezka.ag','HDRezka','high','Видео и стриминг'),
 (1,'animego.org','AnimeGO','high','Аниме и арт'),(1,'shikimori.one','Shikimori','high','Аниме и арт'),
 (1,'myanimelist.net','MyAnimeList','high','Аниме и арт'),(1,'anilist.co','AniList','high','Аниме и арт'),
 -- social
 (1,'linkedin.com','LinkedIn','high','Соцсети'),(1,'pinterest.com','Pinterest','high','Соцсети'),(1,'pinimg.com','Pinterest','high','Соцсети'),
 (1,'tumblr.com','Tumblr','high','Соцсети'),(1,'snapchat.com','Snapchat','high','Соцсети'),(1,'threads.net','Threads','high','Соцсети'),
 (1,'bsky.app','Bluesky','high','Соцсети'),(1,'mastodon.social','Mastodon','high','Соцсети'),(1,'twitter.com','X (Twitter)','high','Соцсети'),
 (1,'pikabu.ru','Пикабу','high','Соцсети'),(1,'habr.com','Хабр','high','Новости и медиа'),(1,'dzen.ru','Дзен','high','Новости и медиа'),
 (1,'quora.com','Quora','high','Соцсети'),(1,'medium.com','Medium','high','Новости и медиа'),(1,'vc.ru','vc.ru','high','Новости и медиа'),
 -- messengers
 (1,'signal.org','Signal','high','Мессенджеры'),(1,'viber.com','Viber','high','Мессенджеры'),(1,'line.me','LINE','high','Мессенджеры'),
 (1,'zoom.us','Zoom','high','Мессенджеры'),(1,'slack.com','Slack','high','Мессенджеры'),(1,'skype.com','Skype','high','Мессенджеры'),
 (1,'max.ru','MAX','medium','Мессенджеры'),
 -- music
 (1,'music.yandex.ru','Яндекс Музыка','high','Музыка'),(1,'soundcloud.com','SoundCloud','high','Музыка'),(1,'deezer.com','Deezer','high','Музыка'),
 (1,'tidal.com','Tidal','high','Музыка'),(1,'last.fm','Last.fm','high','Музыка'),(1,'bandcamp.com','Bandcamp','high','Музыка'),
 (1,'music.apple.com','Apple Music','high','Музыка'),
 -- search and services
 (1,'duckduckgo.com','DuckDuckGo','high','Поиск и сервисы'),(1,'yahoo.com','Yahoo','high','Поиск и сервисы'),
 (1,'baidu.com','Baidu','high','Поиск и сервисы'),(1,'rambler.ru','Rambler','high','Поиск и сервисы'),
 (1,'proton.me','Proton','high','Поиск и сервисы'),(1,'protonmail.com','Proton','high','Поиск и сервисы'),
 (1,'dropbox.com','Dropbox','high','Поиск и сервисы'),(1,'notion.so','Notion','high','Поиск и сервисы'),
 (1,'2gis.ru','2ГИС','high','Поиск и сервисы'),(1,'2gis.com','2ГИС','high','Поиск и сервисы'),
 (1,'ipify.org','Проверка IP','medium','Инструменты и знания'),(1,'2ip.ru','2ip','high','Инструменты и знания'),(1,'2ip.io','2ip','high','Инструменты и знания'),
 -- AI
 (1,'gemini.google.com','Gemini','high','ИИ'),(1,'perplexity.ai','Perplexity','high','ИИ'),(1,'huggingface.co','Hugging Face','high','ИИ'),
 (1,'midjourney.com','Midjourney','high','ИИ'),(1,'x.ai','xAI','high','ИИ'),(1,'mistral.ai','Mistral','high','ИИ'),
 (1,'character.ai','Character.AI','high','ИИ'),(1,'deepseek.com','DeepSeek','high','ИИ'),(1,'civitai.com','Civitai','high','ИИ'),
 (1,'stability.ai','Stability AI','high','ИИ'),(1,'openrouter.ai','OpenRouter','high','ИИ'),(1,'cursor.com','Cursor','high','ИИ'),
 -- development and cloud
 (1,'gitlab.com','GitLab','high','Разработка'),(1,'bitbucket.org','Bitbucket','high','Разработка'),
 (1,'stackoverflow.com','Stack Overflow','high','Разработка'),(1,'stackexchange.com','Stack Overflow','high','Разработка'),
 (1,'npmjs.com','npm','high','Разработка'),(1,'npmjs.org','npm','high','Разработка'),(1,'pypi.org','PyPI','high','Разработка'),
 (1,'pythonhosted.org','PyPI','high','Разработка'),(1,'docker.com','Docker','high','Разработка'),(1,'docker.io','Docker','high','Разработка'),
 (1,'golang.org','Go','high','Разработка'),(1,'go.dev','Go','high','Разработка'),(1,'rust-lang.org','Rust','high','Разработка'),
 (1,'crates.io','Rust','high','Разработка'),(1,'jetbrains.com','JetBrains','high','Разработка'),(1,'vercel.com','Vercel','high','Разработка'),
 (1,'netlify.app','Netlify','high','Разработка'),(1,'visualstudio.com','Visual Studio','high','Разработка'),
 (1,'digitalocean.com','DigitalOcean','high','CDN и инфраструктура'),(1,'hetzner.com','Hetzner','high','CDN и инфраструктура'),
 (1,'cloudflare.net','Cloudflare','high','CDN и инфраструктура'),(1,'jsdelivr.net','jsDelivr','medium','CDN и инфраструктура'),
 (1,'unpkg.com','unpkg','medium','CDN и инфраструктура'),(1,'cdnjs.com','cdnjs','medium','CDN и инфраструктура'),
 (1,'googleusercontent.com','Google','high','CDN и инфраструктура'),(1,'workers.dev','Cloudflare Workers','medium','CDN и инфраструктура'),
 (1,'pages.dev','Cloudflare Pages','medium','CDN и инфраструктура'),(1,'azure.com','Azure','high','CDN и инфраструктура'),
 (1,'tailscale.com','Tailscale','high','CDN и инфраструктура'),(1,'tailscale.io','Tailscale','high','CDN и инфраструктура'),
 -- games
 (1,'epicgames.com','Epic Games','high','Игры'),(1,'unrealengine.com','Epic Games','high','Игры'),(1,'riotgames.com','Riot Games','high','Игры'),
 (1,'leagueoflegends.com','Riot Games','high','Игры'),(1,'valorant.com','Riot Games','high','Игры'),(1,'blizzard.com','Blizzard','high','Игры'),
 (1,'battle.net','Blizzard','high','Игры'),(1,'ea.com','EA','high','Игры'),(1,'origin.com','EA','high','Игры'),
 (1,'ubisoft.com','Ubisoft','high','Игры'),(1,'ubi.com','Ubisoft','high','Игры'),(1,'nintendo.com','Nintendo','high','Игры'),
 (1,'nintendo.net','Nintendo','high','Игры'),(1,'roblox.com','Roblox','high','Игры'),(1,'rbxcdn.com','Roblox','high','Игры'),
 (1,'minecraft.net','Minecraft','high','Игры'),(1,'mojang.com','Minecraft','high','Игры'),(1,'gog.com','GOG','high','Игры'),
 (1,'itch.io','itch.io','high','Игры'),(1,'faceit.com','FACEIT','high','Игры'),(1,'hoyoverse.com','HoYoverse','high','Игры'),
 (1,'mihoyo.com','HoYoverse','high','Игры'),(1,'genshin.hoyoverse.com','Genshin Impact','high','Игры'),
 (1,'dlsite.com','DLsite','high','Игры'),(1,'vndb.org','VNDB','high','Игры'),(1,'f95zone.to','F95zone','medium','Игры'),
 -- shops
 (1,'aliexpress.com','AliExpress','high','Магазины'),(1,'aliexpress.ru','AliExpress','high','Магазины'),(1,'alicdn.com','AliExpress','high','Магазины'),
 (1,'ebay.com','eBay','high','Магазины'),(1,'etsy.com','Etsy','high','Магазины'),(1,'temu.com','Temu','high','Магазины'),
 (1,'market.yandex.ru','Яндекс Маркет','high','Магазины'),(1,'megamarket.ru','Мегамаркет','high','Магазины'),
 (1,'dns-shop.ru','DNS','high','Магазины'),(1,'citilink.ru','Ситилинк','high','Магазины'),(1,'lamoda.ru','Lamoda','high','Магазины'),
 (1,'shein.com','SHEIN','high','Магазины'),(1,'paypal.com','PayPal','high','Банки и госуслуги'),
 -- news and media
 (1,'bbc.com','BBC','high','Новости и медиа'),(1,'bbc.co.uk','BBC','high','Новости и медиа'),(1,'cnn.com','CNN','high','Новости и медиа'),
 (1,'nytimes.com','NYT','high','Новости и медиа'),(1,'theguardian.com','The Guardian','high','Новости и медиа'),
 (1,'meduza.io','Медуза','high','Новости и медиа'),(1,'lenta.ru','Лента','high','Новости и медиа'),(1,'rbc.ru','РБК','high','Новости и медиа'),
 (1,'ria.ru','РИА','high','Новости и медиа'),(1,'kommersant.ru','Коммерсантъ','high','Новости и медиа'),(1,'tvrain.ru','Дождь','high','Новости и медиа'),
 (1,'sankakucomplex.com','Sankaku Complex','high','Аниме и арт'),(1,'sankakuapi.com','Sankaku Complex','high','Аниме и арт'),
 (1,'pixiv.net','pixiv','high','Аниме и арт'),(1,'pximg.net','pixiv','high','Аниме и арт'),(1,'fanbox.cc','pixiv FANBOX','high','Аниме и арт'),
 (1,'deviantart.com','DeviantArt','high','Аниме и арт'),(1,'artstation.com','ArtStation','high','Аниме и арт'),
 (1,'danbooru.donmai.us','Danbooru','high','Аниме и арт'),(1,'donmai.us','Danbooru','high','Аниме и арт'),
 (1,'booru.org','Booru','medium','Аниме и арт'),(1,'zerochan.net','Zerochan','high','Аниме и арт'),
 (1,'wallhaven.cc','Wallhaven','high','Аниме и арт'),(1,'behance.net','Behance','high','Аниме и арт'),
 (1,'mangadex.org','MangaDex','high','Аниме и арт'),(1,'nyaa.si','Nyaa','high','Аниме и арт'),
 -- adult
 (1,'pornhub.com','Pornhub','high','18+'),(1,'phncdn.com','Pornhub','high','18+'),(1,'xvideos.com','XVideos','high','18+'),
 (1,'xnxx.com','XNXX','high','18+'),(1,'xhamster.com','xHamster','high','18+'),(1,'redtube.com','RedTube','high','18+'),
 (1,'youporn.com','YouPorn','high','18+'),(1,'spankbang.com','SpankBang','high','18+'),(1,'eporner.com','Eporner','high','18+'),
 (1,'onlyfans.com','OnlyFans','high','18+'),(1,'fansly.com','Fansly','high','18+'),(1,'chaturbate.com','Chaturbate','high','18+'),
 (1,'stripchat.com','Stripchat','high','18+'),(1,'nhentai.net','nhentai','high','18+'),(1,'e-hentai.org','E-Hentai','high','18+'),
 (1,'exhentai.org','ExHentai','high','18+'),(1,'rule34.xxx','Rule34','high','18+'),(1,'gelbooru.com','Gelbooru','high','18+'),
 (1,'hanime.tv','Hanime','high','18+'),(1,'hentaihaven.xxx','Hentai Haven','high','18+'),(1,'fakku.net','FAKKU','high','18+'),
 (1,'e621.net','e621','high','18+'),(1,'rule34.paheal.net','Rule34','high','18+'),
 -- banks, government, payments
 (1,'tinkoff.ru','Т-Банк','high','Банки и госуслуги'),(1,'tbank.ru','Т-Банк','high','Банки и госуслуги'),
 (1,'vtb.ru','ВТБ','high','Банки и госуслуги'),(1,'alfabank.ru','Альфа-Банк','high','Банки и госуслуги'),
 (1,'nalog.gov.ru','ФНС','high','Банки и госуслуги'),(1,'mos.ru','Москва','high','Банки и госуслуги'),
 (1,'visa.com','Visa','high','Банки и госуслуги'),(1,'mastercard.com','Mastercard','high','Банки и госуслуги'),
 (1,'wise.com','Wise','high','Банки и госуслуги'),(1,'binance.com','Binance','high','Банки и госуслуги'),
 -- system, updates, downloads
 (1,'windowsupdate.com','Windows Update','high','Системные и обновления'),(1,'delivery.mp.microsoft.com','Windows Update','high','Системные и обновления'),
 (1,'ubuntu.com','Ubuntu','high','Системные и обновления'),(1,'debian.org','Debian','high','Системные и обновления'),
 (1,'archlinux.org','Arch Linux','high','Системные и обновления'),(1,'mozilla.org','Mozilla','high','Системные и обновления'),
 (1,'mozilla.com','Mozilla','high','Системные и обновления'),(1,'mozilla.net','Mozilla','high','Системные и обновления'),
 (1,'firefox.com','Mozilla','high','Системные и обновления'),(1,'googleapis.cn','Google','medium','Системные и обновления'),
 (1,'android.com','Android','high','Системные и обновления'),(1,'chrome.com','Chrome','high','Системные и обновления'),
 (1,'samsung.com','Samsung','high','Системные и обновления'),(1,'xiaomi.com','Xiaomi','high','Системные и обновления'),
 (1,'miui.com','Xiaomi','high','Системные и обновления'),(1,'huawei.com','Huawei','high','Системные и обновления'),
 (1,'hicloud.com','Huawei','high','Системные и обновления'),(1,'ntp.org','NTP','high','Системные и обновления'),
 (1,'pool.ntp.org','NTP','high','Системные и обновления'),(1,'letsencrypt.org','Let''s Encrypt','high','Системные и обновления'),
 (1,'digicert.com','Сертификаты','medium','Системные и обновления'),(1,'sectigo.com','Сертификаты','medium','Системные и обновления'),
 (1,'torrent.ubuntu.com','Торренты','low','Системные и обновления'),
 -- tools and knowledge
 (1,'archive.org','Internet Archive','high','Инструменты и знания'),(1,'wikipedia.org','Wikipedia','high','Инструменты и знания'),
 (1,'fandom.com','Fandom','high','Инструменты и знания'),(1,'wikia.com','Fandom','high','Инструменты и знания'),
 (1,'deepl.com','DeepL','high','Инструменты и знания'),(1,'translate.google.com','Google Translate','high','Инструменты и знания'),
 (1,'imgur.com','Imgur','high','Инструменты и знания'),(1,'gravatar.com','Gravatar','medium','Инструменты и знания'),
 (1,'tenor.com','Tenor','medium','Инструменты и знания'),(1,'giphy.com','Giphy','medium','Инструменты и знания'),
 (1,'coursera.org','Coursera','high','Инструменты и знания'),(1,'udemy.com','Udemy','high','Инструменты и знания'),
 (1,'duolingo.com','Duolingo','high','Инструменты и знания'),(1,'steamdb.info','SteamDB','high','Игры'),
 -- ads and trackers (shown as such, not as a person's interests)
 (1,'doubleclick.net','Реклама и трекеры','medium','Реклама и трекеры'),(1,'googlesyndication.com','Реклама и трекеры','high','Реклама и трекеры'),
 (1,'googleadservices.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'adnxs.com','Реклама и трекеры','high','Реклама и трекеры'),
 (1,'criteo.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'scorecardresearch.com','Реклама и трекеры','high','Реклама и трекеры'),
 (1,'hotjar.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'mc.yandex.ru','Реклама и трекеры','high','Реклама и трекеры'),
 (1,'appsflyer.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'adjust.com','Реклама и трекеры','high','Реклама и трекеры'),
 (1,'app-measurement.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'sentry.io','Реклама и трекеры','medium','Реклама и трекеры'),
 (1,'google-analytics.com','Реклама и трекеры','high','Реклама и трекеры'),(1,'googletagmanager.com','Реклама и трекеры','high','Реклама и трекеры')
ON CONFLICT (rule_version, pattern) DO UPDATE SET category = EXCLUDED.category;

-- Rules in the first migration that did not get a category above stay uncategorised on purpose.
