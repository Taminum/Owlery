-- Owlery 0004: destination classification rules and traffic counter samples.

-- Authoritative counters from the panel have no up/down split for users: record the total.
ALTER TABLE traffic_samples DROP CONSTRAINT IF EXISTS traffic_samples_direction_check;
ALTER TABLE traffic_samples ADD CONSTRAINT traffic_samples_direction_check CHECK (direction IN ('up','down','total'));
CREATE INDEX IF NOT EXISTS traffic_samples_user_time ON traffic_samples (panel_id, user_id, source, observed_at DESC);
CREATE INDEX IF NOT EXISTS traffic_samples_node_time ON traffic_samples (panel_id, node_id, source, observed_at DESC);

-- A rule matches a host that equals the pattern or ends with ".pattern". Classification is by
-- DOMAIN only: an IP address is never mapped to a service by guesswork.
-- confidence: high = the domain belongs to that service; medium = shared infrastructure (CDN, cloud).
CREATE UNIQUE INDEX IF NOT EXISTS service_rules_pattern ON service_rules (rule_version, pattern);

INSERT INTO service_rules (rule_version, pattern, service, confidence) VALUES
 (1,'google.com','Google','high'),(1,'googleapis.com','Google','high'),(1,'gstatic.com','Google','high'),
 (1,'googleusercontent.com','Google','high'),(1,'gvt1.com','Google','high'),(1,'gvt2.com','Google','high'),
 (1,'ggpht.com','Google','high'),(1,'googleadservices.com','Google','high'),(1,'doubleclick.net','Google','medium'),
 (1,'google-analytics.com','Google','high'),(1,'googletagmanager.com','Google','high'),(1,'gmail.com','Google','high'),
 (1,'youtube.com','YouTube','high'),(1,'googlevideo.com','YouTube','high'),(1,'ytimg.com','YouTube','high'),(1,'youtu.be','YouTube','high'),
 (1,'telegram.org','Telegram','high'),(1,'t.me','Telegram','high'),(1,'telegram.me','Telegram','high'),(1,'tdesktop.com','Telegram','high'),
 (1,'telesco.pe','Telegram','high'),(1,'cdn-telegram.org','Telegram','high'),
 (1,'apple.com','Apple','high'),(1,'icloud.com','Apple','high'),(1,'mzstatic.com','Apple','high'),(1,'apple-dns.net','Apple','high'),
 (1,'cdn-apple.com','Apple','high'),(1,'aaplimg.com','Apple','high'),
 (1,'cloudflare.com','Cloudflare','high'),(1,'cloudflare-dns.com','Cloudflare','high'),(1,'cloudflareclient.com','Cloudflare','high'),
 (1,'cloudflarestream.com','Cloudflare','high'),
 (1,'microsoft.com','Microsoft','high'),(1,'live.com','Microsoft','high'),(1,'office.com','Microsoft','high'),(1,'office365.com','Microsoft','high'),
 (1,'windowsupdate.com','Microsoft','high'),(1,'msftconnecttest.com','Microsoft','high'),(1,'msn.com','Microsoft','high'),
 (1,'bing.com','Microsoft','high'),(1,'skype.com','Microsoft','high'),(1,'azureedge.net','Microsoft','medium'),(1,'windows.net','Microsoft','medium'),
 (1,'facebook.com','Meta','high'),(1,'fbcdn.net','Meta','high'),(1,'instagram.com','Meta','high'),(1,'cdninstagram.com','Meta','high'),
 (1,'whatsapp.com','WhatsApp','high'),(1,'whatsapp.net','WhatsApp','high'),(1,'meta.com','Meta','high'),
 (1,'netflix.com','Netflix','high'),(1,'nflxvideo.net','Netflix','high'),(1,'nflximg.net','Netflix','high'),(1,'nflxso.net','Netflix','high'),
 (1,'spotify.com','Spotify','high'),(1,'scdn.co','Spotify','high'),(1,'spotifycdn.com','Spotify','high'),
 (1,'tiktok.com','TikTok','high'),(1,'tiktokcdn.com','TikTok','high'),(1,'byteoversea.com','TikTok','high'),(1,'ibytedtos.com','TikTok','high'),
 (1,'twitter.com','X (Twitter)','high'),(1,'x.com','X (Twitter)','high'),(1,'twimg.com','X (Twitter)','high'),(1,'t.co','X (Twitter)','high'),
 (1,'discord.com','Discord','high'),(1,'discordapp.com','Discord','high'),(1,'discord.gg','Discord','high'),(1,'discordapp.net','Discord','high'),
 (1,'github.com','GitHub','high'),(1,'githubusercontent.com','GitHub','high'),(1,'githubassets.com','GitHub','high'),
 (1,'amazon.com','Amazon','high'),(1,'amazonaws.com','Amazon cloud','medium'),(1,'cloudfront.net','Amazon cloud','medium'),
 (1,'primevideo.com','Amazon','high'),(1,'media-amazon.com','Amazon','high'),
 (1,'steampowered.com','Steam','high'),(1,'steamcontent.com','Steam','high'),(1,'steamstatic.com','Steam','high'),(1,'steamcommunity.com','Steam','high'),
 (1,'twitch.tv','Twitch','high'),(1,'ttvnw.net','Twitch','high'),(1,'jtvnw.net','Twitch','high'),
 (1,'yandex.ru','Yandex','high'),(1,'yandex.net','Yandex','high'),(1,'yandex.com','Yandex','high'),(1,'ya.ru','Yandex','high'),
 (1,'yastatic.net','Yandex','high'),(1,'yandex.by','Yandex','high'),
 (1,'vk.com','VK','high'),(1,'vk-cdn.net','VK','high'),(1,'userapi.com','VK','high'),(1,'vkuser.net','VK','high'),(1,'mail.ru','VK','medium'),
 (1,'openai.com','OpenAI','high'),(1,'chatgpt.com','OpenAI','high'),(1,'oaistatic.com','OpenAI','high'),(1,'oaiusercontent.com','OpenAI','high'),
 (1,'anthropic.com','Anthropic','high'),(1,'claude.ai','Anthropic','high'),
 (1,'playstation.com','PlayStation','high'),(1,'playstation.net','PlayStation','high'),(1,'sonyentertainmentnetwork.com','PlayStation','high'),
 (1,'xboxlive.com','Xbox','high'),(1,'xbox.com','Xbox','high'),
 (1,'speedtest.net','Speedtest','high'),(1,'ookla.com','Speedtest','high'),
 (1,'wikipedia.org','Wikipedia','high'),(1,'wikimedia.org','Wikipedia','high'),
 (1,'reddit.com','Reddit','high'),(1,'redditstatic.com','Reddit','high'),(1,'redd.it','Reddit','high'),
 (1,'akamaized.net','CDN (Akamai)','medium'),(1,'akamaihd.net','CDN (Akamai)','medium'),(1,'edgekey.net','CDN (Akamai)','medium'),
 (1,'fastly.net','CDN (Fastly)','medium'),(1,'fastlylb.net','CDN (Fastly)','medium'),
 (1,'rutube.ru','RuTube','high'),(1,'ok.ru','Одноклассники','high'),(1,'sberbank.ru','Сбер','high'),(1,'sber.ru','Сбер','high'),
 (1,'gosuslugi.ru','Госуслуги','high'),(1,'avito.ru','Авито','high'),(1,'wildberries.ru','Wildberries','high'),(1,'ozon.ru','Ozon','high')
ON CONFLICT (rule_version, pattern) DO NOTHING;
