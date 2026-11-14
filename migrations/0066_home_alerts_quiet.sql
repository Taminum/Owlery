-- The alerts of Proxmox at home are their own group, and it is not announced in Telegram until the owner switches it on:
-- the page and the list of alerts show them either way. Channels that exist get the group switched off now, and a new
-- channel starts with it off.
UPDATE notify_channels
   SET prefs = jsonb_set(prefs, '{off}', COALESCE(prefs->'off', '[]'::jsonb) || '["home"]'::jsonb)
 WHERE NOT (COALESCE(prefs->'off', '[]'::jsonb) ? 'home');
ALTER TABLE notify_channels ALTER COLUMN prefs SET DEFAULT '{"off": ["home"]}'::jsonb;
