-- Preserve the previous Telegram behavior when splitting new clients out of Security.
UPDATE notify_channels
   SET prefs = jsonb_set(prefs, '{off}', (prefs->'off') || '["lan_clients"]'::jsonb)
 WHERE (prefs->'off') ? 'security'
   AND NOT ((prefs->'off') ? 'lan_clients');
