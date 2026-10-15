# Kawaii Mode

An optional decorative look and a mascot (Ember). **Off by default**, remembered in this browser only
(`localStorage` key `remnascope.kawaii`), switched in Settings → Оформление. Turning it off puts the standard
look back exactly: the theme is an attribute on `<html>` and nothing else changes.

## What it changes

- **Themes** (`kawaii_dark`, `sakura_light`, `neko_terminal`) override only the surface, line, text and accent
  colours. The status colours keep their meaning; the light theme darkens them for contrast.
- **The mascot** sits in the bottom right (a compact one on phones), never over the page's own controls: it is a
  small fixed element, and a click opens a four-item menu (tease, hide, switch off, settings).
- **Reactions** come from what the application already has, polled once a minute: a new alert (`alert`,
  `concerned` for certificates, `curious` for DNS changes), all alerts closed (`celebrate`) and a new Fail2ban ban
  (`smug`, polled every two minutes). What was open when the page loaded is never announced.
- **Quiet by design**: at most one reaction a minute and a half, the same mood at most every ten minutes, an alert
  may follow sooner, nothing while typing in a form, nothing when the tab is hidden.
- **The item storm** is a joke scene, started from the menu ("Подразнить"), with its own switch. It is skipped
  entirely with animations off or reduced motion.

## Switches

Mode, theme, mascot, comments, animations, item storm, "less motion" (the system preference is honoured too).
With less motion the mascot is a still picture and the lines stay.

## Assets

`apps/web/public/ember/` is produced by `python tools/ember-web-pack.py` from `assets/ember/pilot-v2`
(15 atlases converted to WebP with a lossless alpha channel, about 5.6 MB in all, fetched only when the mode is on).
The source package and its notes stay under `assets/ember` and are not part of the web image.
