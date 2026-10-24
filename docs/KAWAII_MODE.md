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
- **Touch and hover** (package v9): a click on the drawing (not on its transparent corners, checked on the alpha
  of the current picture) makes her react (`tap`) and say a line; a second click during a scene gets "busy"; resting
  the mouse on her for 0.65 s gives `curious`. The "⋯" button at her corner opens the menu.
- **Cheeky scenes**, all from the menu and never on their own, with their own switch ("Озорные сценки"): an air
  kiss (a separate heart flies from her hand), "caught flirting" (she waits, looping two poses, until she is
  clicked, then answers) and taking the hoodie off (she stays in the white top, only talks, until "Надеть худи").
- **Speech bubble**: typed out, with a tail; a click finishes it, the next closes it; screen readers get the whole
  sentence at once. Dark theme for the dark looks, paper for Sakura Light. A scene's line comes at its marker.
- Her hair is red: that is canon now, the original brief said dark.

## Switches

Mode, theme, mascot, comments, animations, item storm, cheeky scenes, "less motion" (the system preference is honoured too).
With less motion the mascot is a still picture and the lines stay.

## Assets

The artwork is **not in the repository and not in the images**. It belongs to the owner and travels as a pack:
`python tools/ember-web-pack.py --archive ember-pack.tar.gz` makes it from the private `assets/ember` (add `--basic`
to leave the cheeky scenes out). The pack is unpacked into a folder that the web container reads
(`deploy/prod/install-ember.sh`, folder `EMBER_DIR`, default `./ember`); `deploy/prod/ship.sh` does this itself when
`assets/ember` is present. Without a pack the mascot does not appear and nothing else changes; the theme and the
settings still work, and the menu offers only the scenes that the installed pack holds.

`apps/web/public/ember/` is produced by `python tools/ember-web-pack.py` from `assets/ember/pilot-v2`
(17 atlases converted to WebP with a lossless alpha channel, about 6.4 MB in all, fetched only when the mode is on; a clip waits for its atlas before it plays, and the last atlas is padded to a square).
The source package and its notes stay under `assets/ember` and are not part of the web image.
