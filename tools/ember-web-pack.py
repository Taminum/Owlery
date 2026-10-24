#!/usr/bin/env python3
"""Packs the Ember asset package for the web app.

Reads assets/ember/pilot-v2/manifest.json (the integration manifest, whose frames point into atlases of
pilot-v2 and library-v1), converts every atlas that a kept clip uses to lossy WebP with a lossless alpha channel,
and writes the pack (by default apps/web/public/ember/):

    atlas-N.webp   the converted atlases (cells of 512x512, full-cell UVs, no repacking)
    projectile.png the separate projectile texture
    heart.png      the heart of the air kiss (only when that scene is in the pack)
    ember.json     a slim manifest: clips as lists of (atlas, x, y), timings, markers, the poster frame
    phrases.ru.json the dialogue lines per clip

    python tools/ember-web-pack.py                       the full pack into apps/web/public/ember
    python tools/ember-web-pack.py --basic               without the cheeky scenes
    python tools/ember-web-pack.py --out DIR             somewhere else
    python tools/ember-web-pack.py --archive ember.tar.gz   also a tar.gz of the pack, for deploy/prod/install-ember.sh

It draws no pixels of the character. Needs Pillow.
"""
import argparse
import json
import os
import shutil
import sys
import tarfile

from PIL import Image

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG = os.path.join(ROOT, "assets", "ember", "pilot-v2")
QUALITY = 86
# The scenes that are not for everyone: left out of the basic pack, with their lines.
CHEEKY = {"kiss_tease", "caught_flirting", "hoodie_off"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "apps", "web", "public", "ember"))
    ap.add_argument("--basic", action="store_true", help="leave out the cheeky scenes and their lines")
    ap.add_argument("--archive", default="", help="also write a tar.gz of the pack")
    args = ap.parse_args()
    out_dir = os.path.abspath(args.out)

    with open(os.path.join(PKG, "manifest.json"), encoding="utf-8") as f:
        m = json.load(f)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    frames = {x["id"]: x for x in m["frames"]}
    kept = {cid: c for cid, c in m["clips"].items() if not (args.basic and cid in CHEEKY)}
    poster_id = os.path.basename(m["reducedMotionPoster"]).replace(".png", "")
    used = {poster_id}
    for c in kept.values():
        used.update(c["frames"])

    atlas_files = []
    for fr in m["frames"]:
        if fr["id"] not in used:
            continue
        p = os.path.normpath(os.path.join(PKG, fr["atlas"]["file"]))
        if p not in atlas_files:
            atlas_files.append(p)
    index = {p: i for i, p in enumerate(atlas_files)}

    total = 0
    for p, i in index.items():
        out = os.path.join(out_dir, f"atlas-{i}.webp")
        im = Image.open(p).convert("RGBA")
        if im.size != (2048, 2048):  # the page sizes the background as a square, so a short last atlas is padded
            full = Image.new("RGBA", (2048, 2048), (0, 0, 0, 0))
            full.paste(im, (0, 0))
            im = full
        im.save(out, "WEBP", quality=QUALITY, method=6, alpha_quality=100)
        total += os.path.getsize(out)

    def cell(fid: str):
        fr = frames[fid]
        a = fr["atlas"]
        p = os.path.normpath(os.path.join(PKG, a["file"]))
        return {"a": index[p], "x": a["x"], "y": a["y"]}

    clips = {}
    for cid, c in kept.items():
        clips[cid] = {
            "frames": [cell(x) for x in c["frames"]],
            "durationsMs": c["durationsMs"],
            "loop": bool(c.get("loop", False)),
            "pivot": c.get("pivot", m["pivot"]),
            "markers": c.get("markers", []),
            "effect": bool(c.get("effect")),
        }
        # Scenes with a scenario: click-to-catch, a change of clothes, a flying heart.
        for key in ("interaction", "wardrobe"):
            if key in c:
                clips[cid][key] = c[key]
        eff = c.get("effect")
        if isinstance(eff, dict) and eff.get("type") == "floating-heart":
            shutil.copyfile(os.path.normpath(os.path.join(PKG, eff["texture"])), os.path.join(out_dir, "heart.png"))
            clips[cid]["heart"] = {"texture": "heart.png", "flight": eff["flight"]}

    proj = m["projectiles"][0]
    shutil.copyfile(os.path.join(PKG, proj["file"]), os.path.join(out_dir, "projectile.png"))
    slim = {
        "frameSize": m["frameSize"],
        "pivot": m["pivot"],
        "atlasCount": len(atlas_files),
        "atlasSize": 2048,
        "poster": cell(poster_id),
        "clips": clips,
        "projectile": {"file": "projectile.png", **proj["textureSize"]},
        "particleMotion": m["particleMotion"],
    }
    with open(os.path.join(out_dir, "ember.json"), "w", encoding="utf-8") as f:
        json.dump(slim, f, ensure_ascii=False, separators=(",", ":"))

    with open(os.path.join(ROOT, "assets", "ember", "dialogue-v1", "phrases.ru.json"), encoding="utf-8") as f:
        phrases = json.load(f)
    if "clips" in phrases:
        phrases["clips"] = {k: v for k, v in phrases["clips"].items() if k in kept}
    with open(os.path.join(out_dir, "phrases.ru.json"), "w", encoding="utf-8") as f:
        json.dump(phrases, f, ensure_ascii=False, indent=1)

    size = sum(os.path.getsize(os.path.join(out_dir, x)) for x in os.listdir(out_dir))
    print(f"{'basic' if args.basic else 'full'} pack: {len(kept)} clips, {len(atlas_files)} atlases, atlases {total / 1e6:.1f} MB, total {size / 1e6:.1f} MB -> {out_dir}")

    if args.archive:
        arc = os.path.abspath(args.archive)
        with tarfile.open(arc, "w:gz") as tf:
            for name in sorted(os.listdir(out_dir)):
                tf.add(os.path.join(out_dir, name), arcname=name)
        print(f"archive: {arc} ({os.path.getsize(arc) / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
