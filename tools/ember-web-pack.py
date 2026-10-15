#!/usr/bin/env python3
"""Packs the Ember asset package for the web app.

Reads assets/ember/pilot-v2/manifest.json (the integration manifest, whose frames point into atlases of
pilot-v2 and library-v1), converts every atlas that a frame uses to lossy WebP with a lossless alpha channel,
and writes apps/web/public/ember/:

    atlas-N.webp   the converted atlases (cells of 512x512, full-cell UVs, no repacking)
    projectile.png the separate projectile texture
    ember.json     a slim manifest: clips as lists of (atlas, x, y), timings, markers, the poster frame
    phrases.ru.json the dialogue lines per clip

It draws no pixels of the character. Needs Pillow:  python tools/ember-web-pack.py
"""
import json
import os
import shutil
import sys

from PIL import Image

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG = os.path.join(ROOT, "assets", "ember", "pilot-v2")
OUT = os.path.join(ROOT, "apps", "web", "public", "ember")
QUALITY = 86


def main() -> int:
    with open(os.path.join(PKG, "manifest.json"), encoding="utf-8") as f:
        m = json.load(f)
    os.makedirs(OUT, exist_ok=True)

    frames = {x["id"]: x for x in m["frames"]}
    atlas_files = []
    for fr in m["frames"]:
        p = os.path.normpath(os.path.join(PKG, fr["atlas"]["file"]))
        if p not in atlas_files:
            atlas_files.append(p)
    index = {p: i for i, p in enumerate(atlas_files)}

    total = 0
    for p, i in index.items():
        out = os.path.join(OUT, f"atlas-{i}.webp")
        Image.open(p).convert("RGBA").save(out, "WEBP", quality=QUALITY, method=6, alpha_quality=100)
        total += os.path.getsize(out)

    def cell(fid: str):
        fr = frames[fid]
        a = fr["atlas"]
        p = os.path.normpath(os.path.join(PKG, a["file"]))
        return {"a": index[p], "x": a["x"], "y": a["y"]}

    clips = {}
    for cid, c in m["clips"].items():
        clips[cid] = {
            "frames": [cell(x) for x in c["frames"]],
            "durationsMs": c["durationsMs"],
            "loop": bool(c.get("loop", False)),
            "pivot": c.get("pivot", m["pivot"]),
            "markers": c.get("markers", []),
            "effect": bool(c.get("effect")),
        }

    proj = m["projectiles"][0]
    shutil.copyfile(os.path.join(PKG, proj["file"]), os.path.join(OUT, "projectile.png"))
    slim = {
        "frameSize": m["frameSize"],
        "pivot": m["pivot"],
        "atlasCount": len(atlas_files),
        "atlasSize": 2048,
        "poster": cell(os.path.basename(m["reducedMotionPoster"]).replace(".png", "")),
        "clips": clips,
        "projectile": {"file": "projectile.png", **proj["textureSize"]},
        "particleMotion": m["particleMotion"],
    }
    with open(os.path.join(OUT, "ember.json"), "w", encoding="utf-8") as f:
        json.dump(slim, f, ensure_ascii=False, separators=(",", ":"))
    shutil.copyfile(
        os.path.join(ROOT, "assets", "ember", "dialogue-v1", "phrases.ru.json"),
        os.path.join(OUT, "phrases.ru.json"),
    )
    size = sum(os.path.getsize(os.path.join(OUT, x)) for x in os.listdir(OUT))
    print(f"{len(atlas_files)} atlases, atlases {total / 1e6:.1f} MB, total {size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
