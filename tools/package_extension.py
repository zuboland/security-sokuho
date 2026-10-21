"""ストア提出用の zip を作る（extension/ をそのまま。テスト用の globalThis 公開はそのまま＝害は無い）。
使い方: python tools/package_extension.py → dist/security-sokuho-<version>.zip
"""
import json, sys, zipfile
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
EXT = HERE.parent / "extension"
DIST = HERE.parent / "dist"
DIST.mkdir(exist_ok=True)
ver = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))["version"]
out = DIST / f"security-sokuho-{ver}.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(EXT.rglob("*")):
        if p.is_file() and not p.name.startswith(".") and p.suffix not in (".map",):
            z.write(p, p.relative_to(EXT).as_posix())
print("wrote", out, out.stat().st_size, "bytes")
with zipfile.ZipFile(out) as z:
    names = z.namelist(); print(len(names), "files:", ", ".join(names))
