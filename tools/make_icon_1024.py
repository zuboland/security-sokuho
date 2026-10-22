"""常駐アプリ用の 1024px アイコン元絵を作る（拡張と同じ盾・device_scale_factor=8 で描く）。
使い方: python tools/make_icon_1024.py → desktop/src-tauri/icon-source-1024.png
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "desktop" / "src-tauri" / "icon-source-1024.png"
SRC = Path(r"D:/company/ナレッジ/アイコン/svg-monoline-set/134_shield_安全.svg")
svg = SRC.read_text(encoding="utf-8"); svg = svg[svg.index("<svg"):]
HTML = f"""<!doctype html><html><body style="margin:0;background:transparent">
<div id="box" style="width:128px;height:128px;border-radius:28px;background:#1F2A44;display:flex;align-items:center;justify-content:center;color:#fff">
  <div style="width:88px;height:88px">{svg}</div></div></body></html>"""
OUT.parent.mkdir(parents=True, exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 128, "height": 128}, device_scale_factor=8)
    pg.set_content(HTML)
    pg.locator("#box").screenshot(path=str(OUT), omit_background=True)
    b.close()
from PIL import Image
im = Image.open(OUT); print("wrote", OUT, im.size, im.mode)
