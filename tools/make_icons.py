"""拡張のアイコンを、社内のアイコン正本（svg-monoline-set/134_shield_安全.svg）から作る。
AI画像は使わない。Playwright の Chromium で SVG を描画して PNG にする。
使い方: python tools/make_icons.py
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "extension" / "icons"
SRC = Path(r"D:/company/ナレッジ/アイコン/svg-monoline-set/134_shield_安全.svg")

svg = SRC.read_text(encoding="utf-8")
svg = svg[svg.index("<svg"):]

HTML = f"""<!doctype html><html><body style="margin:0;background:transparent">
<div id="box" style="width:128px;height:128px;border-radius:28px;background:#1F2A44;display:flex;align-items:center;justify-content:center;color:#fff">
  <div style="width:88px;height:88px">{svg}</div>
</div></body></html>"""

OUT.mkdir(parents=True, exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 128, "height": 128}, device_scale_factor=1)
    pg.set_content(HTML)
    for size in (16, 48, 128, 1024):
        pg.set_viewport_size({"width": 128, "height": 128})
        pg.evaluate("s => { const el = document.getElementById('box'); el.style.transformOrigin='0 0'; el.style.transform = `scale(${s/128})`; }", size)
        pg.set_viewport_size({"width": size, "height": size})
        # 1024 は常駐アプリ（Tauri の `tauri icon` の元絵）用。拡張には使わない
        out = OUT / f"icon{size}.png" if size <= 128 else OUT.parent.parent / "desktop" / "src-tauri" / "icon-source-1024.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        pg.locator("#box").screenshot(path=str(out), omit_background=True)
        print("wrote", out)
    b.close()
