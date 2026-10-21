"""OS通知に載せるバナー画像（icons/banner_alert.png・720x360）をコードで描く。AI画像は使わない。
使い方: python tools/make_banner.py
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "extension" / "icons" / "banner_alert.png"
SHIELD = Path(r"D:/company/ナレッジ/アイコン/svg-monoline-set/134_shield_安全.svg").read_text(encoding="utf-8")
SHIELD = SHIELD[SHIELD.index("<svg"):]

HTML = f"""<!doctype html><html lang="ja"><head><meta charset="utf-8"><style>
  body {{ margin:0; width:720px; height:360px; background:#0B1220; color:#E6EAF2; font-family:"Hiragino Sans","Yu Gothic UI","Meiryo","Noto Sans JP",system-ui,sans-serif; overflow:hidden; }}
  .stripe {{ height:14px; background:repeating-linear-gradient(135deg,#FF3B30 0 18px,#B3150E 18px 36px); }}
  .wrap {{ display:grid; grid-template-columns:170px 1fr; gap:28px; padding:24px 44px; align-items:center; height:346px; }}
  .kanji {{ writing-mode:vertical-rl; text-orientation:upright; font-weight:900; font-size:100px; line-height:1; letter-spacing:.06em; color:#FF3B30; margin:0; justify-self:center; }}
  h1 {{ font-size:34px; line-height:1.2; margin:0 0 10px; font-weight:900; letter-spacing:-.01em; white-space:nowrap; }}
  p {{ font-size:20px; color:#A7B0C2; margin:0 0 16px; line-height:1.5; }}
  .promise {{ display:flex; align-items:center; gap:10px; font-size:16px; color:#E6EAF2; border:1px dashed rgba(230,234,242,.25); border-radius:8px; padding:10px 14px; width:max-content; }}
  .promise svg {{ width:22px; height:22px; color:#22C55E; }}
</style></head><body>
<div class="stripe"></div>
<div class="wrap">
  <p class="kanji">速報</p>
  <div>
    <h1>ブラウザを更新してください</h1>
    <p>悪用が確認された脆弱性があります。<br>クリックすると更新画面が開きます（約1分）。</p>
    <div class="promise">{SHIELD}<span>電話やダウンロードを求めることはありません</span></div>
  </div>
</div></body></html>"""

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 720, "height": 360}, device_scale_factor=1)
    pg.set_content(HTML)
    pg.wait_for_timeout(300)
    pg.screenshot(path=str(OUT))
    b.close()
print("wrote", OUT)
