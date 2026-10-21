"""Chrome ウェブストア用のスクリーンショット（1280x800・PNG）を作る。
  1. 速報画面（要対応）  2. ポップアップ（要対応）を暗い背景に載せた1枚  3. ポップアップ（速報なし）
Playwright の Chromium に拡張を読み込み、偽フィードで状態を作って撮る。
使い方: python tools/store_shots.py → docs/store/*.png
"""
import json, shutil, sys, tempfile, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image
sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
SRC_EXT = HERE.parent / "extension"
OUT = HERE.parent / "docs" / "store"; OUT.mkdir(parents=True, exist_ok=True)
EXT = Path(tempfile.gettempdir()) / "secalert-ext-store"
if EXT.exists(): shutil.rmtree(EXT)
shutil.copytree(SRC_EXT, EXT)

def serve(d):
    class H(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=str(d), **k)
        def end_headers(self): self.send_header("Access-Control-Allow-Origin", "*"); super().end_headers()
        def log_message(self, *a): pass
    s = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=s.serve_forever, daemon=True).start(); return s

def feed(d, min_safe):
    browsers = {"schema": 1, "chrome": {"status": "ok", "min_safe": min_safe, "exploited_cves": ["CVE-2026-87491"] if min_safe else [], "alert_id": "chrome-153.0.8010.36" if min_safe else None, "alert_date": "2026-09-08", "latest_stable": {"win": "156.0.8078.48"}, "as_of": "2026-10-20"},
                "edge": {"status": "ok", "min_safe": None, "exploited_cves": [], "alert_id": None, "alert_date": None, "latest_stable": None, "as_of": None}}
    items = [
        {"id": "chrome-153.0.8010.36", "title": "Chrome 153.0.8010.36 セキュリティ更新（230件の修正）", "title_ja": None, "summary_ja": "細工されたページを開くだけで、パソコンを乗っ取られるおそれのある欠陥です。Google は、この欠陥が実際の攻撃に使われていることを確認しています。", "action_ja": "Chrome を更新（153.0.8010.36 以上）：右上の「︙」→「ヘルプ」→「Google Chrome について」を開き、更新が終わったら「再起動」を押す（1分）", "who_ja": "Google Chrome を使っている人", "advice_ja": ["更新する前に心当たりのないページを開いていた場合は、よく使うサービスのパスワード変更と二段階認証もおすすめ"], "kind": "update", "product_label": "Google Chrome", "cves": ["CVE-2026-87491", "CVE-2026-87429"], "exploited_cves": ["CVE-2026-87491"], "published": "2026-09-08", "severity": "critical", "exploited": True, "sources": [{"name": "Chrome Releases", "url": "https://chromereleases.googleblog.com/"}, {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}], "related_posts": [{"source": "hn", "title": "Actively exploited sandbox RCE in all Chromium versions", "url": "https://news.ycombinator.com/", "created_at": "2026-09-09"}, {"source": "x", "author": "vuln_tracker", "url": "https://x.com/", "created_at": "2026-09-09"}]},
        {"id": "kev-CVE-2026-65400", "title": "Apple macOS：Improper Authentication", "title_ja": None, "summary_ja": "Mac の画面共有に、正しい手順を踏まずに操作できてしまう欠陥があります。実際の攻撃に使われたと CISA が発表しています。", "action_ja": "Mac は「システム設定」→「一般」→「ソフトウェアアップデート」で更新する", "who_ja": "iPhone・iPad・Mac を使っている人", "advice_ja": ["そのサービス・製品で使っているパスワードを変える（同じものを他でも使っていれば、そちらも）", "ログインの二段階認証（2要素認証）をオンにする。これだけで、パスワードが漏れても乗っ取られにくくなる"], "kind": "update", "product_label": "iPhone・iPad・Mac", "cves": ["CVE-2026-65400"], "exploited_cves": ["CVE-2026-65400"], "published": "2026-08-18", "severity": "critical", "exploited": True, "sources": [{"name": "CISA KEV", "url": "https://www.cisa.gov/"}], "related_posts": []},
    ]
    (d / "browsers.json").write_text(json.dumps(browsers), encoding="utf-8")
    (d / "alerts.json").write_text(json.dumps({"schema": 1, "items": items}, ensure_ascii=False), encoding="utf-8")

def compose(popup_png, out, bg="#0B1220"):
    canvas = Image.new("RGB", (1280, 800), bg)
    pop = Image.open(popup_png).convert("RGB")
    if pop.height > 760: pop = pop.crop((0, 0, pop.width, 760))
    x = (1280 - pop.width) // 2; y = (800 - pop.height) // 2
    canvas.paste(pop, (x, max(20, y)))
    canvas.save(out); print("wrote", out)

tmp = Path(tempfile.mkdtemp(prefix="secalert-store-")); fd = tmp / "feed"; fd.mkdir()
srv = serve(fd); base = f"http://127.0.0.1:{srv.server_address[1]}/"
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(str(tmp / "profile"), headless=False, timeout=60000, ignore_default_args=["--disable-extensions"],
        args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}", "--no-first-run"], device_scale_factor=1)
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=15000)
    time.sleep(1)
    sw.evaluate("base => chrome.storage.sync.set({ feedBase: base, notify: false })", base)
    ext_id = sw.url.split("/")[2]
    # 1. 速報画面（要対応）
    feed(fd, "153.0.8010.36"); sw.evaluate("async () => await globalThis.__secalert.check()")
    pg = ctx.new_page(); pg.set_viewport_size({"width": 1280, "height": 800}); pg.goto(f"chrome-extension://{ext_id}/alert.html"); pg.wait_for_timeout(1500)
    pg.screenshot(path=str(OUT / "1_alert_required.png")); print("wrote", OUT / "1_alert_required.png")
    # 2. ポップアップ（要対応）
    pp = ctx.new_page(); pp.set_viewport_size({"width": 400, "height": 760}); pp.goto(f"chrome-extension://{ext_id}/popup.html"); pp.wait_for_timeout(1200)
    pp.screenshot(path=str(tmp / "popup_req.png")); compose(tmp / "popup_req.png", OUT / "2_popup_required.png")
    # 3. ポップアップ（速報なし）
    feed(fd, None); sw.evaluate("async () => await globalThis.__secalert.check()"); pp.reload(); pp.wait_for_timeout(1200)
    pp.screenshot(path=str(tmp / "popup_quiet.png")); compose(tmp / "popup_quiet.png", OUT / "3_popup_quiet.png")
    ctx.close()
srv.shutdown(); srv.server_close()
for f in sorted(OUT.glob("*.png")):
    im = Image.open(f); print(f.name, im.size)
