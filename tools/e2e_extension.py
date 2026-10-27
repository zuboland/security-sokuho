"""拡張の実機テスト（Playwright の Chromium に拡張を読み込む）。
確かめること：
  1. 版数が取れる（navigator.userAgentData.fullVersionList）
  2. 偽のフィード（min_safe=999.0.0.0）で verdict=required・バッジ「!」・通知の記録が付く
  3. 新しい版数相当（min_safe=1.0.0.0）で verdict=ok（patched）・バッジ空
  4. min_safe=null で verdict=ok（quiet）
  5. フィードが取れないと verdict=unknown・バッジ「?」
  6. chrome://settings/help がタブとして開く（「更新する」ボタンの実体）
終了値 0＝全部OK／1＝NGあり。
"""
import json, os, shutil, sys, tempfile, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright

import functools
sys.stdout.reconfigure(encoding="utf-8")  # Windows の cp932 コンソールで落ちないように
print = functools.partial(print, flush=True)  # パイプ越しでも1行ずつ見える（固まった場所が分かる）
HERE = Path(__file__).resolve().parent
SRC_EXT = HERE.parent / "extension"
# 🚨 --load-extension は日本語を含むパスで固まる（demoshot と同じ地雷）。ASCII だけの場所へ写してから読み込む
EXT = Path(tempfile.gettempdir()) / "secalert-ext"
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("OK " if cond else "NG "), name, ("- " + str(detail)) if detail else "")

def serve(dirpath):
    class H(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=str(dirpath), **k)
        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "no-store"); super().end_headers()
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def write_feed(dirpath, min_safe, status="ok", generated_at=None):
    import datetime
    gen = generated_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
    (dirpath / "status.json").write_text(json.dumps({"schema": 1, "generated_at": gen, "sources_failed": []}), encoding="utf-8")
    browsers = {"schema": 1, "chrome": {"status": status, "min_safe": min_safe, "exploited_cves": ["CVE-2026-999999"] if min_safe else [], "alert_id": f"chrome-{min_safe}" if min_safe else None, "alert_date": "2026-10-20", "latest_stable": {"win": "156.0.8078.48"}, "as_of": "2026-10-20"},
                "edge": {"status": "unknown", "min_safe": None, "exploited_cves": [], "alert_id": None, "alert_date": None, "latest_stable": None, "as_of": None}}
    alerts = {"schema": 1, "window_days": 90, "sources_failed": [], "items": [{"id": "chrome-999", "title": "テスト速報", "title_ja": "テスト速報", "summary_ja": "テスト", "action_ja": "更新する", "product_label": "Google Chrome", "cves": ["CVE-2026-999999"], "published": "2026-10-20", "sources": [{"name": "Chrome Releases", "url": "https://example.invalid/"}], "severity": "critical", "exploited": True}]}
    (dirpath / "browsers.json").write_text(json.dumps(browsers), encoding="utf-8")
    (dirpath / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")

def run_check(sw):
    # サービスワーカーの中で check() を直接呼ぶ（SW では import() が禁止なので globalThis 経由）
    return sw.evaluate("async () => await globalThis.__secalert.check()")

def badge(sw):
    return sw.evaluate("() => chrome.action.getBadgeText({})")

def main():
    if EXT.exists(): shutil.rmtree(EXT)
    shutil.copytree(SRC_EXT, EXT)
    tmp = Path(tempfile.mkdtemp(prefix="secalert-e2e-"))
    feed_dir = tmp / "feed"; feed_dir.mkdir()
    srv = serve(feed_dir)
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    with sync_playwright() as p:
        # Playwright は既定で --disable-extensions を付ける。外さないと拡張が読まれない
        ctx = p.chromium.launch_persistent_context(
            str(tmp / "profile"), headless=False, timeout=60000,
            ignore_default_args=["--disable-extensions"],
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}", "--no-first-run"],
        )
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=15000)
        time.sleep(1.0)
        sw.evaluate("base => chrome.storage.sync.set({ feedBase: base, notify: true })", base)
        # 🚨 インストール直後の自動確認（既定URL）が走っている間は check() が同じ実行を返す。1回待ってから始める
        write_feed(feed_dir, None); run_check(sw); run_check(sw)
        # 起動時の確認で付いた既読と状態だけ消す（開いた速報タブの id は残す＝1枚だけの検査のため）
        sw.evaluate("async () => { const all = await chrome.storage.local.get(null); const del = Object.keys(all).filter(k => k !== 'alertTabId'); await chrome.storage.local.remove(del); }")
        sw.evaluate("base => chrome.storage.sync.set({ feedBase: base, notify: true })", base)

        # 1. 版数
        me = sw.evaluate("async () => await globalThis.__secalert.detectBrowser()")
        check("版数が取れる", me.get("version") and me.get("browser") in ("chrome", "chromium"), me)

        # 2. 要対応
        print("step: required")
        write_feed(feed_dir, "999.0.0.0")
        st = run_check(sw)
        print("step: required checked")
        check("min_safe=999 → required", st["result"]["verdict"] == "required", st["result"]["reason"])
        check("バッジが「!」", badge(sw) == "!", badge(sw))
        notified = sw.evaluate("() => chrome.storage.local.get(null)")
        check("通知の記録が付く（1件1回）", any(k.startswith("notified:") for k in notified), [k for k in notified if k.startswith("notified:")])
        st2 = run_check(sw)
        notified2 = sw.evaluate("() => chrome.storage.local.get(null)")
        check("2回目は通知の記録が増えない", sum(k.startswith("notified:") for k in notified2) == sum(k.startswith("notified:") for k in notified))
        check("速報一覧が入る", len(st["alerts"]) == 1)

        # 3. 対応済み
        write_feed(feed_dir, "1.0.0.0")
        st = run_check(sw)
        check("min_safe=1.0 → ok（patched）", st["result"]["verdict"] == "ok" and st["result"]["reason"] == "patched", st["result"]["reason"])
        check("バッジが空", badge(sw) == "", repr(badge(sw)))

        # 4. 速報なし
        write_feed(feed_dir, None)
        st = run_check(sw)
        check("min_safe=null → ok（quiet）", st["result"]["verdict"] == "ok" and st["result"]["reason"] == "quiet", st["result"]["reason"])

        # 5. 情報源が unknown
        write_feed(feed_dir, None, status="unknown")
        st = run_check(sw)
        check("status=unknown → unknown（no_data）", st["result"]["verdict"] == "unknown" and st["result"]["reason"] == "no_data", st["result"]["reason"])
        check("バッジが「?」", badge(sw) == "?", badge(sw))

        # 5a. 配信が古い（24時間超）→ unknown（stale）／壊れた形（min_safe が数値）→ unknown（bad_feed）
        write_feed(feed_dir, "999.0.0.0", generated_at="2026-10-01T00:00:00Z")
        st = run_check(sw)
        check("配信が24時間以上古い → unknown（stale）・要対応にしない", st["result"]["verdict"] == "unknown" and st["result"]["reason"] == "stale", st["result"]["reason"])
        (feed_dir / "browsers.json").write_text(json.dumps({"schema": 1, "chrome": {"status": "ok", "min_safe": 0, "exploited_cves": [], "alert_id": None}, "edge": {"status": "unknown", "min_safe": None, "exploited_cves": []}}), encoding="utf-8")
        write_feed(feed_dir, None); (feed_dir / "browsers.json").write_text(json.dumps({"schema": 1, "chrome": {"status": "ok", "min_safe": 0, "exploited_cves": [], "alert_id": None}, "edge": {"status": "unknown", "min_safe": None, "exploited_cves": []}}), encoding="utf-8")
        st = run_check(sw)
        check("min_safe が数値（壊れた配信）→ unknown（bad_feed）", st["result"]["verdict"] == "unknown" and st["result"]["reason"] == "bad_feed", st["result"]["reason"])
        # 5b. フィードが取れない
        print("step: shutdown server")
        srv.shutdown(); srv.server_close()  # 🚨 shutdown() だけだと待受ソケットが残り、接続が永久に待つ
        print("step: server down")
        st = run_check(sw)
        check("配信元に届かない → unknown（fetch_failed）", st["result"]["verdict"] == "unknown" and st["result"]["reason"] == "fetch_failed", st["result"]["reason"])

        # 6. 更新画面が開く
        print("step: open settings")
        sw.evaluate("() => { chrome.tabs.create({ url: 'chrome://settings/help' }); return true; }")
        time.sleep(1.5)
        # Playwright は chrome:// のタブを pages に出さず、拡張も tabs 権限なしでは URL を読めない（権限を増やさない）。
        # CDP の Target.getTargets で全ターゲットの URL を見る
        cdp = ctx.new_cdp_session(ctx.pages[0])
        urls = [t["url"] for t in cdp.send("Target.getTargets")["targetInfos"]]
        check("chrome://settings/help が開く", any(u.startswith("chrome://settings/help") for u in urls), [u for u in urls if u.startswith("chrome")][:5])

        # 7. ポップアップが描画できる（required 状態）
        write_feed(feed_dir, "999.0.0.0")
        srv2 = serve(feed_dir); base2 = f"http://127.0.0.1:{srv2.server_address[1]}/"
        sw.evaluate("base => chrome.storage.sync.set({ feedBase: base })", base2)
        run_check(sw)
        ext_id = sw.url.split("/")[2]
        pop = ctx.new_page(); pop.goto(f"chrome-extension://{ext_id}/popup.html"); pop.wait_for_timeout(800)
        txt = pop.inner_text("#status")
        check("ポップアップに「更新してください」と修正版が出る", "更新してください" in txt and "999.0.0.0" in txt, txt[:120].replace("\n", " "))
        check("詐欺と見分ける一文が常に出る", "電話やダウンロードを求めることはありません" in pop.inner_text("footer"))
        pop.screenshot(path=str(HERE.parent / "docs" / "popup_required.png"))
        srv2.shutdown(); srv2.server_close()

        # 7b. サービスの漏えい（breaches.json）：鳴らすのは確認済み・新しい・しきい値以上だけ。未確認は旗が立っていても鳴らさない
        print("step: breaches")
        import datetime
        today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).date().isoformat()
        adv = ["パスワードを変える", "二段階認証", "メールのリンクを開かない"]
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        def bitem(id_, count, published, title, eligible=True, typ="confirmed", **kw):
            d = {"id": id_, "type": typ, "basis": "news" if typ == "confirmed" else "x", "title_ja": title, "count": count, "data_ja": [], "published": published, "notify_eligible": eligible, "advice_ja": adv, "sources": [{"name": "ScanNetSecurity", "url": f"https://example.invalid/{id_}"}]}
            d.update(kw); return d
        bitems = [
            bitem("news-big", 20000000, today, "大きな漏えい 2,000万件", published_at=now_iso),
            bitem("news-big2", 15000000, today, "大きな漏えい2 1,500万件", published_at=now_iso),
            bitem("news-big3", 12000000, today, "大きな漏えい3 1,200万件", published_at=now_iso),
            bitem("news-mid", 5000000, today, "中くらいの漏えい 500万件", published_at=now_iso),
            bitem("news-old", 30000000, old, "古い漏えい 3,000万件"),
            bitem("rumor-x", 99000000, today, "X で「ほげペイ」の漏えいについての投稿が増えています（未確認）", typ="rumor", service="ほげペイ", caution_ja="未確認です。X で投稿が増えているだけです。",
                  sources=[{"name": "X の検索結果", "url": "https://x.com/search?q=x"}, {"name": "悪いリンク", "url": "javascript:alert(1)"}]),
        ]
        def write_breaches(rumor_watch=None):
            (feed_dir / "breaches.json").write_text(json.dumps({"schema": 1, "window_days": 30, "sources_failed": [], "rumor_watch": rumor_watch or {"enabled": True, "last_ok_at": now_iso}, "items": bitems}), encoding="utf-8")
        def breach_keys():
            return sorted(k for k in sw.evaluate("() => chrome.storage.local.get(null)") if k.startswith("notified:secalert-breach:"))
        write_feed(feed_dir, None); write_breaches()
        srvB = serve(feed_dir); baseB = f"http://127.0.0.1:{srvB.server_address[1]}/"
        sw.evaluate("base => chrome.storage.sync.set({ feedBase: base, notify: true, breachNotify: 10000000 })", baseB)
        st = run_check(sw)
        keys = breach_keys()
        check("漏えい：1回の確認で鳴るのは最大2件（1,000万件以上・新しい・確認済み）", keys == ["notified:secalert-breach:news-big", "notified:secalert-breach:news-big2"], keys)
        check("漏えい：未確認（rumor）は旗が立っていても鳴らない", not any("rumor" in k for k in keys))
        check("漏えい：一覧に6件入る", st.get("breaches_ok") and len(st.get("breaches", [])) == 6, len(st.get("breaches", [])))
        run_check(sw)
        keys2 = breach_keys()
        check("漏えい：既読の2件が3件目を塞がない（2回目の確認で3件目が鳴る）", keys2 == keys + ["notified:secalert-breach:news-big3"], keys2)
        run_check(sw)
        check("漏えい：3回目は増えない（1件1回）", breach_keys() == keys2, breach_keys())
        sw.evaluate("() => chrome.storage.sync.set({ breachNotify: 1000000 })")
        run_check(sw)
        keys3 = breach_keys()
        check("漏えい：100万件に下げると500万件の件も鳴る（古い件は鳴らない）", keys3 == sorted(keys2 + ["notified:secalert-breach:news-mid"]), keys3)
        pb = ctx.new_page(); pb.goto(f"chrome-extension://{ext_id}/popup.html#breaches"); pb.wait_for_timeout(800)
        bt = pb.inner_text("#breaches")
        check("ポップアップ：確認済みと未確認が分かれ、未確認に注意文が出る", "確認済み・報道" in bt and "未確認" in bt and "X で投稿が増えているだけ" in bt, bt[:160].replace("\n", " "))
        check("ポップアップ：X の確認が動いているときは「3時間ごとに確認」と出す（話題があるときは一覧）", "ほげペイ" in bt, bt[-160:].replace("\n", " "))
        hrefs = pb.eval_on_selector_all("#breaches a", "els => els.map(e => e.getAttribute('href'))")
        check("ポップアップ：https 以外のリンクは出さない", all(h.startswith("https://") for h in hrefs) and not any("javascript" in h for h in hrefs), hrefs)
        pb.screenshot(path=str(HERE.parent / "docs" / "popup_breaches.png"), full_page=True)
        # X の確認が止まっている（off）なら「話題はありません」と言わない
        write_breaches(rumor_watch={"enabled": False, "last_ok_at": None}); run_check(sw); pb.reload(); pb.wait_for_timeout(600)
        check("ポップアップ：X の確認が off なら「確認は行っていません」と出す", "確認は行っていません" in pb.inner_text("#breach-rumor"), pb.inner_text("#breach-rumor")[:80])
        # 漏えいの情報源が古い（breaches_as_of が3日前）：一覧は出すが通知しない
        bitems.append(bitem("news-new", 50000000, today, "新しい大きな漏えい", published_at=now_iso)); write_breaches()
        status = json.loads((feed_dir / "status.json").read_text(encoding="utf-8"))
        status["breaches_as_of"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)).isoformat()
        (feed_dir / "status.json").write_text(json.dumps(status), encoding="utf-8")
        st = run_check(sw)
        check("漏えい：情報源が48時間以上古いと鳴らさない（一覧は出す）", st.get("breaches_stale") is True and st.get("breaches_ok") and "notified:secalert-breach:news-new" not in breach_keys(), st.get("breaches_stale"))
        # data_as_of が「ある形式で null」＝根拠の片方が取れていない → 判定不能（監査 R1 F04・R3）
        status["data_as_of"] = None
        (feed_dir / "status.json").write_text(json.dumps(status), encoding="utf-8")
        st = run_check(sw)
        check("data_as_of が null → unknown（stale）・generated_at で補わない", st["result"]["verdict"] == "unknown" and st["result"]["reason"] == "stale", st["result"])
        write_feed(feed_dir, None, generated_at="2026-10-01T00:00:00Z")
        st = run_check(sw)
        check("漏えい：配信全体が古いときは一覧を出すが古い扱い（通知しない・監査 R4 F05）", st.get("breaches_ok") is True and st.get("breaches_stale") is True, (st.get("breaches_ok"), st.get("breaches_stale")))
        pb.close(); srvB.shutdown(); srvB.server_close()
        sw.evaluate("() => chrome.storage.sync.set({ breachNotify: 10000000 })")

        # 8. 本物のフィード（固定応答から build した public/）で判定する
        #    Playwright の Chromium は安定版より古い（145）ので、悪用確認つきの修正版（153.x）未満＝required になるはず
        import subprocess
        feed_dir_real = HERE.parent / "feed"
        pub = tmp / "public"
        env = dict(os.environ, SECALERT_FIXTURES=str(feed_dir_real / "test" / "fixtures"), SECALERT_PUBLIC=str(pub), SECALERT_SUMMARY_DIR=str(tmp / "sum"), SECALERT_POSTS_DIR=str(tmp / "posts"), SECALERT_AI="none",
                   SECALERT_SNAPSHOT_DIR=str(tmp / "snap"), SECALERT_AFFECTED_DIR=str(tmp / "aff"), SECALERT_XBUZZ_DIR=str(tmp / "xbuzz"), SECALERT_XBUZZ="off", SECALERT_NEWS_CACHE=str(tmp / "news" / "seen.json"))
        r = subprocess.run(["node", str(feed_dir_real / "src" / "build.js")], env=env, capture_output=True, text=True, encoding="utf-8", cwd=str(feed_dir_real))
        check("本物のフィードが build できる", r.returncode == 0, (r.stdout + r.stderr).strip()[-200:])
        srv3 = serve(pub); base3 = f"http://127.0.0.1:{srv3.server_address[1]}/"
        sw.evaluate("base => chrome.storage.sync.set({ feedBase: base })", base3)
        st = run_check(sw)
        bro = json.loads((pub / "browsers.json").read_text(encoding="utf-8"))
        check("本物のフィード：Chromium 145 は修正版未満 → required", st["result"]["verdict"] == "required", f"min_safe={bro['chrome']['min_safe']} reason={st['result']['reason']}")
        check("本物のフィード：速報一覧に1件以上", len(st["alerts"]) >= 1, len(st["alerts"]))
        pop.reload(); pop.wait_for_timeout(800)
        pop.screenshot(path=str(HERE.parent / "docs" / "popup_real_feed.png"), full_page=True)
        # 速報画面（鳴った瞬間に開く1枚）も撮る。通知で自動的に開いているはずなのでそれを確かめる
        # tabs 権限が無いので URL では数えられない → CDP で全ターゲットを見る
        run_check(sw)  # もう1回鳴らしても増えないこと
        targets = [t["url"] for t in cdp.send("Target.getTargets")["targetInfos"] if t["type"] == "page"]
        alert_tabs = sum(1 for u in targets if u.endswith("/alert.html"))
        check("速報画面が自動で1枚だけ開いている（2回鳴らしても増えない）", alert_tabs == 1, targets)
        ap = ctx.new_page(); ap.set_viewport_size({"width": 1280, "height": 860}); ap.goto(f"chrome-extension://{ext_id}/alert.html"); ap.wait_for_timeout(1200)
        at = ap.inner_text("body")
        check("速報画面に版数の対比と守りの行動が出る", "153.0.8010.36" in at and "今すぐ更新" in at and "守り" in at, at[:160].replace("\n", " "))
        ap.screenshot(path=str(HERE.parent / "docs" / "alert_required.png"), full_page=True)
        srv3.shutdown(); srv3.server_close()
        ctx.close()
    ng = [r for r in results if not r[1]]
    print(f"\ne2e: {len(results)-len(ng)}/{len(results)} OK, NG {len(ng)}")
    sys.exit(1 if ng else 0)

if __name__ == "__main__":
    (HERE.parent / "docs").mkdir(exist_ok=True)
    main()
