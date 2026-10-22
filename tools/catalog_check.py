"""catalog.json（winget の ID／CPE の対応表）の実在を機械で確かめる。手書きの対応表は必ず古くなるため。
  - winget ID：microsoft/winget-pkgs の manifests に存在するか（GitHub contents API・gh の認証を使う）
  - CPE：NVD の products API（cpes/2.0?cpeMatchString=cpe:2.3:a:<vendor>:<product>）に 1 件以上あるか（鍵なし 5 回/30秒）
判定は3値：OK／NG／判定不能（API に届かない等）。終了値 1＝NG あり。
使い方: python tools/catalog_check.py [--skip-cpe] [--selftest]
"""
import argparse, json, os, re, subprocess, sys, time, urllib.parse, urllib.request
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / "feed" / "static" / "catalog.json"

def winget_exists(wid):
    # manifests/<first letter lower>/<Publisher>/<Name...>（ID の '.' が階層）
    parts = wid.split(".")
    if len(parts) < 2: return "NG"
    path = "manifests/" + parts[0][0].lower() + "/" + "/".join(parts)
    r = subprocess.run(["gh", "api", f"repos/microsoft/winget-pkgs/contents/{urllib.parse.quote(path)}", "--jq", "length"], capture_output=True, text=True, encoding="utf-8")
    if r.returncode == 0 and r.stdout.strip().isdigit(): return "OK"
    if "404" in (r.stderr or ""): return "NG"
    return "判定不能"

def cpe_exists(vp, key=None):
    vendor, product = vp.split(":", 1)
    q = f"cpe:2.3:a:{vendor}:{product}"
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?resultsPerPage=1&cpeMatchString=" + urllib.parse.quote(q)
    req = urllib.request.Request(url, headers={"apiKey": key} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            n = json.load(r).get("totalResults", 0)
            if n == 0 and product != product.replace("_", "-"):
                return "NG"
            return "OK" if n > 0 else "NG"
    except Exception as e:  # noqa: BLE001
        return f"判定不能({type(e).__name__})"

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--skip-cpe", action="store_true"); ap.add_argument("--selftest", action="store_true"); ap.add_argument("--only", default=None); a = ap.parse_args()
    if a.selftest:
        checks = [("実在する winget ID は OK", winget_exists("Google.Chrome") == "OK"), ("無い winget ID は NG", winget_exists("Zuboland.NoSuchApp.XYZ") == "NG")]
        if not a.skip_cpe:
            checks += [("実在する CPE は OK", cpe_exists("google:chrome") == "OK"), ("無い CPE は NG", cpe_exists("zuboland:nosuchproduct").startswith("NG"))]
        ng = [n for n, ok in checks if not ok]
        for n, ok in checks: print(("OK " if ok else "NG "), n)
        print(f"selftest: {len(checks)-len(ng)}/{len(checks)} OK"); sys.exit(1 if ng else 0)
    cat = json.loads(CATALOG.read_text(encoding="utf-8"))
    key = os.environ.get("NVD_API_KEY")
    ng = 0; unknown = 0
    for p in cat["products"]:
        if a.only and p["key"] != a.only: continue
        res = []
        for wid in p["winget"]:
            r = winget_exists(wid); res.append(f"winget {wid}={r}"); ng += r == "NG"; unknown += r.startswith("判定不能")
        if not a.skip_cpe:
            for vp in p["cpe"]:
                r = cpe_exists(vp, key); res.append(f"cpe {vp}={r}"); ng += r == "NG"; unknown += r.startswith("判定不能")
                time.sleep(0.7 if key else 6.5)
        print(p["key"] + ": " + " | ".join(res))
    print(f"\ncatalog_check: NG {ng} / 判定不能 {unknown} / 製品 {len(cat['products'])}")
    sys.exit(1 if ng else 0)

if __name__ == "__main__":
    main()
