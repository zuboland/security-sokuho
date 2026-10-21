"""D:\\Downloads の貼り付けファイルから X_BEARER_TOKEN を読み、GitHub Secrets に登録して、ファイルを削除する（値は画面に出さない）。
使い方: python tools/set_x_bearer_from_file.py --repo zuboland/security-sokuho [--file "D:/Downloads/X_BEARER_TOKEN_貼り付け.txt"]
"""
import argparse, json, os, subprocess, sys, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True)
ap.add_argument("--file", default=r"D:/Downloads/X_BEARER_TOKEN_貼り付け.txt")
a = ap.parse_args()

tok = None
for line in open(a.file, encoding="utf-8"):
    if line.startswith("X_BEARER_TOKEN="):
        tok = line.split("=", 1)[1].strip().strip('"').strip("'")
if not tok:
    print("まだ貼られていません"); sys.exit(1)

# 1回だけ試し打ち（直近検索・最大10件＝約$0.05）して、402/401 でないことを確かめる
url = "https://api.x.com/2/tweets/search/recent?query=%22CVE-2026-87491%22%20-is%3Aretweet&max_results=10"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        n = len(json.load(r).get("data", []))
    print(f"X 疎通 OK（直近検索の件数 {n}）")
except urllib.error.HTTPError as e:
    print(f"X 疎通 NG: HTTP {e.code} {e.read()[:120].decode('utf-8', 'replace')}"); sys.exit(1)

r = subprocess.run(["gh", "secret", "set", "X_BEARER_TOKEN", "--repo", a.repo], input=tok, text=True, capture_output=True)
print("secret X_BEARER_TOKEN:", "OK" if r.returncode == 0 else "NG " + r.stderr[:200])
if r.returncode == 0:
    os.remove(a.file)
    print("貼り付けファイルを削除しました")
