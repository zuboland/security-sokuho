"""GitHub Actions の Secrets／Variables を設定する（社内用・値は画面に出さない）。

- ANTHROPIC_API_KEY は envload で profile から読み、そのまま `gh secret set` の標準入力へ渡す（Claude は値を運ばない）
- X_BEARER_TOKEN は X の API キー＋シークレット（UNIPOST の profile）から app-only の bearer を取得して登録する
- Variables：SECALERT_AI=anthropic / SECALERT_AI_MODEL=claude-opus-5-5 / SECALERT_AI_MAX=20 / SECALERT_SOCIAL=hn（X の購入後に hn,x へ）
使い方: python tools/set_gh_secrets.py --repo zuboland/security-sokuho --anthropic-profile uniflow [--x-profile unipost] [--social hn]
"""
import argparse, base64, json, os, subprocess, sys, urllib.request

sys.path.insert(0, r"D:\company\.claude\secrets")
from envload import load  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True)
ap.add_argument("--anthropic-profile", default=None)
ap.add_argument("--x-profile", default=None)
ap.add_argument("--x-key-name", default="X_API_KEY")
ap.add_argument("--x-secret-name", default="X_API_SECRET")
ap.add_argument("--x-from-xurl", action="store_true", help="~/.xurl/auth.yml の default アプリの client_id/secret から app-only bearer を取る")
ap.add_argument("--x-env-file", default=None, help="X_API_KEY/X_API_SECRET が書かれた env ファイルのパス（profile に無いとき）")
ap.add_argument("--azure-env-file", default=None, help="AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET が書かれた env ファイル（署名用・Trusted Signing）")
ap.add_argument("--social", default=None)
a = ap.parse_args()


def xurl_app_creds():
    import yaml  # noqa: WPS433
    p = os.path.join(os.path.expanduser("~"), ".xurl", "auth.yml")
    d = yaml.safe_load(open(p, encoding="utf-8"))
    app = d["apps"][d.get("default_app", "default")]
    return app.get("client_id"), app.get("client_secret")


def gh_secret(name, value):
    r = subprocess.run(["gh", "secret", "set", name, "--repo", a.repo], input=value, text=True, capture_output=True)
    print(f"secret {name}: {'OK' if r.returncode == 0 else 'NG ' + r.stderr.strip()[:200]}")


def gh_var(name, value):
    r = subprocess.run(["gh", "variable", "set", name, "--repo", a.repo, "--body", value], text=True, capture_output=True)
    print(f"variable {name}={value}: {'OK' if r.returncode == 0 else 'NG ' + r.stderr.strip()[:200]}")


if a.anthropic_profile:
    load(a.anthropic_profile, only=["ANTHROPIC_API_KEY"])
    v = os.environ.get("ANTHROPIC_API_KEY")
    if not v:
        print("ANTHROPIC_API_KEY が profile に無い"); sys.exit(1)
    gh_secret("ANTHROPIC_API_KEY", v)
    gh_var("SECALERT_AI", "anthropic")
    gh_var("SECALERT_AI_MODEL", "claude-opus-5-5")
    gh_var("SECALERT_AI_MAX", "20")

def read_env_file(path, names):
    out = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key.strip() in names:
            out[key.strip()] = val.strip().strip('"').strip("'")
    return out


if a.x_profile or a.x_from_xurl or a.x_env_file:
    if a.x_from_xurl:
        k, s = xurl_app_creds()
    elif a.x_env_file:
        d = read_env_file(a.x_env_file, {a.x_key_name, a.x_secret_name})
        k, s = d.get(a.x_key_name), d.get(a.x_secret_name)
    else:
        load(a.x_profile, only=[a.x_key_name, a.x_secret_name])
        k, s = os.environ.get(a.x_key_name), os.environ.get(a.x_secret_name)
    if not (k and s):
        print("X の API キー／シークレットが profile に無い"); sys.exit(1)
    basic = base64.b64encode(f"{k}:{s}".encode()).decode()
    req = urllib.request.Request("https://api.x.com/oauth2/token", data=b"grant_type=client_credentials",
                                 headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            tok = json.load(r).get("access_token")
    except Exception as e:  # noqa: BLE001
        print(f"X bearer の取得に失敗: {type(e).__name__} {getattr(e, 'code', '')}"); sys.exit(1)
    if not tok:
        print("X bearer が返らなかった"); sys.exit(1)
    gh_secret("X_BEARER_TOKEN", tok)

if a.azure_env_file:
    if a.azure_env_file == "kuzira":  # 社内の置き場（KUZIRA・UNICREW と同じ署名の鍵）。パスをコマンド行に出さないための別名
        a.azure_env_file = r"D:\secrets\.env.kuzira"
    names = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
    d = read_env_file(a.azure_env_file, set(names))
    missing = [n for n in names if not d.get(n)]
    if missing:
        print("Azure の鍵が足りない:", ", ".join(missing)); sys.exit(1)
    for n in names:
        gh_secret(n, d[n])

if a.social:
    gh_var("SECALERT_SOCIAL", a.social)
