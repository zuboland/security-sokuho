#!/usr/bin/env node
/**
 * UNICREW Windows 署名フック（Azure Trusted Signing / signtool + dlib 直呼び）
 *
 * tauri.conf.json の bundle.windows.signCommand から `node scripts/sign-windows.mjs <path>`
 * として呼ばれる（<path> は署名対象バイナリの絶対パス。Tauri が %1 を置換する）。
 * アプリ本体 exe / NSIS インストーラ / MSI のそれぞれに対して呼ばれる。
 *
 * 方式は KUZIRA で確立済み（kuzira/build/sign-hook.js・2026-08-14 実働）:
 *   - electron-builder/PS モジュール経由は壊れているため signtool /dlib 直呼び
 *   - 🚨 signtool は x64 版を明示（arm64 版を先に拾うと spawn UNKNOWN で死ぬ）
 *   - 🚨 dlib は .NET8 ランタイム必須（無いと exit 3・出力ゼロで死ぬ）
 *   - タイムスタンプ必須（Trusted Signing の証明書は 3 日で失効するため、
 *     タイムスタンプが無いと配布物が 3 日で無効になる）
 *
 * 認証は環境変数 AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET。
 * ★ 認証情報が無い環境（fork のローカルビルド等）では警告して exit 0（未署名ビルド継続）。
 *   CI（GitHub Actions）では 3 変数を Secrets から注入するので必ず署名される。
 *
 * ツールの所在（優先順）:
 *   1. %TRUSTED_SIGNING_DIR%（CI が NuGet で展開する場所を指定）
 *   2. %LOCALAPPDATA%\TrustedSigning（開発機の既存レイアウト）
 * metadata.json が無ければ endpoint/account/profile から自動生成する（秘密情報ではない）。
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

const ENDPOINT = "https://jpe.codesigning.azure.net";
const ACCOUNT = "zubolandsigning";
const PROFILE = "zuboland-prod";
const TIMESTAMP_URL = "http://timestamp.acs.microsoft.com";

const target = process.argv[2];
if (!target) {
  console.error("[sign] usage: node sign-windows.mjs <binary path>");
  process.exit(1);
}
if (process.platform !== "win32") {
  console.log("[sign] not windows — skip");
  process.exit(0);
}
if (!fs.existsSync(target)) {
  console.error(`[sign] 対象が存在しません: ${target}`);
  process.exit(1);
}

const missing = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"].filter(
  (k) => !process.env[k],
);
if (missing.length > 0) {
  // 認証情報の無い環境では未署名で続行（ビルド自体は成立させる）。
  console.warn(
    `[sign] ⚠ 認証情報が無いため署名をスキップ: ${path.basename(target)}（missing: ${missing.join(", ")}）`,
  );
  process.exit(0);
}

/** base 配下を再帰し leaf に一致するファイルを列挙（\x64\ を含むパスを優先） */
function findTool(base, leaf) {
  if (!base || !fs.existsSync(base)) return null;
  const hits = [];
  const walk = (d) => {
    let ents = [];
    try {
      ents = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      const p = path.join(d, e.name);
      if (e.isFile() && e.name.toLowerCase() === leaf.toLowerCase()) hits.push(p);
      else if (e.isDirectory()) walk(p);
    }
  };
  walk(base);
  if (hits.length === 0) return null;
  // 🚨 arm64/x86 の signtool を拾わないよう x64 を優先する
  return hits.find((p) => p.toLowerCase().includes(`${path.sep}x64${path.sep}`)) || hits[0];
}

const roots = [
  process.env.TRUSTED_SIGNING_DIR,
  path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "TrustedSigning"),
].filter(Boolean);

let signtool = null;
let dlib = null;
for (const root of roots) {
  signtool = signtool || findTool(path.join(root, "Microsoft.Windows.SDK.BuildTools"), "signtool.exe") || findTool(root, "signtool.exe");
  dlib = dlib || findTool(path.join(root, "Microsoft.Trusted.Signing.Client"), "Azure.CodeSigning.Dlib.dll") || findTool(root, "Azure.CodeSigning.Dlib.dll");
}
if (!signtool || !dlib) {
  console.error(
    `[sign] 署名ツールが見つかりません（signtool=${signtool} dlib=${dlib}）。` +
      `NuGet の Microsoft.Windows.SDK.BuildTools / Microsoft.Trusted.Signing.Client を ` +
      `%LOCALAPPDATA%\\TrustedSigning か %TRUSTED_SIGNING_DIR% に展開してください。`,
  );
  process.exit(1);
}

// metadata.json（endpoint/account/profile のみ＝秘密情報ではない）。無ければ生成。
let meta = path.join(path.dirname(dlib), "metadata.json");
if (!fs.existsSync(meta)) {
  meta = path.join(os.tmpdir(), "unicrew-trusted-signing-metadata.json");
  fs.writeFileSync(
    meta,
    JSON.stringify({
      Endpoint: ENDPOINT,
      CodeSigningAccountName: ACCOUNT,
      CertificateProfileName: PROFILE,
      ExcludeCredentials: [],
    }),
  );
}

// 冪等: 既に「ZUBOLAND の署名」が付いている場合のみスキップ
// （Tauri は同じバイナリに複数回 signCommand を呼ぶことがある）。
// 🚨 監査指摘（2026-08-14 第1回 HIGH）: 旧実装は verify /pa が通るだけでスキップして
// いたため、他発行者の有効な Authenticode 署名が付いたバイナリが混入した場合に
// 再署名されないまま配布される恐れがあった。発行先サブジェクトまで確認する。
const EXPECTED_SUBJECT = "ZUBOLAND";
try {
  const out = execFileSync(signtool, ["verify", "/pa", "/v", target], {
    stdio: "pipe",
  }).toString("utf8");
  if (out.includes("Successfully verified") && out.includes(EXPECTED_SUBJECT)) {
    console.log(`[sign] ZUBOLAND 署名済みのためスキップ: ${path.basename(target)}`);
    process.exit(0);
  }
  // 有効だが他者の署名 → 我々の署名で置き換える（signtool sign は主署名を置換する）
  console.warn(
    `[sign] ⚠ 既存署名は ${EXPECTED_SUBJECT} ではないため再署名します: ${path.basename(target)}`,
  );
} catch {
  /* 未署名 → 署名へ */
}

// 🚨 dlib(.NET8) の解決に DOTNET_ROOT が要る環境（開発機のユーザーローカル導入）に対応
const env = { ...process.env };
const dotnetRoot = path.join(os.homedir(), ".dotnet");
if (!env.DOTNET_ROOT && fs.existsSync(path.join(dotnetRoot, "dotnet.exe"))) {
  env.DOTNET_ROOT = dotnetRoot;
  env.PATH = `${dotnetRoot}${path.delimiter}${env.PATH || ""}`;
}

console.log(`[sign] ${path.basename(target)}`);
execFileSync(
  signtool,
  [
    "sign",
    "/v",
    "/fd",
    "SHA256",
    "/tr",
    TIMESTAMP_URL,
    "/td",
    "SHA256",
    "/dlib",
    dlib,
    "/dmdf",
    meta,
    target,
  ],
  { stdio: "inherit", env },
);

// 署名結果を必ず検証（signtool の終了コードだけを信用しない）
execFileSync(signtool, ["verify", "/pa", target], { stdio: "inherit" });
console.log(`[sign] ✔ 署名+検証 OK: ${path.basename(target)}`);
