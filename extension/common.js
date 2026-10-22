// 拡張の共通部：設定・フィード取得・自分のブラウザの判定。
// 🚨 外へ出る通信は「公開フィード（静的JSON）を読む」だけ。利用者を識別する情報は送らない。
import { judge, compareVersions } from './version.js';

export const DEFAULT_BASE = 'https://zuboland.github.io/security-sokuho/';
export const CHECK_INTERVAL_MIN = 30;

export async function getSettings() {
  const s = await chrome.storage.sync.get({ feedBase: DEFAULT_BASE, notify: true });
  if (!isAllowedBase(s.feedBase)) s.feedBase = DEFAULT_BASE;
  return s;
}

/** https で / 終わりだけ。自分のPC（127.0.0.1／localhost）だけ http を許す（開発・テスト用） */
export function isAllowedBase(u) {
  return /^https:\/\/.+\/$/.test(u) || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/.*$/.test(u) && u.endsWith('/');
}

export async function fetchFeed(name, base) {
  // 時間切れを必ず付ける（配信元が応答しないと、判定が永久に「確認中」で止まる）
  const res = await fetch(new URL(name, base).toString(), { cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trimStart().startsWith('{')) throw new Error('not JSON');
  return JSON.parse(text);
}

/** 自分のブラウザ。Chrome か Edge か（Brave 等は chromium）。版数が取れなければ null */
export async function detectBrowser() {
  try {
    const uad = navigator.userAgentData;
    if (!uad?.getHighEntropyValues) return { browser: null, version: null };
    const h = await uad.getHighEntropyValues(['fullVersionList']);
    const list = h.fullVersionList || [];
    const pick = (brand) => list.find((b) => b.brand === brand)?.version || null;
    const edge = pick('Microsoft Edge');
    if (edge) return { browser: 'edge', version: edge };
    const chromeV = pick('Google Chrome');
    if (chromeV) return { browser: 'chrome', version: chromeV };
    const chromium = pick('Chromium');
    if (chromium) return { browser: 'chromium', version: chromium };
    return { browser: null, version: null };
  } catch {
    return { browser: null, version: null };
  }
}

/**
 * 判定（3値）。
 *   required … 悪用確認済みの脆弱性があり、自分の版数が修正版未満
 *   ok       … 修正版以上（または期間内に悪用確認済みの件が無い＝quiet）
 *   unknown  … 版数が取れない／そのブラウザの情報が取れていない
 */
export function evaluate(browsers, me) {
  const key = me.browser === 'chromium' ? 'chrome' : me.browser; // Chromium 系は Chrome の修正版で見る（同じエンジン）
  const b = key ? browsers?.[key] : null;
  if (!b || b.status !== 'ok') return { verdict: 'unknown', reason: 'no_data', browser: key, version: me.version, info: b || null };
  if (!me.version) return { verdict: 'unknown', reason: 'no_version', browser: key, version: null, info: b };
  if (!b.min_safe) {
    return { verdict: 'ok', reason: 'quiet', browser: key, version: me.version, info: b, behind_latest: behindLatest(me.version, b) };
  }
  const v = judge(me.version, b.min_safe);
  if (v === 'unknown') return { verdict: 'unknown', reason: 'compare_failed', browser: key, version: me.version, info: b };
  return { verdict: v, reason: v === 'required' ? 'below_min_safe' : 'patched', browser: key, version: me.version, info: b, behind_latest: behindLatest(me.version, b) };
}

function behindLatest(version, b) {
  const latest = typeof b.latest_stable === 'string' ? b.latest_stable : b.latest_stable?.win || b.latest_stable?.mac || null;
  if (!latest) return null;
  const c = compareVersions(version, latest);
  return c === null ? null : c < 0;
}

/** 配信の鮮度。30分ごとの配信が 24 時間止まっていたら「古い」（古い安全判定を現在の確認として出さない・監査R2/R3） */
export const STALE_HOURS = 24;
export function isStale(status, now = Date.now()) {
  // 根拠のデータの時刻（data_as_of）で見る。snapshot で作り直した回は generated_at が新しくても data_as_of は古い（監査R4-H2）
  const t = status?.data_as_of ? Date.parse(status.data_as_of) : status?.generated_at ? Date.parse(status.generated_at) : NaN;
  if (Number.isNaN(t)) return true;
  return now - t > STALE_HOURS * 3600 * 1000;
}

/** 配信の形の検査。壊れた JSON を「速報なし」と読まない（監査R3）。通ったら null、駄目なら理由 */
export function validateBrowsers(b) {
  if (!b || typeof b !== 'object' || b.schema !== 1) return 'schema';
  for (const key of ['chrome', 'edge']) {
    const x = b[key];
    if (!x || typeof x !== 'object') return `${key} missing`;
    if (!['ok', 'unknown'].includes(x.status)) return `${key}.status`;
    if (!(x.min_safe === null || (typeof x.min_safe === 'string' && /^\d+(\.\d+){1,3}$/.test(x.min_safe)))) return `${key}.min_safe`;
    if (!Array.isArray(x.exploited_cves)) return `${key}.exploited_cves`;
  }
  return null;
}
export function validateAlerts(a) {
  if (!a || typeof a !== 'object' || a.schema !== 1) return 'schema';
  if (!Array.isArray(a.items)) return 'items';
  if (a.sources_failed != null && !Array.isArray(a.sources_failed)) return 'sources_failed';
  // 描画で配列として扱う欄は配列であることを見る（監査R4-M6）
  const arr = (x) => x == null || Array.isArray(x);
  if (!a.items.every((i) => i && typeof i === 'object' && typeof i.id === 'string' && arr(i.cves) && arr(i.exploited_cves) && arr(i.advice_ja) && arr(i.sources) && arr(i.related_posts))) return 'item';
  return null;
}

export function settingsUrl(browser) {
  return browser === 'edge' ? 'edge://settings/help' : 'chrome://settings/help';
}
