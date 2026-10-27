// 拡張の共通部：設定・フィード取得・自分のブラウザの判定。
// 🚨 外へ出る通信は「公開フィード（静的JSON）を読む」だけ。利用者を識別する情報は送らない。
import { judge, compareVersions } from './version.js';

export const DEFAULT_BASE = 'https://zuboland.github.io/security-sokuho/';
export const CHECK_INTERVAL_MIN = 30;

// サービスの漏えいを通知する件数のしきい値（0＝通知しない）。既定は 1,000万件＝週に1〜2件（2026-10-27 実測）
export const BREACH_THRESHOLDS = [10000000, 1000000, 0];
export const DEFAULT_BREACH_NOTIFY = 10000000;

export async function getSettings() {
  const s = await chrome.storage.sync.get({ feedBase: DEFAULT_BASE, notify: true, breachNotify: DEFAULT_BREACH_NOTIFY });
  if (!isAllowedBase(s.feedBase)) s.feedBase = DEFAULT_BASE;
  if (!BREACH_THRESHOLDS.includes(s.breachNotify)) s.breachNotify = DEFAULT_BREACH_NOTIFY;
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
  // 🚨 data_as_of が「ある形式なのに null」＝根拠の片方が一度も取れていない。generated_at で補わず古いとみなす（2026-10-28 監査 R1 F04・R3）
  //    generated_at で補うのは data_as_of という欄そのものが無い旧形式の配信だけ
  if (status && 'data_as_of' in status && !status.data_as_of) return true;
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

/** breaches.json の形の検査。通ったら null */
export function validateBreaches(b) {
  if (!b || typeof b !== 'object' || b.schema !== 1) return 'schema';
  if (!Array.isArray(b.items)) return 'items';
  const arr = (x) => x == null || Array.isArray(x);
  if (!b.items.every((i) => i && typeof i === 'object' && typeof i.id === 'string' && ['confirmed', 'rumor'].includes(i.type)
    && (i.count == null || Number.isFinite(i.count)) && arr(i.advice_ja) && arr(i.sources) && arr(i.data_ja))) return 'item';
  return null;
}

/** 件数の概数（1万未満は実数・それ以上は四捨五入した「約◯万件」）。配信側 breaches.js の countLabel と同じ */
export function countLabel(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 10000) return `${n.toLocaleString('ja-JP')}件`;
  if (n < 1e8) return `約${Math.round(n / 1e4).toLocaleString('ja-JP')}万件`;
  return `約${(Math.round(n / 1e7) / 10).toLocaleString('ja-JP')}億件`;
}

/** 発表から何時間以内なら通知するか（入れた直後に過去の件をまとめて鳴らさない） */
export const BREACH_FRESH_HOURS = 72;

/**
 * 通知する漏えい。確認済みで、通知してよい質（配信側で判定）で、件数がしきい値以上で、新しいものだけ。
 * 🚨 未確認（rumor）は件数に関係なく絶対に鳴らさない
 */
export function breachesToNotify(items, threshold, now = Date.now()) {
  if (!threshold) return [];
  return (items || []).filter((i) => i.type === 'confirmed' && i.notify_eligible === true && Number.isFinite(i.count) && i.count >= threshold
    && Number.isFinite(publishedMs(i)) && now - publishedMs(i) <= BREACH_FRESH_HOURS * 3600 * 1000);
}

/** 発表の時刻。published_at（時刻つき）を優先し、日付しか無ければその日の終わりから数える（早く窓から外さない・監査 R1 F15） */
function publishedMs(i) {
  const t = Date.parse(i.published_at || '');
  if (Number.isFinite(t)) return t;
  const d = Date.parse(`${i.published}T00:00:00Z`);
  return Number.isFinite(d) ? d + 86400000 - 1 : NaN;
}

/** 漏えいの情報源の鮮度。breaches_as_of が48時間より古い（または null）なら、漏えいの通知は出さない（一覧は出す） */
export const BREACH_STALE_HOURS = 48;
export function breachesStale(status, now = Date.now()) {
  if (!status || !('breaches_as_of' in status)) return isStale(status, now); // 旧形式の配信
  const t = Date.parse(status.breaches_as_of || '');
  return !Number.isFinite(t) || now - t > BREACH_STALE_HOURS * 3600 * 1000;
}

export function settingsUrl(browser) {
  return browser === 'edge' ? 'edge://settings/help' : 'chrome://settings/help';
}
