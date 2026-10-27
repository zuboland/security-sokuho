// 関連する投稿（その脅威について、人が何を言っているか）。速報（critical）の件だけに付ける。
//
//   hn … Hacker News（Algolia の公開API・無料・鍵なし）。記事タイトルとURL
//   x  … X（有料・pay-per-use）。SECALERT_SOCIAL に x を含め、X_BEARER_TOKEN があるときだけ呼ぶ
//        🚨 X の開発者規約では、第三者へ配ってよいのは ID・ユーザー名・URL まで（本文の再配布は不可）。
//           なので公開フィードには id／@user／URL／日時／言語だけを入れ、本文は入れない
//        🚨 Bluesky の公開検索は日本からの取得が 403（CDNで遮断・2026-10-22 実測）＝使わない
//
// 結果は data/posts/<id>.json に保存（1件1回。X の費用を固定し、公開物を安定させる）
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchJson } from '../fetch.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const POSTS_DIR = process.env.SECALERT_POSTS_DIR || path.join(here, '..', '..', 'data', 'posts');
const PROVIDERS = (process.env.SECALERT_SOCIAL || 'hn').split(',').map((s) => s.trim()).filter(Boolean);
const MAX_PER_ITEM = 5;

export const hnUrl = (q) => `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(q)}&tags=story&hitsPerPage=5`;
// 🚨 recent（直近7日）だと、発表から日が経った速報には何も付かない（2026-10-22 実測＝速報9件で X 0件）。
//    pay-per-use では全期間検索（search/all）が使えるので、発表日から14日の範囲で探す
export const xUrl = (q, { start = null, end = null, all = true } = {}) => {
  const base = all ? 'https://api.x.com/2/tweets/search/all' : 'https://api.x.com/2/tweets/search/recent';
  const p = new URLSearchParams({ query: q, max_results: '10', 'tweet.fields': 'created_at,lang,public_metrics', expansions: 'author_id', 'user.fields': 'username', sort_order: 'relevancy' });
  if (all && start) p.set('start_time', start);
  if (all && end) p.set('end_time', end);
  return `${base}?${p.toString()}`;
};

/** 検索語：悪用確認済みの CVE があればそれ、無ければ最初の CVE、無ければ製品名 */
export function queryFor(item) {
  if (item.exploited_cves?.length) return item.exploited_cves[0];
  if (item.cves?.length) return item.cves[0];
  return item.product_label || item.title || '';
}

export function parseHn(json, q) {
  // 🚨 Algolia はあいまい検索（CVE-2026-81963 で CVE-2026-18963 の Keycloak 記事が返った・2026-10-22 実測）。
  //    検索語がタイトル・URL・本文のどこかに文字どおり入っているものだけ残す
  const needle = String(q || '').toLowerCase();
  return (json?.hits || [])
    .filter((h) => h.title && (h.url || h.objectID))
    .filter((h) => !needle || `${h.title} ${h.url || ''} ${h.story_text || ''} ${h._highlightResult?.title?.value || ''}`.toLowerCase().includes(needle))
    .map((h) => ({
      source: 'hn',
      id: String(h.objectID),
      title: h.title,
      url: `https://news.ycombinator.com/item?id=${h.objectID}`,
      external_url: h.url || null,
      author: h.author || null,
      created_at: h.created_at || null,
      score: h.points ?? null,
      lang: 'en',
      query: q,
    }));
}

export function parseX(json, q) {
  const users = new Map((json?.includes?.users || []).map((u) => [u.id, u.username]));
  return (json?.data || []).map((t) => {
    const user = users.get(t.author_id) || null;
    return {
      source: 'x',
      id: String(t.id),
      author: user,
      url: user ? `https://x.com/${user}/status/${t.id}` : `https://x.com/i/status/${t.id}`,
      created_at: t.created_at || null,
      lang: t.lang || null,
      score: t.public_metrics?.like_count ?? null,
      query: q,
      // 本文は入れない（規約）
    };
  });
}

async function fetchHn(q) {
  return parseHn(await fetchJson(hnUrl(q)), q);
}

export function xWindow(published) {
  if (!published) return { start: null, end: null };
  const d = new Date(published);
  if (Number.isNaN(d.getTime())) return { start: null, end: null };
  const start = new Date(d.getTime() - 86400000);
  const end = new Date(Math.min(d.getTime() + 14 * 86400000, Date.now() - 30000)); // end_time は現在より前でないと 400
  return { start: start.toISOString(), end: end.toISOString() };
}

async function fetchX(q, published) {
  const token = process.env.X_BEARER_TOKEN;
  if (!token) return [];
  const query = `"${q}" -is:retweet (lang:ja OR lang:en)`; // リポストを除く。日本語と英語
  const headers = { authorization: `Bearer ${token}` };
  try {
    return parseX(await fetchJson(xUrl(query, xWindow(published)), { headers, retries: 0 }), q);
  } catch (e) {
    // 全期間検索が使えない契約（403）なら直近7日で代用
    if (!/HTTP 403/.test(e.message)) throw e;
    return parseX(await fetchJson(xUrl(query, { all: false }), { headers, retries: 0 }), q);
  }
}

/** 公開してよい形。X は id・author・url・source・query だけ。HN（公開API・見出し）はそのまま */
export function publicPost(p) {
  if (p?.source !== 'x') return p;
  return { source: 'x', id: p.id, author: p.author, url: p.url, query: p.query };
}

async function loadCached(id) {
  try { return JSON.parse(await readFile(path.join(POSTS_DIR, `${id}.json`), 'utf8')); } catch { return null; }
}

/** critical の件に related_posts を付ける。失敗した情報源は黙って飛ばす（速報の判定には関係ない） */
export async function attachPosts(items, { providers = PROVIDERS, maxCalls = Number(process.env.SECALERT_SOCIAL_MAX || 10) } = {}) {
  await mkdir(POSTS_DIR, { recursive: true });
  let calls = 0;
  for (const item of items) {
    item.related_posts = item.related_posts || [];
    if (item.severity !== 'critical') continue;
    const cached = await loadCached(item.id);
    // 前回失敗した情報源（X の 402 など）が今回も有効なら取り直す。それ以外はキャッシュを使う
    const retry = cached ? (cached.failed || []).filter((p) => providers.includes(p)) : [];
    const missing = cached ? providers.filter((p) => !(cached.providers || []).includes(p)) : [];
    const todo = cached ? [...new Set([...retry, ...missing])] : providers;
    if (cached && todo.length === 0) { item.related_posts = (cached.posts || []).map(publicPost); continue; }
    if (calls >= maxCalls) { if (cached) item.related_posts = (cached.posts || []).map(publicPost); continue; }
    const q = queryFor(item);
    if (!q) continue;
    calls++;
    const posts = cached ? (cached.posts || []).filter((p) => !todo.includes(p.source)) : [];
    const failed = [];
    for (const p of todo) {
      try {
        if (p === 'hn') posts.push(...(await fetchHn(q)));
        else if (p === 'x') posts.push(...(await fetchX(q, item.published)));
      } catch (e) {
        failed.push(p);
        console.warn(`[social] ${p} ${item.id}: ${e.message}`);
      }
    }
    posts.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    // X の投稿は ID・@user・URL だけを残す（いいね数・言語・日時は並べ替えにだけ使い、公開物にもキャッシュにも残さない・監査 R2）
    item.related_posts = posts.slice(0, MAX_PER_ITEM).map(publicPost);
    // 何も見つからなくても保存する（毎回同じ検索を繰り返さない。X は有料）。失敗した情報源は記録して次回だけ取り直す
    await writeFile(path.join(POSTS_DIR, `${item.id}.json`), JSON.stringify({ query: q, fetched_at: new Date().toISOString(), providers, failed, posts: item.related_posts }, null, 1) + '\n');
  }
  return items;
}
