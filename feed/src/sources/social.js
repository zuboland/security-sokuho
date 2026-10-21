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
export const xUrl = (q) => `https://api.x.com/2/tweets/search/recent?query=${encodeURIComponent(q)}&max_results=10&tweet.fields=created_at,lang,public_metrics&expansions=author_id&user.fields=username`;

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

async function fetchX(q) {
  const token = process.env.X_BEARER_TOKEN;
  if (!token) return [];
  // リポストを除く。日本語と英語
  const json = await fetchJson(xUrl(`"${q}" -is:retweet (lang:ja OR lang:en)`), { headers: { authorization: `Bearer ${token}` } });
  return parseX(json, q);
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
    if (cached) { item.related_posts = cached.posts; continue; }
    if (calls >= maxCalls) continue;
    const q = queryFor(item);
    if (!q) continue;
    calls++;
    const posts = [];
    for (const p of providers) {
      try {
        if (p === 'hn') posts.push(...(await fetchHn(q)));
        else if (p === 'x') posts.push(...(await fetchX(q)));
      } catch (e) {
        console.warn(`[social] ${p} ${item.id}: ${e.message}`);
      }
    }
    posts.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    item.related_posts = posts.slice(0, MAX_PER_ITEM);
    // 何も見つからなくても保存する（毎回同じ検索を繰り返さない。X は有料）
    await writeFile(path.join(POSTS_DIR, `${item.id}.json`), JSON.stringify({ query: q, fetched_at: new Date().toISOString(), posts: item.related_posts }, null, 1) + '\n');
  }
  return items;
}
