// Chrome Releases ブログ（Stable updates）。投稿ごとに「修正版の版数」と「直したCVE」と「悪用確認（in the wild）」が取れる。
// CISA KEV より早い一次情報。
import { fetchJson, SourceError } from '../fetch.js';
import { minVersion } from '../version.js';

// 🚨 Blogger のラベル付きフィードは max-results=100 でも1ページ37件しか返さない（2026-10-22 実測）。
// 90日分（週5件前後）を覆うには start-index でページをめくる必要がある
export const CHROME_RELEASES_URL =
  'https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=json&max-results=100';
const MAX_PAGES = 4;

const VERSION_RE = /\b\d+\.\d+\.\d+\.\d+\b/g;
const CVE_RE = /CVE-\d{4}-\d{4,}/g;

export function htmlToText(html) {
  return String(html || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|h\d)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n')
    .trim();
}

/** 悪用を否定する言い回し（これがある文は悪用確認に使わない・監査R1 F08） */
export const NEGATION_RE = /\bnot aware\b|\bno (known )?(reports?|evidence)\b|\bnot (been )?(exploited|observed)\b|\bunaware\b|\bno exploit/i;

/** 「in the wild」を含む肯定文に出てくる CVE を悪用確認済みとして拾う */
export function findExploitedCves(text) {
  const out = new Set();
  const sentences = text.split(/(?<=[.!?])\s+|\n/);
  for (const s of sentences) {
    if (!/in the wild/i.test(s)) continue;
    if (NEGATION_RE.test(s)) continue;
    for (const c of s.match(CVE_RE) || []) out.add(c);
  }
  return [...out];
}

export function parseChromeReleases(json) {
  const entries = json?.feed?.entry;
  if (!Array.isArray(entries)) throw new Error('unexpected shape');
  const posts = [];
  for (const e of entries) {
    const title = e.title?.$t || '';
    // デスクトップ版だけ（Android／iOS／ChromeOS は別物）
    if (!/Stable Channel Update for Desktop/i.test(title)) continue;
    const text = htmlToText(e.content?.$t || '');
    const versions = [...new Set(text.match(VERSION_RE) || [])];
    const cves = [...new Set(text.match(CVE_RE) || [])];
    const link = (e.link || []).find((l) => l.rel === 'alternate')?.href || null;
    posts.push({
      id: e.id?.$t || link,
      title,
      url: link,
      published: e.published?.$t || null,
      updated: e.updated?.$t || null,
      fixed_version: minVersion(versions), // Win/Mac/Linux で末尾が違うことがあるので最小を修正版とする
      versions,
      cves,
      exploited_cves: findExploitedCves(text),
      text,
    });
  }
  return posts;
}

/** since（Date）より古い投稿が出るまでページをめくる。同じ id は1回だけ */
export async function fetchChromeReleases(since = null) {
  try {
    const seen = new Set();
    const posts = [];
    let startIndex = 1;
    for (let page = 0; page < MAX_PAGES; page++) {
      const json = await fetchJson(`${CHROME_RELEASES_URL}&start-index=${startIndex}`);
      const entries = json?.feed?.entry || [];
      if (!Array.isArray(json?.feed?.entry) && page === 0) throw new Error('unexpected shape');
      let added = 0;
      for (const p of parseChromeReleases({ feed: { entry: entries } })) {
        if (seen.has(p.id)) continue;
        seen.add(p.id);
        posts.push(p);
        added++;
      }
      const oldest = entries.at(-1)?.published?.$t;
      if (entries.length === 0 || added === 0) break; // 固定応答や終端では同じものが返る
      if (since && oldest && new Date(oldest) < since) break;
      startIndex += entries.length;
    }
    return posts;
  } catch (e) {
    throw new SourceError('chrome_releases', e.message, e);
  }
}
