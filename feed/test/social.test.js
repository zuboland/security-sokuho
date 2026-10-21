import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseHn, parseX, queryFor } from '../src/sources/social.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (name) => readFile(path.join(here, 'fixtures', name), 'utf8');

test('HN: 記事の見出しとURLが取れる・無ければ空', async () => {
  const hits = parseHn(JSON.parse(await fx('hn_chrome.json')), 'Chrome zero-day exploited');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].url, /^https:\/\/news\.ycombinator\.com\/item\?id=\d+$/);
  assert.equal(parseHn(JSON.parse(await fx('hn_empty.json')), 'x').length, 0);
});

test('HN: あいまい一致（別の CVE 番号）の記事は捨てる', () => {
  const json = { hits: [
    { objectID: '1', title: 'CVE-2026-18963 – Keycloak Reset-Credentials Bypass', url: 'https://example.invalid/a' },
    { objectID: '2', title: 'Windows zero-day CVE-2026-81963 exploited', url: 'https://example.invalid/b' },
  ] };
  const hits = parseHn(json, 'CVE-2026-81963');
  assert.deepEqual(hits.map((h) => h.id), ['2']);
});

test('X: 公開フィードに本文を入れない（規約）', () => {
  const posts = parseX({ data: [{ id: '1', author_id: 'u1', text: '秘密の本文', created_at: '2026-10-20T00:00:00Z', lang: 'ja', public_metrics: { like_count: 3 } }], includes: { users: [{ id: 'u1', username: 'alice' }] } }, 'CVE-1');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, 'https://x.com/alice/status/1');
  assert.ok(!('text' in posts[0]), '本文の欄が無い');
  assert.ok(!JSON.stringify(posts).includes('秘密の本文'));
});

test('検索語は悪用確認済みの CVE を優先', () => {
  assert.equal(queryFor({ exploited_cves: ['CVE-2026-2'], cves: ['CVE-2026-1', 'CVE-2026-2'] }), 'CVE-2026-2');
  assert.equal(queryFor({ exploited_cves: [], cves: ['CVE-2026-1'] }), 'CVE-2026-1');
  assert.equal(queryFor({ exploited_cves: [], cves: [], product_label: 'Windows' }), 'Windows');
});
