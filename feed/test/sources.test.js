// 実データ（2026-10-22 に保存した固定応答）で、各情報源の解析が意図どおり動くか。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseKev } from '../src/sources/kev.js';
import { parseChromeReleases } from '../src/sources/chrome_releases.js';
import { parseRdf } from '../src/sources/rss_rdf.js';
import { parseJvn } from '../src/sources/jvn.js';
import { parseEdge } from '../src/sources/edge.js';
import { compareVersions } from '../src/version.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (name) => readFile(path.join(here, 'fixtures', name), 'utf8');

test('KEV: 件数と Chrome の悪用確認件数', async () => {
  const items = parseKev(JSON.parse(await fx('kev.json')));
  assert.ok(items.length > 500);
  const chrome2025 = items.filter((i) => i.vendor === 'Google' && i.date_added >= '2025-01-01' && i.date_added < '2026-01-01');
  assert.equal(chrome2025.length, 7, '2025年の Google（Chrome）の KEV 入りは 7 件');
  assert.ok(items.every((i) => /^CVE-\d{4}-\d+$/.test(i.cve)));
});

test('Chrome Releases: デスクトップ投稿だけ・版数とCVEが取れる', async () => {
  const posts = parseChromeReleases(JSON.parse(await fx('chromereleases.json')));
  assert.ok(posts.length >= 2);
  assert.ok(posts.every((p) => /Desktop/.test(p.title)));
  const top = posts[0];
  assert.equal(top.fixed_version, '156.0.8078.47');
  assert.ok(top.cves.length > 0);
  assert.ok(posts.every((p) => p.fixed_version === null || p.versions.every((v) => compareVersions(p.fixed_version, v) <= 0)), '修正版は投稿内の最小の版数');
});

test('JPCERT RDF: 注意喚起が日本語で取れる', async () => {
  const items = parseRdf(await fx('jpcert.rdf'), 'jpcert');
  assert.ok(items.length > 5);
  assert.ok(items.some((i) => /jpcert\.or\.jp\/at\//.test(i.url)));
  assert.ok(items.every((i) => i.title.length > 0));
});

test('IPA RDF: 注意喚起が取れる', async () => {
  const items = parseRdf(await fx('ipa.rdf'), 'ipa');
  assert.ok(items.length > 3);
  assert.ok(items.some((i) => /1021-jre/.test(i.url)), '2026-10-21 の Java の注意喚起が入っている');
});

test('JVN: メンテナンス画面（HTTP 200 の HTML）は失敗として扱う', async () => {
  const html = await fx('jvn_maintenance.html');
  assert.throws(() => parseJvn(html), /not XML/);
});

test('Edge: 版数と exploit in the wild の CVE が取れる', async () => {
  const entries = parseEdge(await fx('edge.html'));
  assert.ok(entries.length > 10);
  assert.match(entries[0].fixed_version, /^\d+\.\d+\.\d+\.\d+$/);
  const itw = entries.filter((e) => e.exploited_cves.length > 0);
  assert.ok(itw.length > 0, '悪用確認つきの更新が1つはある');
  assert.ok(itw.some((e) => e.exploited_cves.includes('CVE-2026-87491')), '2026-09-04 の CVE-2026-87491 を拾う');
});
