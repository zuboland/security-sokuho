// 固定応答で build を2回回し、公開物が同じになる（冪等）こと・速報の形を確かめる。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const feedDir = path.join(here, '..');

async function build(publicDir) {
  const env = {
    ...process.env,
    SECALERT_FIXTURES: path.join(here, 'fixtures'),
    SECALERT_PUBLIC: publicDir,
    SECALERT_SUMMARY_DIR: path.join(publicDir, '_summaries'),
    SECALERT_POSTS_DIR: path.join(publicDir, '_posts'),
    SECALERT_AFFECTED_DIR: path.join(publicDir, '_affected'),
    SECALERT_SNAPSHOT_DIR: path.join(publicDir, '_snapshots'),
    SECALERT_XBUZZ_DIR: path.join(publicDir, '_xbuzz'),
    SECALERT_NEWS_CACHE: path.join(publicDir, '_news', 'seen.json'),
    SECALERT_XBUZZ: 'off',
    SECALERT_NVD_MAX: '20',
    SECALERT_AI: 'none',
  };
  return run(process.execPath, [path.join(feedDir, 'src', 'build.js')], { env, cwd: feedDir });
}

test('build: 2回続けて実行して公開物が1バイトも変わらない（status.json 以外）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-'));
  try {
    await build(dir);
    const first = {};
    for (const f of ['feed.json', 'alerts.json', 'browsers.json', 'affected.json']) first[f] = await readFile(path.join(dir, f), 'utf8');
    await build(dir);
    for (const f of ['feed.json', 'alerts.json', 'browsers.json', 'affected.json']) assert.equal(await readFile(path.join(dir, f), 'utf8'), first[f], `${f} が変わった`);
    const affected = JSON.parse(first['affected.json']);
    assert.ok(affected.cves['CVE-2026-87491'], 'Chrome の悪用確認済み CVE の影響範囲が入る');
    assert.equal(affected.cves['CVE-2026-87491'].ranges[0].end_excl, '153.0.8010.36');

    const feed = JSON.parse(first['feed.json']);
    const alerts = JSON.parse(first['alerts.json']);
    const browsers = JSON.parse(first['browsers.json']);
    const status = JSON.parse(await readFile(path.join(dir, 'status.json'), 'utf8'));

    assert.ok(feed.items.length > 20);
    assert.ok(feed.items.every((i) => ['critical', 'high', 'info'].includes(i.severity)));
    assert.ok(feed.items.every((i) => typeof i.action_ja === 'string' && i.action_ja.length > 0), '全件に「今やること」の定型文が付く');
    assert.ok(alerts.items.every((i) => i.severity === 'critical' && i.exploited));
    assert.equal(browsers.chrome.status, 'ok');
    assert.equal(browsers.chrome.latest_stable.win, '156.0.8078.48');
    assert.equal(browsers.edge.status, 'ok');
    assert.ok(status.sources_failed.some((f) => f.source === 'jvn'), 'JVN のメンテナンスは失敗として記録される');
    // 同じ CVE の Chrome 投稿と KEV が1件にまとまる
    const merged = feed.items.filter((i) => i.id.startsWith('chrome-') && i.sources.some((s) => s.name === 'CISA KEV'));
    assert.ok(merged.length >= 1, 'Chrome 投稿と KEV が CVE でまとまっている');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('version.js は拡張側と同じ内容', async () => {
  const a = await readFile(path.join(feedDir, 'src', 'version.js'), 'utf8');
  const b = await readFile(path.join(feedDir, '..', 'extension', 'version.js'), 'utf8');
  assert.equal(a, b);
});
