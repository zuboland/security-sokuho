import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseWingetList, normalizeVersion, displayWidth } from '../ui/winget_parse.js';
import { judge, inRange, matchInstalled } from '../ui/judge.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFile(path.join(here, 'fixtures', n), 'utf8');
const catalog = JSON.parse(await readFile(path.join(here, '..', '..', 'feed', 'static', 'catalog.json'), 'utf8'));
const affected = JSON.parse(await fx('affected_sample.json'));
const feed = { items: [
  { id: 'chrome-153.0.8010.36', title: 'Chrome 153 セキュリティ更新', severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-87491'], cves: ['CVE-2026-87491'], action_ja: 'Chrome を更新', advice_ja: [] },
  { id: 'kev-CVE-2026-99999', title: '7-Zip の欠陥（テスト）', severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-99999'], cves: ['CVE-2026-99999'], action_ja: '7-Zip を更新', advice_ja: [] },
  { id: 'kev-CVE-2026-88888', title: 'VLC 3.0.23 だけの欠陥（テスト）', severity: 'high', exploited: true, exploited_cves: ['CVE-2026-88888'], cves: ['CVE-2026-88888'], action_ja: 'VLC を更新', advice_ja: [] },
  { id: 'info-1', title: '関係ない件', severity: 'info', exploited: false, exploited_cves: [], cves: ['CVE-2026-1'], action_ja: '', advice_ja: [] },
] };

test('winget list（このPCの実出力243行）を読める', async () => {
  const r = parseWingetList(await fx('winget_list.txt'));
  assert.ok(r.ok);
  assert.ok(r.items.length > 200, String(r.items.length));
  const chrome = r.items.find((i) => i.id === 'Google.Chrome');
  assert.deepEqual([chrome.kind, chrome.version, chrome.available], ['winget', '155.0.8059.85', '156.0.8078.48']);
  const sz = r.items.find((i) => i.id === '7zip.7zip');
  assert.deepEqual([sz.version, sz.available], ['26.02', '26.05']);
  const edgeMsix = r.items.find((i) => i.kind === 'msix' && i.id.includes('MicrosoftEdge.Stable'));
  assert.ok(edgeMsix, 'MSIX の Edge が取れる');
  assert.ok(r.items.filter((i) => i.kind === 'winget').every((i) => !/\s/.test(i.id)), 'winget の ID に空白が混ざらない（全角名の幅ずれ対策）');
  const brave = r.items.find((i) => i.id === 'ARP\\Machine\\X86\\BraveSoftware Brave-Browser');
  assert.ok(brave && brave.version === '155.1.97.59', 'ARP の ID は空白を含んでよい（レジストリのキー名）');
  assert.equal(r.items.length, 243, '243行すべて読める');
  assert.deepEqual([r.items.filter((i) => i.kind === 'winget').length, r.items.filter((i) => i.kind === 'msix').length, r.items.filter((i) => i.kind === 'arp').length], [96, 97, 50]);
  const zoom = r.items.find((i) => i.id.startsWith('Zoom.Zoom'));
  assert.equal(normalizeVersion(zoom.version), '7.1.9');
});

test('winget list：ヘッダーが無ければ ok:false（黙って空にしない）', () => {
  assert.equal(parseWingetList('なにもない').ok, false);
  assert.equal(displayWidth('Google Chrome'), 13);
  assert.equal(displayWidth('３Ｄ ビューアー'), 15);
});

test('判定：古い Chrome は required、7-Zip 26.02 は 26.05 未満で required、VLC 3.0.23 は特定版一致で required', async () => {
  const installed = parseWingetList(await fx('winget_list.txt')).items;
  const r = judge({ installed, catalog, affected, feed });
  const chrome = r.products.find((p) => p.key === 'chrome');
  assert.equal(chrome.verdict, 'ok', 'Chrome 155 は 153 未満ではないので ok');
  const sz = r.products.find((p) => p.key === '7zip');
  assert.equal(sz.verdict, 'required'); assert.ok(sz.notify);
  const vlc = r.products.find((p) => p.key === 'vlc');
  assert.equal(vlc.verdict, 'required');
  assert.ok(!r.products.find((p) => p.key === 'winrar'), '入っていない物は出ない');
  assert.equal(r.summary.required, 2);
});

test('判定：版数が読めなければ unknown、古い版なら required', () => {
  const installed = [{ kind: 'winget', id: 'Google.Chrome', name: 'Google Chrome', version: 'Unknown', available: null }];
  assert.equal(judge({ installed, catalog, affected, feed }).products[0].verdict, 'unknown');
  const old = [{ kind: 'winget', id: 'Google.Chrome', name: 'Google Chrome', version: '150.0.1.1', available: null }];
  const p = judge({ installed: old, catalog, affected, feed }).products[0];
  assert.equal(p.verdict, 'required'); assert.deepEqual(p.findings[0].fixed, ['153.0.8010.36']);
});

test('判定：同じ製品が2行（winget とレジストリ）なら新しい版数を採る・browsers.json で Edge も判定する', () => {
  const installed = [
    { kind: 'winget', id: 'Anthropic.Claude', name: 'Claude', version: '1.52386.0.0', available: null },
    { kind: 'arp', id: 'ARP\\User\\X64\\Claude', name: 'Claude', version: '1.0', available: null },
    { kind: 'winget', id: 'Microsoft.Edge', name: 'Microsoft Edge', version: '150.0.1.1', available: null },
  ];
  const browsers = { edge: { status: 'ok', min_safe: '152.0.4191.66', exploited_cves: ['CVE-2026-87491'], alert_id: 'chrome-153.0.8010.36' }, chrome: { status: 'ok', min_safe: null } };
  const r = judge({ installed, catalog, affected, feed, browsers });
  assert.equal(r.products.find((p) => p.key === 'claude_desktop').version, '1.52386.0.0');
  const edge = r.products.find((p) => p.key === 'edge');
  assert.equal(edge.verdict, 'required'); assert.ok(edge.notify); assert.equal(edge.findings[0].from, 'browsers');
});

test('範囲の比較：境界と「範囲なし」', () => {
  assert.equal(inRange('1.0.0', { end_excl: '1.0.0' }), false);
  assert.equal(inRange('0.9.9', { end_excl: '1.0.0' }), true);
  assert.equal(inRange('1.0.0', { end_incl: '1.0.0' }), true);
  assert.equal(inRange('2.0', { start_incl: '1.0', end_excl: '3.0' }), true);
  assert.equal(inRange('abc', { end_excl: '1.0.0' }), null);
  assert.equal(inRange('1.0.0', {}), null, '範囲の指定が無いものを「全部が対象」と読まない');
});

test('対応表：ARP の表示名とMSIX の接頭辞でも当たる', () => {
  const p = catalog.products.find((x) => x.key === 'edge');
  assert.equal(matchInstalled(p, [{ kind: 'msix', id: 'MSIX\\Microsoft.MicrosoftEdge.Stable_153.0.4234.32_neutral__8wekyb3d8bbwe', name: 'Microsoft Edge', version: '153.0.4234.32' }]).length, 1);
  const a = catalog.products.find((x) => x.key === 'acrobat_reader');
  assert.equal(matchInstalled(a, [{ kind: 'arp', id: 'ARP\\Machine\\X64\\AcroRdr', name: 'Adobe Acrobat Reader (64-bit)', version: '24.2.20857' }]).length, 1);
});
