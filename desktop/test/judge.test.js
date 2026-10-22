import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseWingetList, normalizeVersion, displayWidth } from '../ui/winget_parse.js';
import { judge, inRange, matchInstalled, appliesToWindows } from '../ui/judge.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFile(path.join(here, 'fixtures', n), 'utf8');
const catalog = JSON.parse(await readFile(path.join(here, '..', '..', 'feed', 'static', 'catalog.json'), 'utf8'));
const affected = JSON.parse(await fx('affected_sample.json'));
const browsersOk = { chrome: { status: 'ok', min_safe: null, exploited_cves: [], alert_id: null }, edge: { status: 'ok', min_safe: null, exploited_cves: [], alert_id: null } };
const feed = { items: [
  { id: 'chrome-153.0.8010.36', title: 'Chrome 153 セキュリティ更新', products: ['browser-chrome'], severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-87491'], cves: ['CVE-2026-87491'], action_ja: 'Chrome を更新', advice_ja: [] },
  { id: 'kev-CVE-2026-99999', title: '7-Zip の欠陥（テスト）', products: ['archiver'], severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-99999'], cves: ['CVE-2026-99999'], action_ja: '7-Zip を更新', advice_ja: [] },
  { id: 'kev-CVE-2026-88888', title: 'VLC 3.0.23 だけの欠陥（テスト）', products: ['other'], severity: 'high', exploited: true, exploited_cves: ['CVE-2026-88888'], cves: ['CVE-2026-88888'], action_ja: 'VLC を更新', advice_ja: [] },
  { id: 'info-1', title: '関係ない件', products: ['other'], severity: 'info', exploited: false, exploited_cves: [], cves: ['CVE-2026-1'], action_ja: '', advice_ja: [] },
] };
const J = (o) => judge({ catalog, affected, feed, browsers: browsersOk, ...o });

test('winget list（このPCの実出力243行）を読める', async () => {
  const r = parseWingetList(await fx('winget_list.txt'));
  assert.ok(r.ok);
  assert.equal(r.items.length, 243, '243行すべて読める');
  assert.deepEqual([r.items.filter((i) => i.kind === 'winget').length, r.items.filter((i) => i.kind === 'msix').length, r.items.filter((i) => i.kind === 'arp').length], [96, 97, 50]);
  const chrome = r.items.find((i) => i.id === 'Google.Chrome');
  assert.deepEqual([chrome.kind, chrome.version, chrome.available], ['winget', '155.0.8059.85', '156.0.8078.48']);
  const sz = r.items.find((i) => i.id === '7zip.7zip');
  assert.deepEqual([sz.version, sz.available], ['26.02', '26.05']);
  assert.ok(r.items.find((i) => i.kind === 'msix' && i.id.includes('MicrosoftEdge.Stable')), 'MSIX の Edge が取れる');
  assert.ok(r.items.filter((i) => i.kind === 'winget').every((i) => !/\s/.test(i.id)), 'winget の ID に空白が混ざらない');
  const brave = r.items.find((i) => i.id === 'ARP\\Machine\\X86\\BraveSoftware Brave-Browser');
  assert.ok(brave && brave.version === '155.1.97.59', 'ARP の ID は空白を含んでよい（レジストリのキー名）');
  assert.equal(normalizeVersion(r.items.find((i) => i.id.startsWith('Zoom.Zoom')).version), '7.1.9');
});

test('winget list：「利用可能」列が無い（全部最新）表も読める・ヘッダーが無ければ ok:false', () => {
  const r = parseWingetList('Name           Id             Version        Source\n-----------------------------------------------------\nGoogle Chrome  Google.Chrome  156.0.8078.47  winget\n');
  assert.ok(r.ok); assert.equal(r.items.length, 1); assert.equal(r.items[0].available, null); assert.equal(r.items[0].source, 'winget');
  assert.equal(parseWingetList('なにもない').ok, false);
  assert.equal(displayWidth('Google Chrome'), 13);
  assert.equal(displayWidth('３Ｄ ビューアー'), 15);
});

test('判定：古い Chrome は required、7-Zip 26.02 は 26.05 未満で required、VLC 3.0.23 は特定版一致で required', async () => {
  const installed = parseWingetList(await fx('winget_list.txt')).items;
  const r = J({ installed });
  assert.equal(r.products.find((p) => p.key === 'chrome').verdict, 'ok', 'Chrome 155 は 153 未満ではないので ok');
  const sz = r.products.find((p) => p.key === '7zip');
  assert.equal(sz.verdict, 'required'); assert.ok(sz.notify); assert.deepEqual(sz.findings[0].fixed, ['26.05']);
  assert.equal(r.products.find((p) => p.key === 'vlc').verdict, 'required');
  assert.ok(!r.products.find((p) => p.key === 'winrar'), '入っていない物は出ない');
  assert.equal(r.summary.required, 2);
});

test('判定：材料が無ければ unknown（quiet にしない）', () => {
  const sz = [{ kind: 'winget', id: '7zip.7zip', name: '7-Zip', version: '26.02', available: null }];
  // NVD が未取得（pending）
  let r = J({ installed: sz, affected: { cves: {}, pending: ['CVE-2026-99999'] } });
  assert.equal(r.products[0].verdict, 'unknown'); assert.equal(r.products[0].findings[0].why, 'pending');
  // 範囲が無くて pending でもない（取得済み・本当に無い）＝その製品には当たらない → quiet
  r = J({ installed: sz, affected: { cves: { 'CVE-2026-99999': { ranges: [] } }, pending: [] } });
  assert.equal(r.products[0].verdict, 'quiet');
  // 版数が読めない
  r = J({ installed: [{ kind: 'winget', id: 'Google.Chrome', name: 'Google Chrome', version: 'Unknown', available: null }] });
  assert.equal(r.products[0].verdict, 'unknown'); assert.equal(r.products[0].findings[0].why, 'version');
  // ブラウザの情報源が unknown
  r = J({ installed: [{ kind: 'winget', id: 'Microsoft.Edge', name: 'Microsoft Edge', version: '150.0.1.1', available: null }], browsers: { ...browsersOk, edge: { status: 'unknown', min_safe: null, exploited_cves: [], alert_id: null } } });
  assert.equal(r.products[0].verdict, 'unknown'); assert.equal(r.products[0].findings[0].why, 'source');
  // CPE の対応表が無い製品（slack）に、その種類向けの速報があれば unknown
  r = J({ installed: [{ kind: 'winget', id: 'SlackTechnologies.Slack', name: 'Slack', version: '4.0.0', available: null }], feed: { items: [{ id: 'kev-x', title: 'Slack の欠陥', products: ['messaging'], severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-77777'], cves: ['CVE-2026-77777'] }] }, affected: { cves: {}, pending: [] } });
  assert.equal(r.products[0].verdict, 'unknown'); assert.equal(r.products[0].findings[0].why, 'no_cpe');
});

test('判定：同じ製品の別インストール（別の winget ID）は別々に見て、1つでも当たれば required・更新 ID は当たった実体のもの', () => {
  const installed = [
    { kind: 'winget', id: 'Python.Python.3.12', name: 'Python 3.12', version: '3.12.0', available: '3.12.10' },
    { kind: 'winget', id: 'Python.Python.3.13', name: 'Python 3.13', version: '3.13.5', available: null },
  ];
  const aff = { cves: { 'CVE-2026-55555': { ranges: [{ part: 'a', vendor: 'python', product: 'python', start_incl: '3.12.0', end_excl: '3.12.10' }] } }, pending: [] };
  const fd = { items: [{ id: 'kev-py', title: 'Python の欠陥', products: ['other'], severity: 'critical', exploited: true, exploited_cves: ['CVE-2026-55555'], cves: ['CVE-2026-55555'] }] };
  const r = J({ installed, affected: aff, feed: fd });
  const py = r.products.find((p) => p.key === 'python');
  assert.equal(py.verdict, 'required'); assert.equal(py.instances.length, 2);
  const req = py.findings.find((f) => f.verdict === 'required');
  assert.equal(req.winget_id, 'Python.Python.3.12'); assert.equal(req.instance_version, '3.12.0');
  assert.equal(py.findings.find((f) => f.instance_version === '3.13.5').verdict, 'ok');
});

test('判定：同じ実体が winget とレジストリで2行なら新しい版数を採る・browsers.json で Edge も判定', () => {
  const installed = [
    { kind: 'winget', id: 'Anthropic.Claude', name: 'Claude', version: '1.52386.0.0', available: null },
    { kind: 'arp', id: 'ARP\\User\\X64\\Claude', name: 'Claude', version: '1.0', available: null },
    { kind: 'winget', id: 'Microsoft.Edge', name: 'Microsoft Edge', version: '150.0.1.1', available: null },
  ];
  const browsers = { ...browsersOk, edge: { status: 'ok', min_safe: '152.0.4191.66', exploited_cves: ['CVE-2026-87491'], alert_id: 'chrome-153.0.8010.36' } };
  const r = J({ installed, browsers });
  assert.equal(r.products.find((p) => p.key === 'claude_desktop').version, '1.52386.0.0');
  // レジストリの「3.12.10150.0」（ビルド番号混じり）より winget の「3.12.10」を採る
  const py = J({ installed: [{ kind: 'winget', id: 'Python.Python.3.12', name: 'Python 3.12', version: '3.12.10', available: null }, { kind: 'arp', id: 'ARP\\User\\X64\\{py}', name: 'Python 3.12.10 (64-bit)', version: '3.12.10150.0', available: null }] });
  assert.equal(py.products.find((p) => p.key === 'python').version, '3.12.10');
  const edge = r.products.find((p) => p.key === 'edge');
  assert.equal(edge.verdict, 'required'); assert.ok(edge.notify); assert.equal(edge.findings[0].from, 'browsers');
});

test('範囲の比較：境界・「範囲なし」・end_incl は修正版にしない・他OS限定は Windows に当てない', () => {
  assert.equal(inRange('1.0.0', { end_excl: '1.0.0' }), false);
  assert.equal(inRange('0.9.9', { end_excl: '1.0.0' }), true);
  assert.equal(inRange('1.0.0', { end_incl: '1.0.0' }), true);
  assert.equal(inRange('2.0', { start_incl: '1.0', end_excl: '3.0' }), true);
  assert.equal(inRange('abc', { end_excl: '1.0.0' }), null);
  assert.equal(inRange('1.0.0', {}), null, '範囲の指定が無いものを「全部が対象」と読まない');
  const sz = [{ kind: 'winget', id: '7zip.7zip', name: '7-Zip', version: '26.02', available: null }];
  const r = J({ installed: sz, affected: { cves: { 'CVE-2026-99999': { ranges: [{ part: 'a', vendor: '7-zip', product: '7-zip', end_incl: '26.05' }] } }, pending: [] } });
  assert.equal(r.products[0].verdict, 'required'); assert.deepEqual(r.products[0].findings[0].fixed, []); assert.deepEqual(r.products[0].findings[0].also_affected, ['26.05']);
  assert.equal(appliesToWindows({ target_sw: 'android' }), false);
  assert.equal(appliesToWindows({ target_sw: null, os_only: ['apple:macos'] }), false);
  assert.equal(appliesToWindows({ target_sw: 'windows', os_only: [] }), true);
  const vlc = [{ kind: 'winget', id: 'VideoLAN.VLC', name: 'VLC', version: '3.0.23', available: null }];
  const r2 = J({ installed: vlc, affected: { cves: { 'CVE-2026-88888': { ranges: [{ part: 'a', vendor: 'videolan', product: 'vlc_media_player', version: '3.0.23', target_sw: 'android' }] } }, pending: [] } });
  assert.equal(r2.products[0].verdict, 'quiet', 'Android 限定の範囲は Windows に当てない');
});

test('対応表：ARP の表示名とMSIX の接頭辞でも当たる・Acrobat Pro を Reader にしない', () => {
  const p = catalog.products.find((x) => x.key === 'edge');
  assert.equal(matchInstalled(p, [{ kind: 'msix', id: 'MSIX\\Microsoft.MicrosoftEdge.Stable_153.0.4234.32_neutral__8wekyb3d8bbwe', name: 'Microsoft Edge', version: '153.0.4234.32' }]).length, 1);
  const a = catalog.products.find((x) => x.key === 'acrobat_reader');
  assert.equal(matchInstalled(a, [{ kind: 'arp', id: 'ARP\\Machine\\X64\\AcroRdr', name: 'Adobe Acrobat Reader (64-bit)', version: '24.2.20857' }]).length, 1);
  assert.equal(matchInstalled(a, [{ kind: 'arp', id: 'ARP\\Machine\\X64\\AcroPro', name: 'Adobe Acrobat Pro', version: '24.2.20857' }]).length, 0);
});
