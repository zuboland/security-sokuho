import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseNvd, parseCpe } from '../src/sources/nvd.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (name) => readFile(path.join(here, 'fixtures', name), 'utf8');

test('NVD: Chrome の CVE から vendor/product と修正版（end_excl）が取れる', async () => {
  const r = parseNvd(JSON.parse(await fx('nvd_CVE-2026-87491.json')));
  assert.equal(r.cve, 'CVE-2026-87491');
  const g = r.ranges.find((x) => x.vendor === 'google' && x.product === 'chrome');
  assert.ok(g);
  assert.equal(g.end_excl, '153.0.8010.36');
  assert.equal(g.part, 'a');
});

test('NVD: macOS の CVE は複数の系統（14／15／26）の範囲が別々に出る', async () => {
  const r = parseNvd(JSON.parse(await fx('nvd_CVE-2026-65400.json')));
  const ends = r.ranges.filter((x) => x.product === 'macos').map((x) => x.end_excl).sort();
  assert.ok(ends.includes('14.8.9') && ends.includes('15.7.9') && ends.includes('26.6.1'), ends.join(','));
});

test('NVD: 形違い・CPE の分解', () => {
  assert.throws(() => parseNvd({}), /no cve/);
  assert.deepEqual(parseCpe('cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*'), { part: 'a', vendor: 'google', product: 'chrome', version: '*' });
  assert.equal(parseCpe('nonsense'), null);
});
