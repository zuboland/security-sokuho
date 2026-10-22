// NVD API 2.0：CVE → 影響範囲（CPE の vendor／product と版数の範囲）。常駐アプリが「手元の版数」と比べる材料。
// 鍵なしは 5 回/30秒（公式）。鍵（NVD_API_KEY）があれば 50 回/30秒。
// 結果は data/affected/<CVE>.json に保存（1件1回。NVD 側で範囲が後から直ることがあるので 30 日経ったら取り直す）。
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchJson } from '../fetch.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const AFFECTED_DIR = process.env.SECALERT_AFFECTED_DIR || path.join(here, '..', '..', 'data', 'affected');
export const nvdUrl = (cve) => `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`;
const REFRESH_DAYS = 30;

/** cpe:2.3:part:vendor:product:version:... を分解 */
export function parseCpe(criteria) {
  const p = String(criteria || '').split(':');
  if (p.length < 6 || p[0] !== 'cpe' || p[1] !== '2.3') return null;
  return { part: p[2], vendor: p[3], product: p[4], version: p[5] };
}

/** NVD の応答から、脆弱な（vulnerable=true）範囲だけを平らに取り出す */
export function parseNvd(json) {
  const v = json?.vulnerabilities?.[0]?.cve;
  if (!v) throw new Error('no cve in response');
  const ranges = [];
  for (const conf of v.configurations || []) {
    for (const node of conf.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const c = parseCpe(m.criteria);
        if (!c) continue;
        ranges.push({
          part: c.part, vendor: c.vendor, product: c.product,
          version: c.version === '*' || c.version === '-' ? null : c.version, // 特定の版だけが対象のとき
          start_incl: m.versionStartIncluding || null,
          start_excl: m.versionStartExcluding || null,
          end_incl: m.versionEndIncluding || null,
          end_excl: m.versionEndExcluding || null,
        });
      }
    }
  }
  const cvss = v.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? v.metrics?.cvssMetricV40?.[0]?.cvssData?.baseScore ?? null;
  return { cve: v.id, published: v.published || null, last_modified: v.lastModified || null, cvss, ranges };
}

async function loadCached(cve) {
  try { return JSON.parse(await readFile(path.join(AFFECTED_DIR, `${cve}.json`), 'utf8')); } catch { return null; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * CVE の一覧の影響範囲を集める。失敗は黙って飛ばす（拡張の判定には関係ない。常駐アプリ側は「範囲なし＝判定不能」）
 * @returns {Promise<Record<string, object>>} cve → {ranges, ...}
 */
export async function collectAffected(cves, { maxCalls = Number(process.env.SECALERT_NVD_MAX || 40), now = Date.now() } = {}) {
  await mkdir(AFFECTED_DIR, { recursive: true });
  const key = process.env.NVD_API_KEY || null;
  const interval = process.env.SECALERT_FIXTURES ? 0 : key ? 700 : 6500; // 5回/30秒を守る（余裕を持たせる）。固定応答のときは待たない
  const out = {};
  let calls = 0;
  for (const cve of [...new Set(cves)].filter((c) => /^CVE-\d{4}-\d+$/.test(c))) {
    const cached = await loadCached(cve);
    const fresh = cached && now - new Date(cached.fetched_at).getTime() < REFRESH_DAYS * 86400000;
    if (cached && (fresh || calls >= maxCalls)) { out[cve] = cached; continue; }
    if (calls >= maxCalls) continue;
    calls++;
    try {
      if (calls > 1) await sleep(interval);
      const json = await fetchJson(nvdUrl(cve), { timeoutMs: 60000, retries: 1, headers: key ? { apiKey: key } : {} });
      const rec = { ...parseNvd(json), fetched_at: new Date(now).toISOString() };
      await writeFile(path.join(AFFECTED_DIR, `${cve}.json`), JSON.stringify(rec, null, 1) + '\n');
      out[cve] = rec;
    } catch (e) {
      console.warn(`[nvd] ${cve}: ${e.message}`);
      if (cached) out[cve] = cached;
    }
  }
  return out;
}
