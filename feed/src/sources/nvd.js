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
  const norm = (x) => (x === undefined || x === '*' || x === '-' ? null : x);
  // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
  return { part: p[2], vendor: p[3], product: p[4], version: p[5], target_sw: norm(p[10]), target_hw: norm(p[11]) };
}

/** NVD の応答から、脆弱な（vulnerable=true）範囲だけを平らに取り出す */
export function parseNvd(json) {
  const v = json?.vulnerabilities?.[0]?.cve;
  if (!v) throw new Error('no cve in response');
  const ranges = [];
  for (const conf of v.configurations || []) {
    // AND 条件の OS（例：この欠陥は macOS 上でだけ成立）を持っておく。Windows の常駐アプリは macOS 限定の範囲を使わない（監査R1 F09）
    const osOnly = (conf.operator === 'AND')
      ? [...new Set((conf.nodes || []).flatMap((n) => (n.cpeMatch || []).map((m) => parseCpe(m.criteria)).filter((c) => c && c.part === 'o').map((c) => `${c.vendor}:${c.product}`)))]
      : [];
    for (const node of conf.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const c = parseCpe(m.criteria);
        if (!c) continue;
        ranges.push({
          part: c.part, vendor: c.vendor, product: c.product,
          target_sw: c.target_sw, // android／macos／windows など。null＝指定なし
          os_only: osOnly,
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
  // NVD の解析状態（Awaiting Analysis 等）。範囲が空のときは「未解析」と「本当に無い」を区別する材料
  const status = ranges.length ? 'analyzed' : /analyzed|modified/i.test(v.vulnStatus || '') ? 'no_ranges' : 'awaiting';
  return { cve: v.id, published: v.published || null, last_modified: v.lastModified || null, cvss, vuln_status: v.vulnStatus || null, status, ranges };
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
  const pending = []; // 頼まれたのに取れなかった CVE（上限・失敗）。常駐アプリは「範囲なし」と区別して判定不能にする
  let calls = 0;
  for (const cve of [...new Set(cves)].filter((c) => /^CVE-\d{4}-\d+$/.test(c))) {
    const cached = await loadCached(cve);
    // 未解析（範囲が空）は1日で取り直す（監査R3：NVD が翌日に範囲を足しても30日反映されなかった）
    const ttlDays = cached && cached.ranges?.length ? REFRESH_DAYS : 1;
    const fresh = cached && now - new Date(cached.fetched_at).getTime() < ttlDays * 86400000;
    if (cached && (fresh || calls >= maxCalls)) { out[cve] = cached; continue; }
    if (calls >= maxCalls) { pending.push(cve); continue; }
    calls++;
    try {
      if (calls > 1) await sleep(interval);
      const json = await fetchJson(nvdUrl(cve), { timeoutMs: 60000, retries: 1, headers: key ? { apiKey: key } : {} });
      const rec = { ...parseNvd(json), fetched_at: new Date(now).toISOString() };
      await writeFile(path.join(AFFECTED_DIR, `${cve}.json`), JSON.stringify(rec, null, 1) + '\n');
      out[cve] = rec;
    } catch (e) {
      console.warn(`[nvd] ${cve}: ${e.message}`);
      if (cached) out[cve] = cached; else pending.push(cve);
    }
  }
  Object.defineProperty(out, '__pending', { value: pending, enumerable: false });
  return out;
}
