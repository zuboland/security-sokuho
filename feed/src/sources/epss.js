// EPSS（悪用される見込みの点数 0〜1）。FIRST の公開API。100件ずつ。
import { fetchJson } from '../fetch.js';

export const epssUrl = (cves) => `https://api.first.org/data/v1/epss?cve=${cves.join(',')}`;

export async function fetchEpss(cves) {
  const out = {};
  const unique = [...new Set(cves)].filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  for (let i = 0; i < unique.length; i += 100) {
    const chunk = unique.slice(i, i + 100);
    try {
      const json = await fetchJson(epssUrl(chunk));
      for (const d of json?.data || []) {
        out[d.cve] = { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date };
      }
    } catch {
      // EPSS は飾り。取れなくても判定は変えないので黙って飛ばす（status に残すのは呼び出し側）
    }
  }
  return out;
}
