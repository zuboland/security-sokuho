// Microsoft Edge のセキュリティ更新ページ（HTML・RSSなし）。
// 「Microsoft Edge for Stable (Version x.y.z.w)」と「CVE-… has an exploit in the wild」を拾う。
// HTML が変わって取れないときは判定不能にする（無理に出さない）。
import { fetchText, SourceError } from '../fetch.js';
import { htmlToText } from './chrome_releases.js';

export const EDGE_URL = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security';

const CVE_RE = /CVE-\d{4}-\d{4,}/g;

export function parseEdge(html) {
  const sections = html.split(/<h2\b/i).slice(1);
  if (sections.length === 0) throw new Error('no h2 sections');
  const out = [];
  for (const raw of sections) {
    const text = htmlToText('<h2' + raw);
    const date = text.split('\n')[0]?.trim() || null;
    const vm = text.match(/Microsoft Edge for Stable \(Version (\d+\.\d+\.\d+\.\d+)\)/i);
    if (!vm) continue;
    const exploited = new Set();
    for (const s of text.split(/(?<=[.!?])\s+|\n/)) {
      if (!/exploit in the wild/i.test(s)) continue;
      for (const c of s.match(CVE_RE) || []) exploited.add(c);
    }
    out.push({
      date,
      fixed_version: vm[1],
      cves: [...new Set(text.match(CVE_RE) || [])],
      exploited_cves: [...exploited],
      url: EDGE_URL,
    });
  }
  if (out.length === 0) throw new Error('no release entries parsed');
  return out;
}

export async function fetchEdge() {
  try {
    return parseEdge(await fetchText(EDGE_URL, { timeoutMs: 60000 }));
  } catch (e) {
    throw new SourceError('edge', e.message, e);
  }
}
