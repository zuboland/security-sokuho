// JVN iPedia（MyJVN API）。日本語の脆弱性DB。2026-10-22 実測＝メンテナンス中（HTMLが返る）。
// 止まっていても他の情報源で動く。取れたときだけ日本語のタイトルを足す。
import { XMLParser } from 'fast-xml-parser';
import { fetchText, SourceError } from '../fetch.js';

export const JVN_URL =
  'https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n&lang=ja&maxCountItem=50';

export function parseJvn(xml) {
  const head = xml.trimStart().slice(0, 5);
  if (!head.startsWith('<?xml') && !head.startsWith('<rdf')) throw new Error('not XML (maintenance?)');
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const doc = parser.parse(xml);
  const root = doc['rdf:RDF'];
  if (!root) throw new Error('no rdf:RDF');
  let items = root.item || [];
  if (!Array.isArray(items)) items = [items];
  return items.map((it) => {
    let refs = it['sec:references'] || [];
    if (!Array.isArray(refs)) refs = [refs];
    const cves = refs
      .filter((r) => r['@_source'] === 'CVE')
      .map((r) => r['@_id'])
      .filter(Boolean);
    return {
      source: 'jvn',
      id: it['sec:identifier'] || null,
      title: String(it.title || '').trim(),
      url: String(it.link || '').trim(),
      description: String(it.description || '').trim(),
      date: it['dcterms:issued'] || it['dc:date'] || null,
      cves,
    };
  });
}

export async function fetchJvn() {
  try {
    return parseJvn(await fetchText(JVN_URL, { timeoutMs: 60000 }));
  } catch (e) {
    throw new SourceError('jvn', e.message, e);
  }
}
