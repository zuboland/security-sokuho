// JPCERT/CC・IPA の日本語 RSS（RDF 1.0）。
import { XMLParser } from 'fast-xml-parser';
import { fetchText, SourceError } from '../fetch.js';
import { htmlToText } from './chrome_releases.js';

export const JPCERT_URL = 'https://www.jpcert.or.jp/rss/jpcert.rdf';
export const IPA_URL = 'https://www.ipa.go.jp/security/alert-rss.rdf';

const CVE_RE = /CVE-\d{4}-\d{4,}/g;

export function parseRdf(xml, source) {
  const head = xml.trimStart().slice(0, 5);
  if (!head.startsWith('<?xml') && !head.startsWith('<rdf')) throw new Error('not XML');
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const doc = parser.parse(xml);
  const root = doc['rdf:RDF'] || doc.RDF;
  if (!root) throw new Error('no rdf:RDF');
  let items = root.item || [];
  if (!Array.isArray(items)) items = [items];
  return items.map((it) => {
    const title = String(it.title || '').trim();
    const desc = htmlToText(it.description || '');
    const text = `${title}\n${desc}`;
    return {
      source,
      title,
      url: String(it.link || it['@_rdf:about'] || '').trim(),
      description: desc,
      date: it['dc:date'] || it['dcterms:issued'] || null,
      cves: [...new Set(text.match(CVE_RE) || [])],
      // 本文に「悪用」があれば悪用確認の手がかりにする（確定ではない。KEV／メーカーの文言が正）
      mentions_exploit: /悪用|攻撃を確認|exploit/i.test(text),
    };
  });
}

export async function fetchJpcert() {
  try {
    return parseRdf(await fetchText(JPCERT_URL), 'jpcert').filter((i) => /\/at\//.test(i.url)); // 注意喚起だけ（Weekly Report は除く）
  } catch (e) {
    throw new SourceError('jpcert', e.message, e);
  }
}

export async function fetchIpa() {
  try {
    return parseRdf(await fetchText(IPA_URL), 'ipa');
  } catch (e) {
    throw new SourceError('ipa', e.message, e);
  }
}
