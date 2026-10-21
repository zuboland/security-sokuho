// CISA KEV（悪用が確認された脆弱性の一覧）。公式JSON。
import { fetchJson, SourceError } from '../fetch.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export function parseKev(json) {
  if (!json || !Array.isArray(json.vulnerabilities)) throw new Error('unexpected shape');
  return json.vulnerabilities.map((v) => ({
    cve: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    description: v.shortDescription,
    date_added: v.dateAdded,
    due_date: v.dueDate,
    ransomware: v.knownRansomwareCampaignUse,
    cwes: Array.isArray(v.cwes) ? v.cwes : [],
    urls: String(v.notes || '')
      .split(';')
      .map((s) => s.trim())
      .filter((s) => /^https?:\/\//.test(s)),
  }));
}

export async function fetchKev() {
  try {
    const json = await fetchJson(KEV_URL, { timeoutMs: 60000 });
    return { released: json.dateReleased, items: parseKev(json) };
  } catch (e) {
    throw new SourceError('kev', e.message, e);
  }
}
