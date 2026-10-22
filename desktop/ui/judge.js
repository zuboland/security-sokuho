// 判定（3値）。入っている物 × 対応表（catalog）× 影響範囲（affected・NVD）× 速報（feed）。
// 🚨 AI は使わない。比べるのは版数だけ。分からないものは unknown（「大丈夫」と言わない）。
import { compareVersions, parseVersion } from './shared/version.js';
import { normalizeVersion } from './winget_parse.js';

/** 対応表の1製品に当たる「入っている物」を探す */
export function matchInstalled(product, installed) {
  const hits = [];
  for (const it of installed) {
    if (it.kind === 'winget' && product.winget.includes(it.id)) hits.push(it);
    else if (it.kind === 'msix' && product.msix.some((p) => it.id.replace(/^MSIX\\/, '').startsWith(p))) hits.push(it);
    else if (it.kind === 'arp' && product.arp.some((re) => new RegExp(re, 'i').test(it.name || ''))) hits.push(it);
  }
  return hits;
}

/** 版数が範囲の中か。true／false／null（比べられない） */
export function inRange(version, r) {
  if (r.version) { const c = compareVersions(version, r.version); return c === null ? null : c === 0; }
  const checks = [
    r.start_incl ? [compareVersions(version, r.start_incl), (c) => c >= 0] : null,
    r.start_excl ? [compareVersions(version, r.start_excl), (c) => c > 0] : null,
    r.end_incl ? [compareVersions(version, r.end_incl), (c) => c <= 0] : null,
    r.end_excl ? [compareVersions(version, r.end_excl), (c) => c < 0] : null,
  ].filter(Boolean);
  if (checks.length === 0) return null; // 範囲の指定が無い＝「全部」とは読まない（分からない扱い）
  for (const [c, ok] of checks) { if (c === null) return null; if (!ok(c)) return false; }
  return true;
}

/**
 * @param {object} o
 * @param {Array} o.installed  parseWingetList の items（＋レジストリ由来 kind:'arp'）
 * @param {object} o.catalog   catalog.json
 * @param {object} o.affected  affected.json（cves: cve → {ranges}）
 * @param {object} o.feed      feed.json（items）
 * @returns {{products: Array, summary: object}}
 */
export function judge({ installed, catalog, affected, feed, browsers = null }) {
  const cveMap = affected?.cves || {};
  const products = [];
  for (const p of catalog.products) {
    const hits = matchInstalled(p, installed);
    if (hits.length === 0) continue; // 入っていない物は出さない
    const cpes = new Set(p.cpe.map((s) => s.toLowerCase()));
    // 同じ製品が winget とレジストリの両方に出るとき、いちばん新しい版数を採る
    // （2026-10-22 実測＝Claude デスクトップが winget 1.52386.0.0 とレジストリ 1.0 の2行。先頭を採ると偽の要対応になる）
    let rawVersion = null; let version = null;
    for (const h of hits) {
      const v = normalizeVersion(h.version);
      if (!v || !parseVersion(v)) continue;
      if (!version || compareVersions(v, version) > 0) { version = v; rawVersion = h.version; }
    }
    if (!rawVersion) rawVersion = hits.map((h) => h.version).find(Boolean) || null;
    const findings = [];
    // ブラウザは拡張と同じ材料（browsers.json の min_safe）でも判定する。NVD の CPE が Chrome だけで Edge に付かない件があるため
    const bkey = p.key === 'chrome' ? 'chrome' : p.key === 'edge' ? 'edge' : null;
    const b = bkey ? browsers?.[bkey] : null;
    if (b && b.status === 'ok' && b.min_safe) {
      const c = version ? compareVersions(version, b.min_safe) : null;
      const verdict = c === null ? 'unknown' : c < 0 ? 'required' : 'ok';
      const item = (feed.items || []).find((i) => i.id === b.alert_id) || null;
      findings.push({ item_id: b.alert_id || `${bkey}-min_safe`, title: item?.title_ja || item?.title || `${p.label} の悪用確認済み脆弱性`, exploited: true, severity: 'critical', verdict, fixed: [b.min_safe], cves: b.exploited_cves || [], action_ja: item?.action_ja || '', advice_ja: item?.advice_ja || [], summary_ja: item?.summary_ja || null, sources: item?.sources || [], from: 'browsers' });
    }
    for (const item of feed.items || []) {
      if (item.severity === 'info') continue;
      const cves = item.exploited_cves?.length ? item.exploited_cves : item.cves.slice(0, 3);
      const ranges = cves.flatMap((c) => (cveMap[c]?.ranges || []).map((r) => ({ ...r, cve: c })))
        .filter((r) => cpes.has(`${r.vendor}:${r.product}`.toLowerCase()));
      if (ranges.length === 0) continue;
      if (findings.some((f) => f.item_id === item.id)) continue; // browsers.json で既に見た件
      let verdict;
      if (!version || !parseVersion(version)) verdict = 'unknown';
      else {
        const results = ranges.map((r) => inRange(version, r));
        verdict = results.some((x) => x === true) ? 'required' : results.some((x) => x === null) ? 'unknown' : 'ok';
      }
      findings.push({ item_id: item.id, title: item.title_ja || item.title, exploited: !!item.exploited, severity: item.severity, verdict, fixed: ranges.map((r) => r.end_excl || r.end_incl).filter(Boolean), cves: [...new Set(ranges.map((r) => r.cve))], action_ja: item.action_ja, advice_ja: item.advice_ja || [], summary_ja: item.summary_ja || null, sources: item.sources || [] });
    }
    const verdict = findings.some((f) => f.verdict === 'required') ? 'required' : findings.some((f) => f.verdict === 'unknown') ? 'unknown' : findings.length ? 'ok' : 'quiet';
    const notify = findings.some((f) => f.verdict === 'required' && f.exploited);
    products.push({ key: p.key, label: p.label, class: p.class, update: p.update, installed: hits, version, raw_version: rawVersion, available: hits.map((h) => h.available).find(Boolean) || null, verdict, notify, findings });
  }
  const order = { required: 0, unknown: 1, ok: 2, quiet: 3 };
  products.sort((a, b) => order[a.verdict] - order[b.verdict] || a.label.localeCompare(b.label, 'ja'));
  const summary = {
    required: products.filter((p) => p.verdict === 'required').length,
    unknown: products.filter((p) => p.verdict === 'unknown').length,
    ok: products.filter((p) => p.verdict === 'ok').length,
    quiet: products.filter((p) => p.verdict === 'quiet').length,
    watched: products.length,
    notify: products.filter((p) => p.notify).map((p) => p.key),
  };
  return { products, summary };
}
