// 判定（3値）。入っている物 × 対応表（catalog）× 影響範囲（affected・NVD）× 速報（feed）× ブラウザ（browsers）。
// 🚨 AI は使わない。比べるのは版数だけ。分からないものは unknown（「大丈夫」と言わない）。
//
// 監査（2026-10-22・R1/R2/R3）で直したこと：
//  - 材料が欠けている（NVD 未取得・CPE 未対応・版数不明・ブラウザ情報源が unknown）ときは quiet ではなく unknown
//  - 同じ製品の別インストール（Python 3.12 と 3.13・JDK 17 と 21）は別々に判定し、1つでも当たれば要対応
//  - 修正版として案内するのは end_excl だけ（end_incl は「その版も対象」）。更新 ID は検出した実体の ID
//  - 他 OS 限定の範囲（target_sw / AND 条件の OS）は Windows に当てない
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

/** Windows の常駐アプリで使ってよい範囲か（他 OS 限定の範囲を除く） */
export function appliesToWindows(r) {
  if (r.target_sw && !/^windows/i.test(r.target_sw)) return false;
  if (Array.isArray(r.os_only) && r.os_only.length && !r.os_only.some((o) => /^microsoft:windows/i.test(o))) return false;
  return true;
}

/**
 * 「入っている物」を実体ごとにまとめる。winget の ID が同じ・MSIX の同じ接頭辞・ARP の同じキーは同一実体。
 * 同じ製品でも winget の ID が違えば（Python.Python.3.12 と 3.13）別の実体＝別々に判定する。
 */
function groupInstances(product, hits) {
  const groups = new Map();
  for (const h of hits) {
    const key = h.kind === 'winget' ? `winget:${h.id}` : h.kind === 'msix' ? `msix:${h.id.replace(/^MSIX\\/, '').split('_')[0]}` : `arp:${(h.name || '').toLowerCase()}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(h);
  }
  // winget とレジストリで同じ製品が1行ずつ出るときは同一実体とみなす（版数は新しい方）。ただし winget の ID が複数あれば別実体
  const wingetKeys = [...groups.keys()].filter((k) => k.startsWith('winget:'));
  if (wingetKeys.length === 1) {
    const main = groups.get(wingetKeys[0]);
    for (const [k, v] of groups) if (!k.startsWith('winget:')) { main.push(...v); groups.delete(k); }
  }
  return [...groups.entries()].map(([key, list]) => {
    // 版数は winget の値を優先（レジストリは「3.12.10150.0」のようにビルド番号を混ぜる＝2026-10-22 実測。最大値を採ると偽の ok になる）
    const w = list.find((h) => h.kind === 'winget');
    let version = null; let raw = null;
    const wv = w ? normalizeVersion(w.version) : null;
    if (wv && parseVersion(wv)) { version = wv; raw = w.version; }
    else {
      for (const h of list) {
        const v = normalizeVersion(h.version);
        if (!v || !parseVersion(v)) continue;
        if (!version || compareVersions(v, version) > 0) { version = v; raw = h.version; }
      }
    }
    return { key, items: list, version, raw_version: raw || list.map((h) => h.version).find(Boolean) || null, winget_id: w?.id || null, available: list.map((h) => h.available).find(Boolean) || null };
  });
}

/** 1つの実体 × 1つの速報 の判定 */
function judgeInstance(inst, item, ranges, pending) {
  const cves = item.exploited_cves?.length ? item.exploited_cves : item.cves.slice(0, 3);
  if (!inst.version) return { verdict: 'unknown', why: 'version', fixed: [], also_affected: [] };
  const usable = ranges.filter(appliesToWindows);
  if (usable.length === 0) {
    // 範囲が無い理由：未取得（pending）なら分からない。取得済みで無ければ「この製品には当たらない」
    return cves.some((c) => pending.has(c)) ? { verdict: 'unknown', why: 'pending', fixed: [], also_affected: [] } : null;
  }
  const results = usable.map((r) => ({ r, hit: inRange(inst.version, r) }));
  const verdict = results.some((x) => x.hit === true) ? 'required' : results.some((x) => x.hit === null) ? 'unknown' : 'ok';
  // 修正版の案内は「当たった範囲」の end_excl だけ。end_incl は「その版も対象」として別に出す
  const matched = results.filter((x) => x.hit === true).map((x) => x.r);
  const fixed = [...new Set(matched.map((r) => r.end_excl).filter(Boolean))];
  const alsoAffected = [...new Set(matched.map((r) => r.end_incl).filter(Boolean))];
  return { verdict, why: null, fixed, also_affected: alsoAffected };
}

/**
 * @param {object} o
 * @param {Array} o.installed  parseWingetList の items（＋レジストリ由来 kind:'arp'）
 * @param {object} o.catalog   catalog.json
 * @param {object} o.affected  affected.json（cves: cve → {ranges, status}・pending: 取れなかった CVE）
 * @param {object} o.feed      feed.json（items）
 * @param {object} [o.browsers] browsers.json（chrome／edge の min_safe）
 * @returns {{products: Array, summary: object}}
 */
export function judge({ installed, catalog, affected, feed, browsers = null }) {
  const cveMap = affected?.cves || {};
  const pending = new Set(affected?.pending || []);
  const items = (feed?.items || []).filter((i) => i.severity !== 'info');
  const products = [];
  for (const p of catalog.products) {
    const hits = matchInstalled(p, installed);
    if (hits.length === 0) continue; // 入っていない物は出さない
    const cpes = new Set((p.cpe || []).map((s) => s.toLowerCase()));
    const instances = groupInstances(p, hits);
    const findings = [];

    // ブラウザは拡張と同じ材料（browsers.json の min_safe）でも判定する
    const bkey = p.key === 'chrome' ? 'chrome' : p.key === 'edge' ? 'edge' : null;
    const b = bkey ? browsers?.[bkey] : null;
    if (bkey) {
      for (const inst of instances) {
        if (!b || b.status !== 'ok') { findings.push(f(inst, { item_id: `${bkey}-source`, title: `${p.label} の悪用確認済み脆弱性の情報が取れていません`, exploited: true, severity: 'critical' }, { verdict: 'unknown', why: 'source', fixed: [], also_affected: [] })); continue; }
        if (!b.min_safe) continue; // 期間内に悪用確認済みの件なし
        const c = inst.version ? compareVersions(inst.version, b.min_safe) : null;
        const item = items.find((i) => i.id === b.alert_id) || { id: b.alert_id || `${bkey}-min_safe`, title: `${p.label} の悪用確認済み脆弱性`, exploited: true, severity: 'critical', cves: b.exploited_cves || [] };
        findings.push(f(inst, item, { verdict: c === null ? 'unknown' : c < 0 ? 'required' : 'ok', why: c === null ? 'version' : null, fixed: [b.min_safe], also_affected: [] }, 'browsers'));
      }
    }

    for (const item of items) {
      if (findings.some((x) => x.item_id === item.id)) continue; // browsers.json で既に見た件
      const cves = item.exploited_cves?.length ? item.exploited_cves : item.cves.slice(0, 3);
      const ranges = cves.flatMap((c) => (cveMap[c]?.ranges || []).map((r) => ({ ...r, cve: c }))).filter((r) => cpes.has(`${r.vendor}:${r.product}`.toLowerCase()));
      const relevantByClass = (item.products || []).includes(p.class) && p.class !== 'other';
      for (const inst of instances) {
        let res = judgeInstance(inst, item, ranges, pending);
        // 範囲が無く、この製品の種類に向けた速報で CPE の対応が無い（slack／obs）か未取得なら、黙らず unknown
        if (!res && relevantByClass && (cpes.size === 0 || cves.some((c) => pending.has(c) || !cveMap[c]))) res = { verdict: 'unknown', why: cpes.size === 0 ? 'no_cpe' : 'pending', fixed: [], also_affected: [] };
        if (!res) continue;
        findings.push(f(inst, item, res, 'nvd'));
      }
    }

    const order = { required: 0, unknown: 1, ok: 2 };
    const verdict = findings.length ? ['required', 'unknown', 'ok'].find((v) => findings.some((x) => x.verdict === v)) : 'quiet';
    const notify = findings.some((x) => x.verdict === 'required' && x.exploited);
    findings.sort((a, c) => order[a.verdict] - order[c.verdict]);
    products.push({
      key: p.key, label: p.label, class: p.class, update: p.update,
      instances: instances.map((i) => ({ key: i.key, version: i.version, raw_version: i.raw_version, winget_id: i.winget_id, available: i.available })),
      installed: hits, version: instances[0]?.version || null, raw_version: instances.map((i) => i.raw_version).filter(Boolean).join(' / ') || null,
      available: instances.map((i) => i.available).find(Boolean) || null,
      verdict, notify, findings,
    });
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

function f(inst, item, res, from = 'nvd') {
  return {
    item_id: item.id, title: item.title_ja || item.title, exploited: !!item.exploited, severity: item.severity,
    instance: inst.key, instance_version: inst.raw_version, winget_id: inst.winget_id,
    verdict: res.verdict, why: res.why, fixed: res.fixed, also_affected: res.also_affected,
    cves: item.exploited_cves?.length ? item.exploited_cves : (item.cves || []).slice(0, 3),
    action_ja: item.action_ja || '', advice_ja: item.advice_ja || [], summary_ja: item.summary_ja || null, sources: item.sources || [], from,
  };
}
