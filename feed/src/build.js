// 情報源を集めて public/*.json を出す。AIなしで動く。AI要約は summarize.js が「上に載せる」。
//
// 出すもの
//   public/feed.json      直近の全件（一覧用）
//   public/alerts.json    速報の候補（悪用確認済み かつ 一般の人に関係する製品）
//   public/browsers.json  ブラウザごとの「この版数以上なら安全」（拡張はこれだけ見れば判定できる）
//   public/status.json    生成時刻・取れなかった情報源（ここだけ毎回変わる）
//
// 🚨 feed/alerts/browsers は中身が同じなら1バイトも変わらない作りにする（2回続けて実行して2回目が変更なし）

import { mkdir, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchKev } from './sources/kev.js';
import { fetchChromeReleases } from './sources/chrome_releases.js';
import { fetchChromeStable } from './sources/versionhistory.js';
import { fetchEpss } from './sources/epss.js';
import { fetchJpcert, fetchIpa } from './sources/rss_rdf.js';
import { fetchJvn } from './sources/jvn.js';
import { fetchEdge } from './sources/edge.js';
import { classify, classLabel, actionTemplate, whoTemplate, protectAdvice, kindOf, CONSUMER_CLASSES } from './triage.js';
import { compareVersions, maxVersion } from './version.js';
import { applySummaries } from './summarize.js';
import { attachPosts } from './sources/social.js';
import { collectAffected } from './sources/nvd.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PUBLIC_DIR = process.env.SECALERT_PUBLIC || path.join(here, '..', 'public');
const WINDOW_DAYS = Number(process.env.SECALERT_WINDOW_DAYS || 90);

const dayMs = 86400000;
const toDate = (s) => (s ? new Date(s) : null);
const isoDay = (s) => (s ? new Date(s).toISOString().slice(0, 10) : null);

// 情報源ごとの「直前に取れた中身」。1つ落ちただけで既知の速報が公開物から消えないように（監査R1 F05）
export const SNAPSHOT_DIR = process.env.SECALERT_SNAPSHOT_DIR || path.join(here, '..', 'data', 'snapshots');
const snapPath = (name) => path.join(SNAPSHOT_DIR, `${name}.json`);

async function settle(name, p, { isEmpty = () => false } = {}) {
  try {
    const value = await p;
    if (isEmpty(value)) throw new Error('empty response');
    await mkdir(SNAPSHOT_DIR, { recursive: true });
    await writeFile(snapPath(name), JSON.stringify({ fetched_at: new Date().toISOString(), value }));
    return { name, ok: true, value };
  } catch (e) {
    try {
      const s = JSON.parse(await readFile(snapPath(name), 'utf8'));
      return { name, ok: false, error: e.message, value: s.value, snapshot_from: s.fetched_at };
    } catch {
      return { name, ok: false, error: e.message, value: null };
    }
  }
}

/** 共有する CVE で項目をまとめる（Chrome の投稿 ＋ KEV ＋ JPCERT が同じ件なら1件に） */
function mergeByCve(items) {
  const byCve = new Map();
  const groups = [];
  for (const it of items) {
    let target = null;
    for (const c of it.cves) if (byCve.has(c)) { target = byCve.get(c); break; }
    if (!target) { target = { ...it, sources: [...it.sources] }; groups.push(target); }
    else mergeInto(target, it);
    for (const c of target.cves) byCve.set(c, target);
  }
  return groups;
}

function mergeInto(a, b) {
  a.aliases = [...new Set([...(a.aliases || [a.id]), ...(b.aliases || [b.id])])];
  // 製品ごとの手順は失わない（Chrome と Edge が同じ CVE で1件になっても、Edge の更新手順を保持する）
  a.actions_by_product = { ...(a.actions_by_product || {}), ...(b.actions_by_product || {}) };
  a.cves = [...new Set([...a.cves, ...b.cves])].sort();
  a.sources.push(...b.sources);
  a.exploited = a.exploited || b.exploited;
  a.exploited_cves = [...new Set([...a.exploited_cves, ...b.exploited_cves])].sort();
  a.exploit_evidence = [...new Set([...a.exploit_evidence, ...b.exploit_evidence])];
  a.products = [...new Set([...a.products, ...b.products])];
  a.cwes = [...new Set([...(a.cwes || []), ...(b.cwes || [])])];
  for (const [k, v] of Object.entries(b.fixed_versions)) {
    if (!a.fixed_versions[k] || compareVersions(v, a.fixed_versions[k]) > 0) a.fixed_versions[k] = v;
  }
  if (!a.title_ja && b.title_ja) a.title_ja = b.title_ja;
  if (!a.summary_ja && b.summary_ja) a.summary_ja = b.summary_ja;
  if (!a.title && b.title) a.title = b.title;
  if (!a.summary && b.summary) a.summary = b.summary;
  if (b.published && (!a.published || b.published < a.published)) a.published = b.published;
  if (b.updated && (!a.updated || b.updated > a.updated)) a.updated = b.updated;
  // Chrome の投稿の id を優先（修正版が付いているので拡張が使う）
  if (b.id.startsWith('chrome-') && !a.id.startsWith('chrome-')) a.id = b.id;
}

function baseItem(o) {
  return {
    id: o.id,
    aliases: [o.id], // まとめられる前の id（browsers.json の alert_id がまとめ後の item を指せるように・監査R1 F07）
    title: o.title || null,
    title_ja: o.title_ja || null,
    summary: o.summary || null,
    summary_ja: o.summary_ja || null,
    action_ja: null,
    who_ja: null,
    advice_ja: [],
    kind: 'update',
    cwes: o.cwes || [],
    severity: 'info',
    exploited: !!o.exploited,
    exploited_cves: [...new Set(o.exploited_cves || [])].sort(),
    exploit_evidence: o.exploit_evidence || [],
    products: o.products || [],
    fixed_versions: o.fixed_versions || {},
    cves: [...new Set(o.cves || [])].sort(),
    epss_max: null,
    sources: o.sources || [],
    published: o.published || null,
    updated: o.updated || o.published || null,
  };
}

export function assemble({ kev, chrome, chromeStable, edge, jpcert, ipa, jvn, epss }, { now = new Date(), windowDays = WINDOW_DAYS } = {}) {
  const since = new Date(now.getTime() - windowDays * dayMs);
  const raw = [];

  for (const p of chrome || []) {
    if (!p.published || toDate(p.published) < since) continue;
    raw.push(baseItem({
      id: `chrome-${p.fixed_version || isoDay(p.published)}`,
      title: `Chrome ${p.fixed_version || ''} セキュリティ更新（${p.cves.length}件の修正）`.replace('  ', ' '),
      title_ja: null,
      summary: p.text.slice(0, 600),
      exploited: p.exploited_cves.length > 0,
      exploited_cves: p.exploited_cves,
      exploit_evidence: p.exploited_cves.map((c) => `Google: ${c} の悪用を確認（in the wild）`),
      products: ['browser-chrome'],
      fixed_versions: p.fixed_version ? { chrome: p.fixed_version } : {},
      cves: p.cves,
      sources: [{ name: 'Chrome Releases', url: p.url, date: isoDay(p.published) }],
      published: isoDay(p.published),
      updated: isoDay(p.updated),
    }));
  }

  for (const e of edge || []) {
    const d = parseEnglishDate(e.date);
    if (!d || d < since) continue;
    raw.push(baseItem({
      id: `edge-${e.fixed_version}`,
      title: `Edge ${e.fixed_version} セキュリティ更新`,
      exploited: e.exploited_cves.length > 0,
      exploited_cves: e.exploited_cves,
      exploit_evidence: e.exploited_cves.map((c) => `Microsoft: ${c} の悪用を確認（exploit in the wild）`),
      products: ['browser-edge'],
      fixed_versions: { edge: e.fixed_version },
      cves: e.cves,
      sources: [{ name: 'Microsoft Edge セキュリティ更新', url: e.url, date: isoDay(d) }],
      published: isoDay(d),
    }));
  }

  for (const k of kev?.items || []) {
    if (toDate(k.date_added) < since) continue;
    const cls = classify(k.vendor, k.product, k.description);
    raw.push(baseItem({
      id: `kev-${k.cve}`,
      title: `${k.vendor} ${k.product}：${k.name}`,
      summary: k.description,
      exploited: true,
      exploited_cves: [k.cve],
      exploit_evidence: [`CISA KEV に掲載（${k.date_added}）`],
      products: [cls],
      cwes: k.cwes,
      cves: [k.cve],
      sources: [{ name: 'CISA KEV', url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${k.cve}`, date: k.date_added }, ...k.urls.slice(0, 2).map((u) => ({ name: 'メーカー', url: u, date: k.date_added }))],
      published: k.date_added,
    }));
  }

  for (const list of [jpcert, ipa, jvn]) {
    for (const j of list || []) {
      const d = toDate(j.date);
      if (!d || d < since) continue;
      const cls = classify('', j.title, j.description);
      raw.push(baseItem({
        id: `${j.source}-${slug(j.url)}`,
        title: j.title,
        title_ja: j.title,
        summary_ja: j.description || null,
        exploited: false, // 日本語の注意喚起は手がかり。悪用確認は KEV／メーカーの文言で決める
        exploit_evidence: j.mentions_exploit ? [`${j.source.toUpperCase()} の文中に「悪用」の言及`] : [],
        products: [cls],
        cves: j.cves,
        sources: [{ name: j.source === 'jpcert' ? 'JPCERT/CC' : j.source === 'ipa' ? 'IPA' : 'JVN', url: j.url, date: isoDay(d) }],
        published: isoDay(d),
      }));
    }
  }

  // CVE が無い項目は単独のまま。CVE があるものは同じ CVE でまとめる
  const withCve = raw.filter((i) => i.cves.length > 0);
  const noCve = raw.filter((i) => i.cves.length === 0);
  const items = [...mergeByCve(withCve), ...noCve];

  for (const it of items) {
    it.products = it.products.filter((p) => p !== 'other');
    if (it.products.length === 0) it.products = ['other'];
    const consumer = it.products.some((p) => CONSUMER_CLASSES.has(p));
    const main = it.products.find((p) => CONSUMER_CLASSES.has(p)) || 'other';
    it.severity = it.exploited && consumer ? 'critical' : it.exploited ? 'high' : 'info';
    it.action_ja = actionTemplate(main, { fixedVersion: it.fixed_versions[main.replace('browser-', '')] });
    // 製品ごとの手順（1件に複数のブラウザが入ったとき用）
    it.actions_by_product = Object.fromEntries(it.products.filter((p) => CONSUMER_CLASSES.has(p)).map((p) => [p, actionTemplate(p, { fixedVersion: it.fixed_versions[p.replace('browser-', '')] })]));
    it.who_ja = whoTemplate(main);
    it.advice_ja = protectAdvice({ cls: main, text: `${it.title || ''}\n${it.title_ja || ''}\n${it.summary || ''}\n${it.summary_ja || ''}`, cwes: it.cwes, exploited: it.exploited });
    it.kind = kindOf(main, it.fixed_versions);
    it.product_label = classLabel(main);
    const scores = it.cves.map((c) => epss?.[c]?.epss).filter((x) => typeof x === 'number');
    it.epss_max = scores.length ? Math.max(...scores) : null;
    it.sources = dedupeSources(it.sources);
  }

  items.sort((a, b) => (b.published || '').localeCompare(a.published || '') || a.id.localeCompare(b.id));

  const alerts = items.filter((i) => i.severity === 'critical');
  const kevCves = new Set((kev?.items || []).map((k) => k.cve));
  // 期間内に KEV へ載ったブラウザの CVE（Chromium 系は Chrome と Edge の両方に効く）
  const kevBrowserCves = { chrome: new Set(), edge: new Set() };
  for (const k of kev?.items || []) {
    if (toDate(k.date_added) < since) continue;
    const cls = classify(k.vendor, k.product, k.description);
    // Edge の更新情報は Chromium 由来の CVE を列挙しないことが多いので、「未カバー」の検査は Edge 固有の CVE だけに掛ける
    if (cls === 'browser-chrome') kevBrowserCves.chrome.add(k.cve);
    if (cls === 'browser-edge') kevBrowserCves.edge.add(k.cve);
  }
  const browsers = buildBrowsers({ chrome, chromeStable, edge, since, kevCves, kevBrowserCves });
  // alert_id は「まとめた後の item の id」にそろえる（Edge の投稿が Chrome の item に吸われたとき）
  for (const key of ['chrome', 'edge']) {
    const b = browsers[key];
    if (!b?.alert_id) continue;
    const hit = items.find((i) => i.id === b.alert_id || (i.aliases || []).includes(b.alert_id));
    if (hit) b.alert_id = hit.id;
  }
  // Chrome／Edge の投稿にも KEV 由来の悪用確認を反映（一覧と browsers.json の食い違いをなくす）
  for (const it of items) {
    const extra = it.cves.filter((c) => kevCves.has(c) && !it.exploited_cves.includes(c));
    if (extra.length) { it.exploited_cves = [...it.exploited_cves, ...extra].sort(); it.exploited = true; it.exploit_evidence = [...new Set([...it.exploit_evidence, ...extra.map((c) => `CISA KEV に掲載（${c}）`)])]; }
    if (it.exploited) { const consumer = it.products.some((p) => CONSUMER_CLASSES.has(p)); it.severity = consumer ? 'critical' : 'high'; }
  }
  const alerts2 = items.filter((i) => i.severity === 'critical');
  return { items, alerts: alerts2, browsers };
}

function buildBrowsers({ chrome, chromeStable, edge, since, kevCves = new Set(), kevBrowserCves = { chrome: new Set(), edge: new Set() } }) {
  const out = {};
  // 悪用確認＝メーカーの「in the wild」か、CISA KEV に載った CVE（監査R2：KEV が後から確認した件が通知に反映されなかった）
  const exploitedOf = (p) => [...new Set([...(p.exploited_cves || []), ...(p.cves || []).filter((c) => kevCves.has(c))])];
  // 「期間内」の意味＝メーカーの悪用確認は投稿日、KEV の悪用確認は KEV の追加日。古い投稿でも KEV が今日載せた CVE を直していれば候補にする（監査R4-H6）
  const candidate = (p, date, kevSet) => (p.exploited_cves.length && toDate(date) >= since) || (p.cves || []).some((c) => kevSet.has(c));
  // Chrome：悪用確認つきの投稿のうち最新の修正版を「この版数以上なら安全」とする
  if (chrome) {
    const itw = chrome.map((p) => ({ ...p, exploited_cves: exploitedOf(p) })).filter((p) => p.fixed_version && candidate(p, p.published, kevBrowserCves.chrome))
      .sort((a, b) => compareVersions(b.fixed_version, a.fixed_version));
    const top = itw[0] || null;
    // KEV が期間内に載せた Chrome の CVE で、どの投稿にも修正版が無いものがあれば「分からない」（速報なしと言わない）
    const uncovered = [...kevBrowserCves.chrome].filter((c) => !chrome.some((p) => (p.cves || []).includes(c)));
    out.chrome = {
      status: uncovered.length ? 'unknown' : 'ok',
      uncovered_cves: uncovered,
      min_safe: top?.fixed_version || null,
      exploited_cves: top?.exploited_cves || [],
      alert_id: top ? `chrome-${top.fixed_version}` : null,
      alert_date: top ? isoDay(top.published) : null,
      latest_stable: chromeStable || null,
      as_of: chrome[0] ? isoDay(chrome[0].published) : null,
    };
  } else {
    out.chrome = { status: 'unknown', min_safe: null, exploited_cves: [], alert_id: null, alert_date: null, latest_stable: chromeStable || null, as_of: null };
  }
  if (edge) {
    const itw = edge.map((e) => ({ ...e, exploited_cves: exploitedOf(e) })).filter((e) => e.fixed_version && candidate(e, parseEnglishDate(e.date), kevBrowserCves.edge))
      .sort((a, b) => compareVersions(b.fixed_version, a.fixed_version));
    const top = itw[0] || null;
    const uncovered = [...kevBrowserCves.edge].filter((c) => !edge.some((e) => (e.cves || []).includes(c)));
    out.edge = {
      status: uncovered.length ? 'unknown' : 'ok',
      uncovered_cves: uncovered,
      min_safe: top?.fixed_version || null,
      exploited_cves: top?.exploited_cves || [],
      alert_id: top ? `edge-${top.fixed_version}` : null,
      alert_date: top ? isoDay(parseEnglishDate(top.date)) : null,
      latest_stable: edge[0]?.fixed_version || null,
      as_of: edge[0] ? isoDay(parseEnglishDate(edge[0].date)) : null,
    };
  } else {
    out.edge = { status: 'unknown', min_safe: null, exploited_cves: [], alert_id: null, alert_date: null, latest_stable: null, as_of: null };
  }
  out.firefox = { status: 'unknown', min_safe: null, exploited_cves: [], alert_id: null, alert_date: null, latest_stable: null, as_of: null, note: 'Firefox は次の段階で対応' };
  return out;
}

/** 「September 4, 2026」のような日付だけの文字列は UTC の0時として読む（ローカル時刻で読むと isoDay で前日にずれる） */
/**
 * メーカー投稿に無い KEV の CVE（uncovered）を NVD の範囲（google:chrome／microsoft:edge_chromium の end_excl）で埋める。
 * 埋まれば min_safe に反映して status を ok に戻す。埋まらなければ unknown のまま（速報なしと言わない）
 */
export function reconcileBrowsers(browsers, affected) {
  const cpeOf = { chrome: ['google:chrome'], edge: ['microsoft:edge_chromium', 'microsoft:edge'] };
  for (const key of ['chrome', 'edge']) {
    const b = browsers[key];
    if (!b || !b.uncovered_cves?.length) continue;
    const still = [];
    for (const cve of b.uncovered_cves) {
      const ranges = (affected?.[cve]?.ranges || []).filter((r) => cpeOf[key].includes(`${r.vendor}:${r.product}`) && r.end_excl);
      const fix = maxVersion(ranges.map((r) => r.end_excl));
      if (!fix) { still.push(cve); continue; }
      if (!b.min_safe || compareVersions(fix, b.min_safe) > 0) { b.min_safe = fix; b.alert_id = b.alert_id || `kev-${cve}`; }
      b.exploited_cves = [...new Set([...(b.exploited_cves || []), cve])];
    }
    b.uncovered_cves = still;
    b.status = still.length ? 'unknown' : 'ok';
  }
  return browsers;
}

export function parseEnglishDate(s) {
  if (!s) return null;
  const d = new Date(/\d{1,2}:\d{2}|Z$|[+-]\d{2}:\d{2}$/.test(s) ? s : `${s} UTC`);
  return Number.isNaN(d.getTime()) ? null : d;
}

function slug(url) {
  return String(url || '').replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
}

function dedupeSources(list) {
  const seen = new Set();
  return list.filter((s) => { if (!s.url || seen.has(s.url)) return false; seen.add(s.url); return true; });
}

export async function collect() {
  const since = new Date(Date.now() - WINDOW_DAYS * dayMs);
  // 🚨 取れたのに『空』は失敗と同じ扱い（空の KEV や 0 件の Chrome で min_safe=null を配信すると速報が消える）。失敗時は直前の中身（snapshot）を使う
  const results = await Promise.all([
    settle('kev', fetchKev(), { isEmpty: (v) => !v?.items || v.items.length < 100 }),
    settle('chrome_releases', fetchChromeReleases(since), { isEmpty: (v) => !Array.isArray(v) || v.length === 0 }),
    settle('versionhistory', fetchChromeStable()),
    settle('edge', fetchEdge(), { isEmpty: (v) => !Array.isArray(v) || v.length === 0 }),
    settle('jpcert', fetchJpcert()),
    settle('ipa', fetchIpa()),
    settle('jvn', fetchJvn()),
  ]);
  const got = Object.fromEntries(results.map((r) => [r.name, r.value]));
  const failed = results.filter((r) => !r.ok).map((r) => ({ source: r.name, error: r.error, using_snapshot_from: r.snapshot_from || null }));
  // 情報源ごとの「最後に正常に取れた時刻」。snapshot を使った回は古い時刻のまま＝クライアントはこれで鮮度を見る（監査R4-H2）
  const nowIso = new Date().toISOString();
  const sources = Object.fromEntries(results.map((r) => [r.name, { ok: r.ok, last_ok_at: r.ok ? nowIso : (r.snapshot_from || null) }]));
  const cves = new Set();
  for (const p of got.chrome_releases || []) p.exploited_cves.forEach((c) => cves.add(c));
  for (const k of got.kev?.items || []) cves.add(k.cve);
  const epss = cves.size ? await fetchEpss([...cves].slice(0, 300)) : {};
  return { got, failed, epss, sources };
}

function stable(obj) {
  return JSON.stringify(obj, null, 1) + '\n';
}

export async function writeOutputs({ items, alerts, browsers, failed, generatedAt, affected = {}, sources = {} }) {
  await mkdir(PUBLIC_DIR, { recursive: true });
  // 静的ページ（プライバシーポリシー等）は feed/static/ からそのまま配信に乗せる
  const staticDir = path.join(here, '..', 'static');
  try {
    const { readdir, copyFile } = await import('node:fs/promises');
    for (const f of await readdir(staticDir)) await copyFile(path.join(staticDir, f), path.join(PUBLIC_DIR, f));
  } catch { /* static が無ければ何もしない */ }
  const schema = 1;
  await writeFile(path.join(PUBLIC_DIR, 'feed.json'), stable({ schema, window_days: WINDOW_DAYS, items }));
  // 期間と「取れなかった情報源」を一緒に配る（拡張が『直近N日』を決め打ちせず、欠けを表示できるように）
  await writeFile(path.join(PUBLIC_DIR, 'alerts.json'), stable({ schema, window_days: WINDOW_DAYS, sources_failed: failed.map((f) => f.source), items: alerts }));
  await writeFile(path.join(PUBLIC_DIR, 'browsers.json'), stable({ schema, ...browsers }));
  // affected.json は fetched_at を落として安定させる（中身が同じなら変わらない）
  const aff = Object.fromEntries(Object.entries(affected).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, { published: v.published, last_modified: v.last_modified, cvss: v.cvss, status: v.status || (v.ranges?.length ? 'analyzed' : 'awaiting'), ranges: v.ranges }]));
  const pending = [...(affected.__pending || [])].sort();
  await writeFile(path.join(PUBLIC_DIR, 'affected.json'), stable({ schema, pending, cves: aff }));
  // data_as_of＝速報の根拠（Chrome Releases・KEV）のうち古い方の最終正常取得時刻。snapshot で作った回はここが古くなる
  const essential = ['chrome_releases', 'kev'].map((k) => sources[k]?.last_ok_at).filter(Boolean).map((t) => Date.parse(t));
  const dataAsOf = essential.length === 2 ? new Date(Math.min(...essential)).toISOString() : null;
  await writeFile(path.join(PUBLIC_DIR, 'status.json'), stable({ schema, generated_at: generatedAt, data_as_of: dataAsOf, sources, sources_failed: failed, counts: { items: items.length, alerts: alerts.length } }));
}

export async function main() {
  const { got, failed, epss, sources } = await collect();
  // 🚨 速報の根拠（Chrome Releases と KEV）が両方とも「今回も直前の中身も」無いときは、古い公開物を上書きしない
  if (!got.chrome_releases && !got.kev) {
    console.error('chrome_releases と kev の両方が取れなかったので public/ を更新しません:', failed);
    process.exitCode = 2;
    return;
  }
  let { items, alerts, browsers } = assemble({
    kev: got.kev, chrome: got.chrome_releases, chromeStable: got.versionhistory, edge: got.edge,
    jpcert: got.jpcert, ipa: got.ipa, jvn: got.jvn, epss,
  });
  items = await applySummaries(items); // AI 要約（SECALERT_AI=none なら何もしない）
  items = await attachPosts(items); // 関連する投稿（速報の件だけ・Hacker News は無料・X は鍵があるときだけ）
  alerts = items.filter((i) => i.severity === 'critical');
  // 影響範囲（NVD）：常駐アプリが手元の版数と比べる材料。速報と high の件だけ
  // 速報（critical）から先に取る（1回の上限に当たっても、常駐アプリが使う件から順に範囲がそろう）
  const rank = { critical: 0, high: 1 };
  const cvesForRanges = [...items].filter((i) => i.severity !== 'info').sort((a, b) => rank[a.severity] - rank[b.severity])
    .flatMap((i) => i.exploited_cves.length ? i.exploited_cves : i.cves.slice(0, 3));
  // 速報の根拠に入っていないブラウザの CVE（KEV だけが知っている）も範囲を取る
  for (const key of ['chrome', 'edge']) for (const c of browsers[key]?.uncovered_cves || []) cvesForRanges.unshift(c);
  const affected = await collectAffected(cvesForRanges);
  reconcileBrowsers(browsers, affected);
  await writeOutputs({ items, alerts, browsers, failed, generatedAt: new Date().toISOString(), affected, sources });
  console.log(`items ${items.length} / alerts ${alerts.length} / chrome min_safe ${browsers.chrome.min_safe} / edge min_safe ${browsers.edge.min_safe} / failed ${failed.map((f) => f.source).join(',') || 'none'}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((e) => { console.error(e); process.exit(1); });
}

export { readFile };
