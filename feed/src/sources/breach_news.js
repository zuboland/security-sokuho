// 日本の漏えい報道（企業が公表した個人情報の漏えい・不正アクセス）。
//
//   scan … ScanNetSecurity（RDF 1.0）
//   snext … Security NEXT（RSS 2.0）
//
// 🚨 見出しは判定にだけ使い、文は配らない・残さない（判定結果だけを持つ。breaches.js が名前と件数から自前の題名を作る）。本文は取らない
// 🚨 報道であって公式発表ではない。公開物では「報道」と出典を必ず添える
// 漏えいかどうかは見出しの「行為」で決める（漏えい・流出・第三者が閲覧できた 等）。否定・対策の見出しは入れない。
// 「可能性」「〜か」など起きたと言い切っていない見出しは一覧に出すが、通知の対象にしない（certain=false）
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { XMLParser } from 'fast-xml-parser';
import { fetchText, SourceError } from '../fetch.js';

export const SCAN_URL = 'https://scan.netsecurity.ne.jp/rss/index.rdf';
export const SNEXT_URL = 'https://www.security-next.com/feed';

const here = path.dirname(fileURLToPath(import.meta.url));
// RSS は約1週間分しか無い。30日分ためておく（RSS の入れ替わりで一覧から消えたり、同じ件の ID が変わったりしないように・監査 R3）
export const NEWS_CACHE = process.env.SECALERT_NEWS_CACHE || path.join(here, '..', '..', 'data', 'breach_news', 'seen.json');
const KEEP_DAYS = 30;

// 「情報が外へ出た／他人が見られた」という行為。不正アクセスだけ・脆弱性の話だけの見出しは漏えいにしない
const LEAK_RE = /漏えい|漏洩|流出|閲覧され|閲覧でき|閲覧可能|持ち出し|窃取|盗まれ|出力された/;
// 「漏洩のおそれ」は起きうる話（脆弱性・不正プログラムの説明）で、漏えいが起きた報道ではない
const RISK_ONLY_RE = /(漏えい|漏洩|流出)[^、。]{0,15}(おそれ|恐れ)/;
// 否定・対策の言い回し（漏えいは確認されていない／漏えい対策を発表）。この部分を取り除いても漏えいの言葉が残る見出しは漏えい
// 間に「が」や別の漏えいの言葉をはさまない（「流出したがパスワードの流出はなし」で先の肯定まで消さない・監査 R5 F01）
//   「流出が確認されなかった」のように助詞1文字の直後の否定も拾う（監査 R6 F01）
const NEGATED_RE = /(漏えい|漏洩|流出|閲覧)(?:[はがも]|[^、。が漏流]{0,12}?)(確認されて(い)?ない|確認されなかった|確認されておらず|確認されず|確認できず|確認できない|確認できなかった|確認できていない|未確認|はなかった|は無かった|なかった|はない|は無い|なし|事実はない|を否定|していない|しておらず|せず)|(漏えい|漏洩|情報流出)(対策|防止|を防ぐ|を防止)/g;
// 🚨 通知してよいのは、見出しのどこにも否定・疑問・可能性・調査・訂正の言葉が無いものだけ。
//    日本語の言い回しは正規表現で全部は読み分けられない（監査を5回回しても取りこぼしが尽きなかった）ので、
//    少しでも当てはまれば一覧に出すだけにする＝誤報より鳴らし漏れを選ぶ（監査 R5 F01・F02）
// 「か」は漏えいの言葉に続く疑問だけ（「流出か」「漏えいしたか」）。「ほか、」の「か」では止めない（監査 R4 F08）
//    「なかった」「未確認」「不明」と、漏えいの言葉の直後の「か」（「流出か」「流出かを調査」）も含める（監査 R6 F01）
const DOUBT_RE = /ず|ない|無い|なかった|なし|否定|未確認|不明|可能性|疑い|恐れ|おそれ|調査|かどうか|確認中|[?？]|訂正|誤報|誤り|(漏えい|漏洩|流出|閲覧|窃取)(し|され|でき)?(た|る)?か/;
// 件数に使わない節（否定している節の数字は被害件数ではない・監査 R5 F02・R6 F01）
const NEG_CLAUSE_RE = /ず|ない|無い|なかった|なし|否定|未確認|かどうか/;

const toHalf = (s) => String(s).replace(/[０-９，．]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0));
const NUM = String.raw`\d[\d,]*(?:\.\d+)?`;
// 直前が数字・ハイフン・スラッシュ・小数点（電話番号・日付・小数の途中）は数えない。「件目」（順番）も数えない
const COUNT_RE = new RegExp(String.raw`(?<![\d,.\-/－])((?:${NUM}億)?(?:${NUM}万)?(?:\d[\d,]*)?)\s*(件|人|名|アカウント)(?!目)`, 'g');

function jaNumber(expr) {
  const m = expr.match(new RegExp(String.raw`^(?:(${NUM})億)?(?:(${NUM})万)?([\d,]+)?$`));
  if (!m) return null;
  const n = (s) => (s ? Number(s.replace(/,/g, '')) : 0);
  const v = n(m[1]) * 1e8 + n(m[2]) * 1e4 + n(m[3]);
  return Number.isFinite(v) && v > 0 ? Math.round(v) : null;
}

function countsIn(text) {
  const out = [];
  for (const m of toHalf(text).matchAll(COUNT_RE)) {
    if (!m[1] || !/\d/.test(m[1])) continue;
    const n = jaNumber(m[1]);
    if (n !== null) out.push(n);
  }
  return out;
}

/**
 * 見出しの漏えい件数（件・人・名・アカウント）。「1,078万8,963件」「約 26,000件」「1.2億件」。
 * 🚨 漏えいを述べている節の数字だけを使う（「会員100万人のうち30件が流出」の100万を拾わない・監査 R1 F09・R2）。
 *    「うち」があればその後ろ。節の中に数字が2つ以上あって決められないときは null（件数不明＝通知しない）
 */
export function parseJaCount(text) {
  const t = toHalf(text);
  // 🚨 半角・全角のカンマでは切らない（「1,078万8,963件」の桁区切りで数字が割れる）
  const clauses = t.split(/[、。|｜]|\s[-－–—]\s/);
  // 漏えいを肯定している節だけ（否定を取り除いても漏えいの言葉が残り、節そのものに否定の言葉が無い）
  const leak = clauses.filter((c) => LEAK_RE.test(c.replace(NEGATED_RE, '')) && !NEG_CLAUSE_RE.test(c));
  const found = [];
  for (let c of leak) {
    const i = c.lastIndexOf('うち');
    if (i >= 0) c = c.slice(i + 2);
    found.push(...countsIn(c));
  }
  // 漏えいの節に数字が無いときは件数不明（別の節の会員総数などを件数にしない・監査 R4 F03）
  return found.length === 1 ? found[0] : null;
}

export function isLeakHeadline(title) {
  const t = String(title || '').replace(NEGATED_RE, '');
  if (!LEAK_RE.test(t)) return false;
  return !(RISK_ONLY_RE.test(t) && !LEAK_RE.test(t.replace(RISK_ONLY_RE, '')));
}

export const isCertain = (title) => !DOUBT_RE.test(String(title || ''));

/** 見出しの「」『』の中の名前（サービス名・会社名として表に出す）。無ければ null */
export function quotedName(title) {
  const m = String(title || '').match(/[「『]([^」』]{2,40})[」』]/);
  return m ? m[1].trim() : null;
}

function parseXml(xml) {
  const head = xml.trimStart().slice(0, 5);
  if (!head.startsWith('<?xml') && !head.startsWith('<rss') && !head.startsWith('<rdf')) throw new Error('not XML');
  return new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', processEntities: true }).parse(xml);
}

const arr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
const text = (x) => (typeof x === 'object' && x !== null ? String(x['#text'] ?? '') : String(x ?? '')).trim();

/** RSS 2.0 と RDF 1.0 のどちらでも、見出し・URL・日時の並びにする */
export function parseNewsFeed(xml, source) {
  const doc = parseXml(xml);
  let items;
  if (doc.rss?.channel) items = arr(doc.rss.channel.item);
  else if (doc['rdf:RDF']) items = arr(doc['rdf:RDF'].item);
  else throw new Error('no rss/rdf root');
  return items.map((it) => {
    const title = text(it.title);
    const raw = it.pubDate || it['dc:date'] || null;
    const d = raw ? new Date(text(raw)) : null;
    return {
      source,
      title,
      url: text(it.link) || String(it['@_rdf:about'] || '').trim(),
      date: d && !Number.isNaN(d.getTime()) ? d.toISOString() : null, // 時刻まで持つ（72時間の判定に使う・監査 R1 F15）
    };
  }).filter((i) => i.title && /^https:\/\//.test(i.url));
}

/**
 * 見出しを判定して、判定結果だけを残す（見出しの文は捨てる）。
 * 🚨 見出しの文は公開リポジトリのキャッシュ・snapshot にも残さない（記事の題名の再配布にしない・監査 R4 F11）
 * 漏えいでない記事も leak:false で残す（後で否定に訂正された記事を、ためた分から撤回するため・監査 R4 F07）
 */
export function judgeNews(list) {
  return (list || []).map((i) => {
    const leak = isLeakHeadline(i.title);
    return { source: i.source, url: i.url, date: i.date, leak, count: leak ? parseJaCount(i.title) : null, certain: leak ? isCertain(i.title) : false, name: leak ? quotedName(i.title) : null };
  });
}

/** 漏えいの見出しだけ（テスト・一覧用） */
export function toBreaches(list) {
  return judgeNews(list).filter((i) => i.leak);
}


const okItem = (i) => i && typeof i.url === 'string' && /^https:\/\//.test(i.url) && Number.isFinite(Date.parse(i.date));
/** 事故の ID（URL の指紋・FNV-1a 32bit を36進）。最初にその記事が見えたときに決めて、以後は変えない */
const urlKey = (s) => { let h = 0x811c9dc5; for (const c of String(s)) { h ^= c.codePointAt(0); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(36); };

/**
 * 今回の RSS の判定結果と、ためてある30日分をまとめる。結果をためる先に書き戻し、漏えいの件だけを返す。
 *   ・同じ URL は新しい判定で上書きする（否定への訂正で撤回）。上書きは期限の判定より先（古い日付の記事の訂正も効く・監査 R5 F05）
 *   ・初めて見えた日時と事故の ID（incident）は最初のものを保つ（訂正・名前の追記・件数の訂正で ID を変えない・監査 R5 F04）
 *   ・新しい記事は、件数が同じで名前が食い違わない既存の事故があればその ID に入る（後から届いた報道でも ID は動かない）
 *   ・旧い形式（見出しの文を持つ）は判定し直して文を捨てる（監査 R5 F06）
 * RSS が取れなかった回（list が null）はためてある分だけ
 */
export async function accumulateNews(list, { now = new Date(), file = NEWS_CACHE } = {}) {
  let kept = [];
  try { const j = JSON.parse(await readFile(file, 'utf8')); if (Array.isArray(j.items)) kept = j.items; } catch { /* 初回 */ }
  const migrate = (i) => (typeof i?.title === 'string' && typeof i.leak !== 'boolean' ? { ...judgeNews([i])[0], incident: i.incident } : i);
  const byUrl = new Map();
  for (const i of kept.map(migrate)) if (okItem(i) && typeof i.leak === 'boolean') byUrl.set(i.url, { ...i, incident: i.incident || `news-${urlKey(i.url)}` });
  for (const i of (list || []).map(migrate)) {
    if (!okItem(i) || typeof i.leak !== 'boolean') continue;
    const prev = byUrl.get(i.url);
    let incident = prev?.incident || null;
    if (!incident && i.leak && i.count >= 1000) {
      // まとめ先の事故に属する記事の名前を全部見る（名前の無い記事を橋渡しに、名前の違う事故を1つにしない・監査 R6 F03）
      const namesOf = (inc) => new Set([...byUrl.values()].filter((o) => o.incident === inc && o.name).map((o) => o.name));
      const same = [...byUrl.values()].find((o) => {
        if (!o.leak || !o.incident || o.count !== i.count) return false;
        const names = namesOf(o.incident);
        return !i.name ? names.size <= 1 : [...names].every((n) => n === i.name);
      });
      if (same) incident = same.incident;
    }
    byUrl.set(i.url, { source: i.source, url: i.url, date: prev ? prev.date : i.date, leak: i.leak, count: i.count ?? null, certain: !!i.certain, name: i.name ?? prev?.name ?? null, incident: incident || `news-${urlKey(i.url)}` });
  }
  const since = now.getTime() - KEEP_DAYS * 86400000;
  const items = [...byUrl.values()].filter((i) => Date.parse(i.date) >= since).sort((a, b) => a.date.localeCompare(b.date) || a.url.localeCompare(b.url));
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify({ items }, null, 1) + '\n');
  return items.filter((i) => i.leak);
}

// 取得した RSS を判定して返す（見出しの文は返さない＝snapshot にも残らない）
export async function fetchScan() {
  try { return judgeNews(parseNewsFeed(await fetchText(SCAN_URL), 'scan')); } catch (e) { throw new SourceError('scan', e.message, e); }
}

export async function fetchSnext() {
  try { return judgeNews(parseNewsFeed(await fetchText(SNEXT_URL), 'snext')); } catch (e) { throw new SourceError('snext', e.message, e); }
}
