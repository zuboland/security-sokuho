// サービス側の漏えい（PayPal の件のように、利用者のPCではなく運営会社のほうで起きた事故）を breaches.json にまとめる。
//
//   confirmed … 確認済み・報道ベース（HIBP＝流出データの実物を確認した件／日本の報道＝企業の公表を伝えた記事）
//   rumor     … X で話題になっているだけの未確認の件（x_buzz.js）。通知は出さない
//
// 🚨 alerts.json・browsers.json とは別ファイル（配布済みの拡張・常駐アプリの判定を変えない）
// 🚨 通知するかは拡張側で決める（件数のしきい値は利用者の設定・既定 1,000万件）。ここでは「通知してよい質の件か」だけ付ける
// 🚨 判定に AI を使わない。AI が関わるのは rumor の候補名の抜き出しだけで、投稿の本文に文字どおりある名前しか通らない
// 🚨 報道の見出しはそのまま配らない。見出しの「」内の名前と件数から、自前の短い題名を作る（記事の題名の再配布にしない・監査 R2）
import { xSearchLink } from './sources/x_buzz.js';

export const BREACH_WINDOW_DAYS = Number(process.env.SECALERT_BREACH_WINDOW_DAYS || 30);
const dayMs = 86400000;

const DATA_JA = {
  'Email addresses': 'メールアドレス', Passwords: 'パスワード', Names: '氏名', 'Phone numbers': '電話番号',
  'Physical addresses': '住所', 'Dates of birth': '生年月日', 'Credit cards': 'クレジットカード情報',
  'Partial credit card data': 'カード情報の一部', 'Bank account numbers': '銀行口座番号', Usernames: 'ユーザー名',
  'IP addresses': 'IPアドレス', Genders: '性別', 'Government issued IDs': '公的な身分証の番号', 'Purchases': '購入履歴',
};
const MONEY = new Set(['Credit cards', 'Partial credit card data', 'Bank account numbers']);

const NEWS_NAME = { scan: 'ScanNetSecurity', snext: 'Security NEXT' };

export const CONFIRMED_ADVICE = [
  'このサービスを使っているなら、パスワードを変える（同じパスワードを使い回している他のサービスも）',
  '二段階認証（ログインのときの確認コード）を有効にする',
  'この件をかたるメール・SMS・電話には応じない。確かめるときはブックマークや公式アプリから',
];
export const MONEY_ADVICE = 'カードや口座の利用明細に、覚えのない請求が無いか確かめる';
export const RUMOR_CAUTION = '未確認です。X で投稿が増えているだけで、公式の発表や報道はまだ確認できていません。誤った情報のこともあります。';
export const RUMOR_ADVICE = [
  '慌ててパスワードの入力画面を開かない。この話題をきっかけにしたメール・SMS・DM のリンクは開かない',
  '気になるときは、ブックマークや公式アプリから運営のお知らせを確かめる',
  'この一覧は一部の報道と漏えいデータベースだけを見ています。公式の発表がすべて載るわけではありません',
];
export const HIBP_NOTE = 'Have I Been Pwned のデータを抜き出して日本語の題名・項目名を付け、件数を概数にしています（CC BY 4.0）';

const slug = (s) => String(s || '').replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
const isoDay = (s) => (s ? new Date(s).toISOString().slice(0, 10) : null);
/** 名前の短い指紋（ID 用・FNV-1a 32bit を36進） */
const hash = (s) => { let h = 0x811c9dc5; for (const c of String(s)) { h ^= c.codePointAt(0); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(36); };

/** 件数の概数（1万未満は実数・それ以上は四捨五入した「約◯万件」）。小さい件を「約1万件」と丸めない */
export function countLabel(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 10000) return `${n.toLocaleString('ja-JP')}件`;
  if (n < 1e8) return `約${Math.round(n / 1e4).toLocaleString('ja-JP')}万件`;
  return `約${(Math.round(n / 1e7) / 10).toLocaleString('ja-JP')}億件`;
}

function newsTitle(n) {
  const who = n.name ? `「${n.name}」` : '企業のサービス';
  const size = n.count != null ? `（${countLabel(n.count)}）` : '';
  return `${who}で情報漏えいが報じられています${size}${n.certain ? '' : '（可能性の段階）'}`;
}

export function assembleBreaches({ hibp, news, rumors, rumorWatch = { enabled: false, last_ok_at: null } }, { now = new Date(), windowDays = BREACH_WINDOW_DAYS } = {}) {
  const since = now.getTime() - windowDays * dayMs;
  const items = [];

  for (const b of hibp || []) {
    const added = Date.parse(b.added_date);
    if (!Number.isFinite(added) || added < since) continue;
    const recentBreach = b.breach_date && now.getTime() - Date.parse(b.breach_date) <= 365 * dayMs;
    const hasPw = b.data_classes.includes('Passwords');
    const money = b.data_classes.some((c) => MONEY.has(c));
    items.push({
      id: `hibp-${slug(b.name)}`,
      type: 'confirmed',
      basis: 'hibp',
      title_ja: `${b.title}${b.domain ? `（${b.domain}）` : ''} の利用者情報の流出が確認されました`,
      service: b.title,
      domain: b.domain,
      count: b.count,
      data_ja: b.data_classes.map((c) => DATA_JA[c]).filter(Boolean),
      breach_date: b.breach_date, // 漏えいが起きた日（掲載日とは別・古い漏えいの新規掲載と分かるように・監査 R2）
      published: b.added_date,
      published_at: b.added_at || null,
      // 通知してよい質＝1年以内に起きた漏えいで、パスワードかお金の情報を含む（古い流出の再掲・名前とメールだけの件では鳴らさない）
      notify_eligible: !!recentBreach && (hasPw || money),
      advice_ja: money ? [...CONFIRMED_ADVICE, MONEY_ADVICE] : CONFIRMED_ADVICE,
      note_ja: HIBP_NOTE,
      sources: [{ name: 'Have I Been Pwned', url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(b.name)}`, date: b.added_date }],
    });
  }

  // 報道：同じ件を複数の媒体・複数の日に報じることがある。件数が完全に一致し、名前が食い違わなければ同じ件として1つにまとめる。
  // ID は「件数・名前・最初の報道の日」から作る（RSS の入れ替わりで変わらない＝同じ件を2回鳴らさない・監査 R1 F13／
  // 件数だけだと同じ件数の別の事故を飲み込む・名前と日付を入れる・監査 R4 F06）。報道は30日ためてあるので、最初の報道は窓の間ずっと残る
  const groups = [];
  for (const n of [...(news || [])].sort((a, b) => (a.date || '').localeCompare(b.date || '') || a.url.localeCompare(b.url))) {
    const t = Date.parse(n.date);
    if (!Number.isFinite(t) || t < since) continue;
    const src = { name: NEWS_NAME[n.source] || n.source, url: n.url, date: isoDay(n.date) };
    const groupable = n.count && n.count >= 1000;
    // ためる側（accumulateNews）が決めた事故の ID があれば、それでまとめる（訂正・遅れて届いた報道でも ID が動かない・監査 R5 F04）
    const hit = n.incident ? groups.find((g) => g.id === n.incident) : groupable && groups.find((g) => !g._incident && g.count === n.count && (!g.service || !n.name || g.service === n.name));
    if (hit) {
      if (!hit.sources.some((s) => s.url === src.url)) hit.sources.push(src);
      // 後の報道で言い切りに変わったら、その時点から通知の対象にする（published_at は最初の報道のまま）
      if (n.certain && !hit._certain) { hit._certain = true; hit.notify_eligible = hit.count != null; hit.title_ja = newsTitle({ ...n, count: hit.count, certain: true }); }
      if (!hit.service && n.name) { hit.service = n.name; hit.title_ja = newsTitle({ ...n, count: hit.count, certain: hit._certain }); }
      continue;
    }
    const it = {
      id: n.incident || (groupable ? `news-n${n.count}${n.name ? `-${hash(n.name)}` : ''}-${n.date.slice(0, 10).replace(/-/g, '')}` : `news-${slug(n.url)}`),
      _incident: !!n.incident,
      type: 'confirmed',
      basis: 'news', // 報道ベース（公式発表そのものではない）
      title_ja: newsTitle(n),
      service: n.name || null,
      domain: null,
      count: n.count ?? null,
      data_ja: [],
      breach_date: null,
      published: isoDay(n.date),
      published_at: n.date,
      // 件数が見出しに無い・起きたと言い切っていない件は鳴らさない（一覧には出す）
      notify_eligible: n.count != null && !!n.certain,
      advice_ja: CONFIRMED_ADVICE,
      sources: [src],
      _certain: !!n.certain,
    };
    items.push(it);
    if (groupable || n.incident) groups.push(it);
  }
  for (const it of items) { delete it._certain; delete it._incident; }

  // 未確認の話題：確認済みの件のサービス名・ドメインに同じ名前があれば、もう確認済み側に載っているので出さない
  const confirmedNames = items.flatMap((i) => [i.service, i.domain]).filter(Boolean).map((s) => s.toLowerCase());
  for (const r of rumors || []) {
    const name = r.service.toLowerCase();
    if (confirmedNames.some((c) => c === name || c.includes(name) || name.includes(c))) continue;
    items.push({
      id: `rumor-${slug(r.service) || encodeURIComponent(r.service).slice(0, 60)}`,
      type: 'rumor',
      basis: 'x',
      title_ja: `X で「${r.service}」の漏えいについての投稿が増えています（未確認）`,
      service: r.service,
      domain: null,
      count: null, // X から数えた件数は配らない（X の計測値の再配布にしない・監査 R2）
      data_ja: [],
      breach_date: null,
      published: isoDay(r.first_seen),
      published_at: r.first_seen,
      notify_eligible: false, // 🚨 未確認は鳴らさない
      caution_ja: RUMOR_CAUTION,
      advice_ja: RUMOR_ADVICE,
      sources: [{ name: 'X の検索結果', url: xSearchLink(r.service), date: isoDay(r.last_seen) }],
    });
  }

  items.sort((a, b) => (b.published || '').localeCompare(a.published || '') || a.id.localeCompare(b.id));
  return { items, rumor_watch: { enabled: !!rumorWatch.enabled, last_ok_at: rumorWatch.last_ok_at || null } };
}
