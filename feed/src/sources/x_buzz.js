// X で話題になっている「まだ公表されていない漏えい」（未確認）。
//
// 流れ（SECALERT_XBUZZ_INTERVAL_H 時間に1回・既定3）
//   1. X の直近検索：漏えいの言葉を含む日本語の投稿を関連度順に10件（1件 $0.005）
//   2. Claude で「漏えいの被害に遭ったと言われているサービス名」を抜き出す（投稿の本文に文字どおり出てくる名前だけ残す＝AIの作り話を通さない）
//   3. 候補ごとに X の件数カウント（直近24時間・1回 $0.005・本文は読まない）。SECALERT_XBUZZ_MIN 件以上なら「話題」
//
// 🚨 未確認の情報。通知は出さない・公開物では必ず「未確認」と注意文を添える（breaches.js が付ける）
// 🚨 X の規約で投稿の本文・投稿者は配らない。公開物にはサービス名・件数・X 検索へのリンクだけ
// 🚨 月の上限（SECALERT_XBUZZ_CAP_USD・既定15）を X と Claude の合計で数える。超えそうならその月は止める
// 台帳は data/xbuzz/state.json（支出）と rumors.json（話題）。リポジトリにコミット＝回をまたいで残る
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchJson } from '../fetch.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const XBUZZ_DIR = process.env.SECALERT_XBUZZ_DIR || path.join(here, '..', '..', 'data', 'xbuzz');

export const PRICE = { post: 0.005, count: 0.005 }; // X 公式（docs.x.com/x-api/getting-started/pricing・2026-10-27 確認）
// Claude Opus 5.5 の公式単価（$/100万トークン）。モデルを変えたら環境変数で直す
const AI_IN = Number(process.env.SECALERT_XBUZZ_AI_IN_PER_M || 4);
const AI_OUT = Number(process.env.SECALERT_XBUZZ_AI_OUT_PER_M || 20);
// 1回の AI 呼び出しの上限（最悪の費用の見積もりに使う）。入力は投稿10件×500字＋指示で、日本語1字≒1トークン以下（監査 R1 F05）
export const AI_MAX_TOKENS = 2000;
export const AI_MAX_INPUT_TOKENS = 8000;
const PROMPT_MAX_CHARS = 6000;

const LEAK_WORDS = '(流出 OR 漏えい OR 漏洩 OR 不正アクセス)';
export const SEARCH_QUERY = `${LEAK_WORDS} lang:ja -is:retweet -is:reply`;
// 最後に話題として見えてから12時間で一覧から外す（3時間ごとに見直す。古い話題を出し続けない・監査 R2）
export const RUMOR_TTL_H = 12;

export const searchUrl = () => `https://api.x.com/2/tweets/search/recent?${new URLSearchParams({ query: SEARCH_QUERY, max_results: '10', sort_order: 'relevancy', 'tweet.fields': 'created_at,lang' })}`;
export const countQuery = (name) => `"${name.replace(/"/g, '')}" ${LEAK_WORDS} -is:retweet`;
export const countUrl = (name, now) => `https://api.x.com/2/tweets/counts/recent?${new URLSearchParams({ query: countQuery(name), granularity: 'hour', start_time: new Date(now.getTime() - 86400000).toISOString() })}`;
/** 公開物に載せるのは X の検索画面へのリンクだけ（本文・投稿者は配らない） */
export const xSearchLink = (name) => `https://x.com/search?${new URLSearchParams({ q: `"${name}" ${LEAK_WORDS}`, f: 'live' })}`;

const SYSTEM = `あなたは日本語のSNS投稿から、情報漏えい・不正アクセスの被害に遭ったと言われている「サービス名・会社名」だけを抜き出す係です。
次の JSON だけを返してください。{"services": ["名前", ...]}
守ること：
- 投稿の中に書かれている名前を、書かれているとおりに写す。言い換え・補完・推測をしない
- 漏えいの被害者として名指しされているものだけ。注意喚起・一般論・攻撃者側・ニュースサイト名・「個人情報」のような一般名詞は入れない
- 該当が無ければ {"services": []}
- JSON 以外は出力しない`;

const ym = (d) => d.toISOString().slice(0, 7);

async function readJson(file, fallback) {
  try { return JSON.parse(await readFile(path.join(XBUZZ_DIR, file), 'utf8')); } catch { return fallback; }
}

// 🚨 台帳と話題のファイルは公開リポジトリに入る。読み込んだら許した項目だけに削る（旧い形式の候補名・件数を持ち越さない・監査 R5 F07）
const RUN_KEYS = ['at', 'armed', 'reserved_usd', 'posts', 'candidates', 'counts', 'ai_in', 'ai_out', 'usd', 'rumors', 'error'];
// 値は数・文字列・真偽値・null だけ。配列は件数に、入れ子のオブジェクトは捨てる（旧い counts:[{service,count_24h}] を持ち越さない・監査 R6 F07）
const cleanVal = (v) => (Array.isArray(v) ? v.length : v === null || ['number', 'string', 'boolean'].includes(typeof v) ? v : undefined);
const cleanRun = (r) => Object.fromEntries(RUN_KEYS.filter((k) => k in (r || {})).map((k) => [k, cleanVal(r[k])]).filter(([, v]) => v !== undefined));
const cleanRumor = (r) => ({ service: r.service, first_seen: r.first_seen, last_seen: r.last_seen, ...(r.checked_at ? { checked_at: r.checked_at } : {}) });

/**
 * 支出台帳を読む。🚨 無い・壊れている・数が数でない＝「課金してよいか分からない」ので呼ばない側に倒す
 *   missing … ファイルが無い（初回 or 自動コミットの push に失敗して消えた）→ この回は準備だけ（last_run_at を今にして書く）
 *   bad     … JSON が壊れている・spent_usd が有限の数でない・last_run_at が日時でない → 呼ばない。人が直す
 * （2026-10-28 監査の実測：台帳が毎回消えると30分ごとに X を呼び、月の上限も毎回0に戻った）
 */
async function readState(now) {
  let raw;
  try { raw = await readFile(path.join(XBUZZ_DIR, 'state.json'), 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') return { kind: 'missing', state: { month: ym(now), spent_usd: 0, last_run_at: null, runs: [] } };
    return { kind: 'bad', state: null };
  }
  let s;
  try { s = JSON.parse(raw); } catch { return { kind: 'bad', state: null }; }
  const okNum = typeof s?.spent_usd === 'number' && Number.isFinite(s.spent_usd) && s.spent_usd >= 0;
  // 月は実在する年月で、未来でないこと（「2026-99」や来月の台帳を「前月」と取り違えて支出を0に戻さない・監査 R4 F09）
  const okMonth = typeof s?.month === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(s.month) && s.month <= ym(now);
  const okLast = s?.last_run_at === null || (typeof s?.last_run_at === 'string' && Number.isFinite(Date.parse(s.last_run_at)) && Date.parse(s.last_run_at) <= now.getTime() + 60000);
  // 最終実行が台帳の月より後の月＝前月の台帳に当月の実行が混ざっている。月が変わったと取り違えて支出を0に戻さない（監査 R5 F11）
  const okOrder = s.last_run_at === null || s.last_run_at.slice(0, 7) <= s.month;
  if (!okNum || !okMonth || !okLast || !okOrder) return { kind: 'bad', state: null };
  return { kind: 'ok', state: { month: s.month, spent_usd: s.spent_usd, last_run_at: s.last_run_at, ...(s.last_ok_at ? { last_ok_at: s.last_ok_at } : {}), runs: Array.isArray(s.runs) ? s.runs.map(cleanRun) : [] } };
}
async function writeJson(file, obj) {
  await mkdir(XBUZZ_DIR, { recursive: true });
  await writeFile(path.join(XBUZZ_DIR, file), JSON.stringify(obj, null, 1) + '\n');
}

// サービス名ではない一般の言葉（AI が「被害者」として返しても候補にしない。企業名を消すためのものではない）
const GENERIC = new Set(['個人情報', '情報', '会員情報', '顧客情報', '会社', '企業', '大手', 'サービス', 'アプリ', 'サイト', 'ウェブサイト', '会員', '顧客', 'システム', 'サーバー', 'サーバ', 'アカウント', 'パスワード', 'メール', 'データ', '政府', '銀行', '病院', '学校', '自治体', 'ネット', 'sns', 'web']);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * AI の出力から名前を取り出し、次を全部満たすものだけ残す（作り話・言い換え・一般名詞を落とす・監査 R1 F11）
 *   ・投稿の本文に文字どおり出てくる（英数字の名前は単語の途中に埋もれていない＝「AB」が「ABC」の中で一致しない）
 *   ・2件以上の投稿に出てくる（1人の投稿だけでは「話題」にしない）
 *   ・一般の言葉ではない
 */
export function validateServices(out, texts) {
  const list = Array.isArray(out?.services) ? out.services : [];
  const lower = texts.map((t) => t.toLowerCase());
  const seen = new Set();
  const ok = [];
  for (const s of list) {
    if (typeof s !== 'string') continue;
    const name = s.trim();
    if (name.length < 2 || name.length > 40) continue;
    if (/https?:|@|#|\n/.test(name)) continue;
    if (GENERIC.has(name.toLowerCase())) continue;
    const ascii = /^[\x20-\x7e]+$/.test(name);
    const re = ascii ? new RegExp(`(?<![a-z0-9])${esc(name.toLowerCase())}(?![a-z0-9])`) : null;
    const hits = lower.filter((t) => (re ? re.test(t) : t.includes(name.toLowerCase()))).length;
    if (hits < 2) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    ok.push(name);
  }
  return ok;
}

function parseJson(text) {
  const m = String(text || '').match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

async function callAnthropic(system, prompt) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  // 🚨 SDK の自動再試行は止める（予約と精算の外で、応答を受け取れなかった試行に追加で課金される・監査 R4 F04）
  const client = new Anthropic({ maxRetries: 0 });
  const model = process.env.SECALERT_AI_MODEL || 'claude-opus-5-5';
  const res = await client.messages.create({
    model,
    max_tokens: AI_MAX_TOKENS,
    output_config: { effort: 'low' }, // 名前を写すだけの仕事。考える量を抑えて費用を下げる
    system,
    messages: [{ role: 'user', content: prompt }],
  });
  if (res.stop_reason === 'refusal') return { text: '', model, usage: res.usage };
  const text = res.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
  return { text, model, usage: res.usage };
}

/** いま有効な話題（最後に見えてから RUMOR_TTL_H 時間以内） */
export function activeRumors(rumors, now) {
  return (rumors?.items || []).filter((r) => typeof r?.service === 'string' && now.getTime() - Date.parse(r.last_seen) <= RUMOR_TTL_H * 3600000);
}

/** 1回の最悪の費用。投稿10件＋カウント maxChecks 回＋AI（入力の上限＋出力の上限）。実費はこれ以下 */
export function worstCost(maxChecks) {
  return 10 * PRICE.post + maxChecks * PRICE.count + (AI_MAX_INPUT_TOKENS * AI_IN + AI_MAX_TOKENS * AI_OUT) / 1e6;
}

const finite = (v, { min = 0, positive = false } = {}) => typeof v === 'number' && Number.isFinite(v) && (positive ? v > 0 : v >= min);

/**
 * 3時間に1回だけ X を見に行き、話題の一覧（rumors）を返す。
 * 🚨 X を呼ぶ前に「最悪の費用」を台帳に予約し、それを persist（Actions では git push）できた回だけ呼ぶ。
 *    あとで保存に失敗しても、残るのは予約額（実費以上）＝月の上限は破れない（2026-10-28 監査 R1 F01・R3）
 * opts.get / opts.ai / opts.persist はテスト用の差し替え口
 */
export async function runXBuzz({
  now = new Date(),
  token = process.env.X_BEARER_TOKEN,
  enabled = (process.env.SECALERT_XBUZZ || 'off') === 'on',
  provider = (process.env.SECALERT_AI || 'none').toLowerCase(),
  intervalH = Number(process.env.SECALERT_XBUZZ_INTERVAL_H || 3),
  capUsd = Number(process.env.SECALERT_XBUZZ_CAP_USD || 15),
  minCount = Number(process.env.SECALERT_XBUZZ_MIN || 50),
  maxChecks = 3,
  get = fetchJson,
  ai = null,
  persist = null,
} = {}) {
  // 🚨 off にしたら、公開中の未確認の一覧も出さない（誤った話題をすぐ撤回できるように・監査 R3）
  if (!enabled) return { status: 'off', items: [], watch: { enabled: false, last_ok_at: null } };
  const loaded = await readState(now);
  const raw = await readJson('rumors.json', { items: [] });
  const rumors = { items: (Array.isArray(raw?.items) ? raw.items : []).filter((r) => typeof r?.service === 'string').map(cleanRumor) };
  const state = loaded.state;
  const watch = () => ({ enabled: true, last_ok_at: state?.last_ok_at || null });
  const result = (status) => ({ status, items: activeRumors(rumors, now), watch: watch(), spent_usd: state ? state.spent_usd : null, month: state ? state.month : null });

  if (!token) return result('no_token');
  const call = ai || (provider === 'anthropic' ? callAnthropic : null);
  if (!call) return result('no_ai');
  // 設定が数でないと大小比較が常に偽になり、上限も間隔も効かなくなる（監査 R1 F06）
  if (!finite(intervalH, { positive: true }) || !finite(capUsd) || !finite(minCount, { positive: true }) || !finite(AI_IN) || !finite(AI_OUT) || !finite(worstCost(maxChecks))) {
    console.warn('[xbuzz] 設定 SECALERT_XBUZZ_INTERVAL_H / CAP_USD / MIN / AI_IN_PER_M / AI_OUT_PER_M が数でないので X を呼びません');
    return result('bad_config');
  }
  if (loaded.kind === 'bad') { console.warn('[xbuzz] 支出台帳 data/xbuzz/state.json が壊れているので X を呼びません（人が直すまで止まる）'); return result('bad_state'); }
  if (loaded.kind === 'missing') {
    // 準備だけ：この台帳がコミットされて次の回に読めたときに初めて呼ぶ（push に失敗し続けても課金されない）
    state.last_run_at = now.toISOString();
    state.runs = [{ at: now.toISOString(), armed: true, usd: 0 }];
    await writeJson('state.json', state);
    if (persist) await persist('xbuzz: 支出台帳を作る（準備だけ）').catch(() => {});
    console.warn('[xbuzz] 支出台帳が無いので、この回は準備だけ（X は呼ばない）');
    return result('armed');
  }
  if (state.month !== ym(now)) { state.month = ym(now); state.spent_usd = 0; }
  if (state.last_run_at && now.getTime() - Date.parse(state.last_run_at) < intervalH * 3600000) return result('waiting');
  const worst = worstCost(maxChecks);
  if (state.spent_usd + worst > capUsd) { console.warn(`[xbuzz] 月の上限 $${capUsd} に達するので止めます（${state.month} 使用 $${state.spent_usd.toFixed(3)}）`); return result('cap'); }

  // 予約：最悪の費用を先に支出へ足し、実行時刻と一緒に保存する。保存（push）できなければ呼ばない
  const before = state.spent_usd;
  state.spent_usd = Number((before + worst).toFixed(6));
  state.last_run_at = now.toISOString();
  state.runs = [...(state.runs || []), { at: now.toISOString(), reserved_usd: worst }].slice(-60);
  await writeJson('state.json', state);
  if (persist) {
    try { await persist('xbuzz: 支出の予約'); } catch (e) {
      state.spent_usd = before; // 予約を保存できなかった＝呼んでいない
      console.warn(`[xbuzz] 支出の予約を保存できないので X を呼びません: ${e.message}`);
      return result('persist_failed');
    }
  }

  const headers = { authorization: `Bearer ${token}` };
  // 🚨 台帳は公開リポジトリに入る。X から得た候補名・件数は残さない（呼び出しの回数と費用だけ・監査 R4 F12）
  const run = { at: now.toISOString(), reserved_usd: worst, posts: 0, candidates: 0, counts: 0, ai_in: null, ai_out: null, usd: 0, rumors: 0 };
  let candidates = [];
  let unknownCost = false; // 応答を受け取れなかった・usage が無い呼び出しがあった＝実費が分からない→予約額のまま残す（監査 R1 F07）
  try {
    let json;
    try { json = await get(searchUrl(), { headers, retries: 0 }); } catch (e) { unknownCost = true; throw e; }
    const all = Array.isArray(json?.data) ? json.data : [];
    const posts = all.filter((t) => typeof t?.text === 'string');
    run.posts = all.length;
    run.usd += run.posts * PRICE.post;
    const texts = posts.map((t) => t.text);
    if (texts.length) {
      const prompt = texts.map((t, i) => `[${i + 1}] ${t.replace(/\s+/g, ' ').slice(0, 500)}`).join('\n').slice(0, PROMPT_MAX_CHARS);
      let r;
      try { r = await call(SYSTEM, prompt); } catch (e) { unknownCost = true; throw e; }
      const inT = r?.usage?.input_tokens; const outT = r?.usage?.output_tokens;
      if (Number.isFinite(inT) && Number.isFinite(outT)) { run.ai_in = inT; run.ai_out = outT; run.usd += (inT * AI_IN + outT * AI_OUT) / 1e6; } else unknownCost = true;
      candidates = validateServices(parseJson(r?.text), texts);
      run.candidates = candidates.length;
    }
    // 🚨 話題にならなかった候補は何も残さない（名前も指紋も。指紋は候補名を総当たりで当てれば戻せる・監査 R5 F08）。
    //    数え直しを省くのは、すでに話題の一覧に載っている名前（公開している名前）だけ。その最後に数えた時刻は話題の項目に持つ
    const todo = [];
    for (const name of candidates) {
      const prev = rumors.items.find((x) => x.service.toLowerCase() === name.toLowerCase());
      if (prev && Number.isFinite(Date.parse(prev.checked_at)) && now.getTime() - Date.parse(prev.checked_at) <= 6 * 3600000) {
        prev.last_seen = now.toISOString(); // 直近6時間に数えた話題は数え直さず、まだ話題として見えた時刻だけ更新する
        continue;
      }
      if (todo.length < maxChecks) todo.push(name);
    }
    for (const name of todo) {
      let c;
      try { c = await get(countUrl(name, now), { headers, retries: 0 }); } catch (e) { unknownCost = true; throw e; }
      run.counts++;
      run.usd += PRICE.count;
      const total = Number(c?.meta?.total_tweet_count);
      const prev = rumors.items.find((x) => x.service.toLowerCase() === name.toLowerCase());
      if (Number.isFinite(total) && total >= minCount) {
        if (prev) Object.assign(prev, { last_seen: now.toISOString(), checked_at: now.toISOString() });
        else rumors.items.push({ service: name, first_seen: now.toISOString(), last_seen: now.toISOString(), checked_at: now.toISOString() });
        run.rumors++;
      } else if (prev && Number.isFinite(total)) {
        // 数え直して減っていたら、話題の一覧から外す（過去の件数で「増えています」と出し続けない・監査 R2）
        rumors.items = rumors.items.filter((x) => x !== prev);
      }
    }
    delete rumors.checked;
    rumors.items = activeRumors(rumors, now);
    state.last_ok_at = now.toISOString();
  } catch (e) {
    run.error = e.message;
    console.warn(`[xbuzz] 失敗: ${e.message}`);
  } finally {
    // 精算：実費が分かっていれば予約を実費に置き換える。分からなければ予約額のまま（多めに数える）
    const settled = unknownCost ? Math.max(worst, run.usd) : run.usd;
    run.usd = Number(settled.toFixed(6));
    state.spent_usd = Number((before + settled).toFixed(6));
    state.runs = [...state.runs.slice(0, -1), run].slice(-60);
    await writeJson('state.json', state);
    await writeJson('rumors.json', rumors);
  }
  return result(run.error ? 'error' : 'ran');
}
