// サービス側の漏えい（breaches.json）。実データ（2026-10-27 に保存した固定応答）と、X の話題の費用・作り話の止め方。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseNewsFeed, toBreaches, judgeNews, parseJaCount, isLeakHeadline, isCertain, accumulateNews } from '../src/sources/breach_news.js';
import { parseHibp } from '../src/sources/hibp.js';
import { assembleBreaches, countLabel } from '../src/breaches.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (name) => readFile(path.join(here, 'fixtures', name), 'utf8');
const now = new Date('2026-10-27T12:00:00Z');
const items = (input) => assembleBreaches(input, { now }).items;
const newsOf = (title, over = {}) => ({ ...toBreaches([{ source: 'scan', title, url: `https://example.invalid/${encodeURIComponent(title)}`, date: '2026-10-26T00:00:00Z' }])[0], ...over });

async function realInputs() {
  const raw = [...parseNewsFeed(await fx('scannetsecurity.rdf'), 'scan'), ...parseNewsFeed(await fx('securitynext.xml'), 'snext')];
  const news = toBreaches(raw);
  const hibp = parseHibp(JSON.parse(await fx('hibp_breaches.json')).concat(Array(30).fill({})));
  return { news, hibp, raw };
}

test('件数：見出しの日本語の数字を読む・円や周年は数えない（漏えいを述べる節の数字だけ）', () => {
  assert.equal(parseJaCount('約 26,000件の会員情報'), null, '漏えいの言葉が無い見出しの数字は件数にしない');
  assert.equal(parseJaCount('1,078万8,963件の個人情報が漏えい'), 10788963);
  assert.equal(parseJaCount('全世界合計 11,774,247件のメールアドレス等が漏えい'), 11774247);
  assert.equal(parseJaCount('約 26,000件の会員情報が漏えい'), 26000);
  assert.equal(parseJaCount('顧客17万4,933人の情報が流出'), 174933);
  assert.equal(parseJaCount('延べ約900万件が流出'), 9000000);
  assert.equal(parseJaCount('１２万件が流出'), 120000);
  assert.equal(parseJaCount('情報が流出、見舞いとして 3,000円相当'), null);
  assert.equal(parseJaCount('創刊 28 周年の流出'), null);
  assert.equal(parseJaCount('ID 20260001件目の不正ログインで情報が流出'), null, '「件目」は順番で件数ではない');
  assert.equal(parseJaCount('窓口 03-1234-5678 件の流出'), null, '電話番号の末尾を件数にしない');
  assert.equal(parseJaCount('10/27/23件の流出'), null, '日付の一部を件数にしない');
  assert.equal(parseJaCount('10/27 23件が流出'), 23, '日付のあとに空白を挟んだ件数は件数');
});

test('件数：小数の億・万を途中から読まない（監査 R1 F10）／漏えいの節の数字だけ（監査 R1 F09）', () => {
  assert.equal(parseJaCount('約1.2億件の個人情報が流出'), 120000000);
  assert.equal(parseJaCount('3.5万人の会員情報が漏えい'), 35000);
  assert.equal(parseJaCount('会員100万人のうち30件の情報が流出'), 30, '「うち」の後ろ');
  assert.equal(parseJaCount('会員100万人のサービスに不正アクセス、30件が流出'), 30, '漏えいを述べている節');
  assert.equal(parseJaCount('会員100万人、顧客2万人の情報が流出'), 20000);
  assert.equal(parseJaCount('100万人と2万人の情報が流出'), null, '決められないときは件数不明');
});

test('漏えいの見出し：起きた件だけ。否定・対策・「おそれ」は入れない（監査 R1 F08・R2）', () => {
  assert.ok(isLeakHeadline('「架空チョイス」に不正アクセス、4,454,097件の会員情報が流出'));
  assert.ok(isLeakHeadline('支払い証明書が第三者に閲覧される可能性'));
  assert.ok(!isLeakHeadline('「架空ツール」に不審な部品 - 認証情報漏洩やコード実行のおそれ'));
  assert.ok(!isLeakHeadline('Apache Tomcat に複数の脆弱性'));
  assert.ok(!isLeakHeadline('架空ポイントの照会サービスに不正アクセス、11月1日 再開'));
  assert.ok(!isLeakHeadline('会員100万人に不正アクセス、個人情報の流出は確認されず'));
  assert.ok(!isLeakHeadline('1000万件の情報漏えい対策を発表'));
  assert.ok(!isLeakHeadline('顧客情報の漏えいはないと発表'));
  assert.ok(isCertain('1,078万8,963件の個人情報が漏えい'));
  assert.ok(!isCertain('最大3,709,551件の個人情報が漏えいした可能性'));
  assert.ok(!isCertain('架空くじの配送情報が流出か'));
});

test('実データ：大きい件が件数つきで入り、同じ件数の報道は1件にまとまる・見出しの文は配らない', async () => {
  const input = await realInputs();
  const list = items(input);
  const capcom = list.find((i) => i.service === 'テストID');
  assert.ok(capcom && capcom.count === 11774247 && capcom.notify_eligible, JSON.stringify(capcom));
  assert.match(capcom.id, /^news-n11774247-[0-9a-z]+-20261026$/, '件数・名前・最初の報道の日から作った ID');
  assert.equal(list.filter((i) => i.count === 10788963).length, 1, '同じ件数は1件');
  assert.ok(list.every((i) => i.type === 'confirmed' && i.sources.length >= 1 && i.sources.every((s) => /^https:\/\//.test(s.url))));
  assert.ok(list.every((i) => Array.isArray(i.advice_ja) && i.advice_ja.length >= 3), '全件に守りの行動');
  assert.ok(list.filter((i) => i.basis === 'news' && i.count == null).every((i) => !i.notify_eligible), '件数の無い報道は鳴らさない');
  const carsensor = list.find((i) => i.count === 3709551);
  assert.equal(carsensor.notify_eligible, false, '「可能性」の報道は鳴らさない');
  const heads = input.raw.map((n) => n.title);
  assert.ok(heads.length > 10 && !list.some((i) => heads.includes(i.title_ja)), '報道の見出しの文をそのまま title_ja にしない');
  assert.ok(input.news.every((n) => !('title' in n)), '判定結果に見出しの文を持たない（キャッシュ・snapshot に残さない）');
  assert.ok(!list.some((i) => /AfD/.test(i.title_ja)), 'HIBP の機微な件は載せない');
  assert.ok(list.every((i) => !('description' in i)));
  const h = list.find((i) => i.basis === 'hibp');
  assert.ok(h.breach_date && h.note_ja && /CC BY 4\.0/.test(h.note_ja), 'HIBP は漏えい日と加工の注記つき');
});

test('HIBP：古い漏えいの再掲・パスワードもお金の情報も無い件は鳴らさない', () => {
  const base = { name: 'X', title: 'X', domain: 'x.example', added_date: '2026-10-20', added_at: '2026-10-20T05:00:00Z', count: 50000000, data_classes: ['Email addresses', 'Passwords'] };
  assert.equal(items({ hibp: [{ ...base, breach_date: '2019-08-01' }] })[0].notify_eligible, false, '2019年の漏えいを今年追加しただけ');
  assert.equal(items({ hibp: [{ ...base, breach_date: '2026-09-01', data_classes: ['Email addresses', 'Names'] }] })[0].notify_eligible, false);
  const pw = items({ hibp: [{ ...base, breach_date: '2026-09-01' }] })[0];
  assert.equal(pw.notify_eligible, true);
  assert.equal(pw.published_at, '2026-10-20T05:00:00Z', '掲載の時刻を持つ（72時間の判定用）');
});

test('未確認の話題：通知しない・件数を配らない・注意文と X 検索へのリンクだけ・確認済みに同じ名前があれば出さない', () => {
  const rumors = [{ service: 'ほげペイ', first_seen: '2026-10-27T03:00:00Z', last_seen: '2026-10-27T09:00:00Z', count_24h: 320 }, { service: 'テストID', first_seen: '2026-10-27T03:00:00Z', last_seen: '2026-10-27T09:00:00Z', count_24h: 900 }];
  const news = [newsOf('「テストID」に不正アクセス、11,774,247件が漏えい')];
  const out = assembleBreaches({ news, rumors, rumorWatch: { enabled: true, last_ok_at: '2026-10-27T09:00:00Z' } }, { now });
  const r = out.items.filter((i) => i.type === 'rumor');
  assert.equal(r.length, 1, 'テストID は確認済み側にあるので話題からは消える');
  assert.equal(r[0].notify_eligible, false);
  assert.equal(r[0].count, null);
  assert.ok(!JSON.stringify(r[0]).includes('320'), 'X から数えた件数は配らない');
  assert.match(r[0].caution_ja, /未確認/);
  assert.ok(r[0].sources.every((s) => s.url.startsWith('https://x.com/search?')));
  assert.ok(!JSON.stringify(r[0]).includes('status/'), '個別の投稿へのリンク（本文）は配らない');
  assert.deepEqual(out.rumor_watch, { enabled: true, last_ok_at: '2026-10-27T09:00:00Z' });
});

test('報道：言い切りの記事が後から出たら、同じ件として通知の対象になる', () => {
  const a = newsOf('「ほげ」の会員 2,000万件が漏えいした可能性', { date: '2026-10-25T00:00:00Z' });
  const b = newsOf('「ほげ」会員 2,000万件の情報が流出', { url: 'https://example.invalid/b', date: '2026-10-26T00:00:00Z' });
  const one = items({ news: [a] });
  assert.equal(one[0].notify_eligible, false);
  const both = items({ news: [a, b] });
  assert.equal(both.length, 1);
  assert.equal(both[0].notify_eligible, true);
  assert.match(both[0].id, /^news-n20000000-[0-9a-z]+-20261025$/);
  assert.equal(both[0].published_at, '2026-10-25T00:00:00Z', '発表時刻は最初の報道のまま');
});

test('期間外（30日より前）の件は入れない', () => {
  assert.equal(items({ news: [newsOf('会員情報 2,000,000件が流出', { date: '2026-08-01T00:00:00Z' })] }).length, 0);
});

test('概数：小さい件を「約1万件」と丸めない', () => {
  assert.equal(countLabel(9999), '9,999件');
  assert.equal(countLabel(19999), '約2万件');
  assert.equal(countLabel(11774247), '約1,177万件');
  assert.equal(countLabel(120000000), '約1.2億件');
});

test('報道を30日ためる：RSS から消えても残る・30日を過ぎたら捨てる・取れない回はためた分だけ', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news-'));
  const file = path.join(dir, 'seen.json');
  try {
    const n1 = { source: 'scan', title: '「A」の会員 2,000万件が漏えい', url: 'https://example.invalid/1', date: '2026-10-20T00:00:00Z' };
    const r1 = await accumulateNews(judgeNews([n1]), { now, file });
    assert.equal(r1.length, 1);
    const r2 = await accumulateNews([], { now, file });
    assert.equal(r2.length, 1, 'RSS から消えても30日はためた分が残る');
    const r3 = await accumulateNews(null, { now: new Date('2026-11-25T00:00:00Z'), file });
    assert.equal(r3.length, 0, '30日を過ぎたら捨てる');
    const a = await readFile(file, 'utf8'); await accumulateNews(null, { now: new Date('2026-11-25T00:00:00Z'), file });
    assert.equal(await readFile(file, 'utf8'), a, '2回目は変わらない（冪等）');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

// ── X の話題：費用の上限・間隔・作り話の止め方 ──
async function withXbuzz(fn, { seed = true } = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-xbuzz-'));
  process.env.SECALERT_XBUZZ_DIR = dir;
  // 既に動いている状態の台帳（前回は十分前）。seed=false で「台帳が無い」を試す
  if (seed) await writeFile(path.join(dir, 'state.json'), JSON.stringify({ month: '2026-10', spent_usd: 0, last_run_at: '2026-10-26T00:00:00Z', runs: [] }));
  const mod = await import(`../src/sources/x_buzz.js?dir=${encodeURIComponent(dir)}`);
  try { return await fn(mod, dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

const posts = { data: [
  { id: '1', text: 'ほげペイから個人情報が流出したらしい、パスワード変えた' },
  { id: '2', text: 'ほげペイ 漏えい まじか' },
  { id: '3', text: '不正アクセスには気をつけよう（一般論）' },
] };

test('X の話題：本文に無い名前（AI の作り話）は通さない・件数が少なければ話題にしない', async () => {
  await withXbuzz(async ({ runXBuzz }) => {
    const calls = [];
    const get = async (url) => { calls.push(url); return url.includes('/counts/') ? { meta: { total_tweet_count: url.includes(encodeURIComponent('ほげペイ')) ? 120 : 3 } } : posts; };
    const ai = async () => ({ text: '{"services":["ほげペイ","ふがバンク"]}', usage: { input_tokens: 1000, output_tokens: 100 } });
    const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai });
    assert.equal(r.status, 'ran');
    assert.deepEqual(r.items.map((i) => i.service), ['ほげペイ']);
    assert.equal(calls.filter((u) => u.includes('/counts/')).length, 1, '本文に無い「ふがバンク」は数えにも行かない（課金しない）');
  });
});

test('X の話題：間隔内は呼ばない・月の上限を超えそうなら止める・費用は台帳に残る', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    let n = 0;
    const get = async (url) => { n++; return url.includes('/counts/') ? { meta: { total_tweet_count: 80 } } : posts; };
    const ai = async () => ({ text: '{"services":["ほげペイ"]}', usage: { input_tokens: 1000, output_tokens: 100 } });
    const o = { token: 't', enabled: true, provider: 'anthropic', get, ai };
    await runXBuzz({ ...o, now });
    const state = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'));
    // 投稿3件×$0.005 ＋ カウント1回×$0.005 ＋ AI（1000×4＋100×20）/1e6
    assert.ok(Math.abs(state.spent_usd - (3 * 0.005 + 0.005 + 0.006)) < 1e-9, `spent ${state.spent_usd}`);
    const before = n;
    const w = await runXBuzz({ ...o, now: new Date(now.getTime() + 3600000) });
    assert.equal(w.status, 'waiting'); assert.equal(n, before, '1時間後は呼ばない');
    const c = await runXBuzz({ ...o, now: new Date(now.getTime() + 4 * 3600000), capUsd: 0.05 });
    assert.equal(c.status, 'cap'); assert.equal(n, before, '上限を超えそうなら呼ばない');
  });
});

test('X の話題：台帳が無いときは準備だけ（呼ばない）・次の回から呼ぶ', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    let n = 0;
    const get = async (url) => { n++; return url.includes('/counts/') ? { meta: { total_tweet_count: 1 } } : posts; };
    const ai = async () => ({ text: '{"services":[]}', usage: { input_tokens: 10, output_tokens: 10 } });
    const o = { token: 't', enabled: true, provider: 'anthropic', get, ai };
    assert.equal((await runXBuzz({ ...o, now })).status, 'armed');
    assert.equal(n, 0, '台帳が無い回は1回も呼ばない（push 失敗で台帳が消え続けても課金しない）');
    const st = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'));
    assert.equal(st.last_run_at, now.toISOString());
    assert.equal((await runXBuzz({ ...o, now: new Date(now.getTime() + 3600000) })).status, 'waiting');
    assert.equal((await runXBuzz({ ...o, now: new Date(now.getTime() + 3 * 3600000) })).status, 'ran');
    assert.ok(n > 0);
  }, { seed: false });
});

test('X の話題：台帳が壊れていたら呼ばない（例外も外へ漏らさない）', async () => {
  for (const bad of ['{ broken', JSON.stringify({ month: '2026-10', spent_usd: 'abc', last_run_at: null }), JSON.stringify({ month: '2026-10', spent_usd: null, last_run_at: null }), JSON.stringify({ month: '2026-10', spent_usd: 0, last_run_at: 'xyz' }), JSON.stringify({ month: 'x', spent_usd: 0, last_run_at: null })]) {
    await withXbuzz(async ({ runXBuzz }, dir) => {
      await writeFile(path.join(dir, 'state.json'), bad);
      let n = 0;
      const get = async () => { n++; return posts; };
      const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{}' }) });
      assert.equal(r.status, 'bad_state', bad);
      assert.equal(n, 0, `壊れた台帳で呼んだ: ${bad}`);
    });
  }
});

test('X の話題：off・鍵なし・AI なしでは1回も呼ばない', async () => {
  await withXbuzz(async ({ runXBuzz }) => {
    let n = 0;
    const get = async () => { n++; return posts; };
    assert.equal((await runXBuzz({ now, token: 't', enabled: false, get })).status, 'off');
    assert.equal((await runXBuzz({ now, token: '', enabled: true, provider: 'anthropic', get })).status, 'no_token');
    assert.equal((await runXBuzz({ now, token: 't', enabled: true, provider: 'none', get })).status, 'no_ai');
    assert.equal(n, 0);
  });
});

test('X の話題：予約を保存（push）できない回は呼ばない', async () => {
  await withXbuzz(async ({ runXBuzz }) => {
    let n = 0;
    const get = async () => { n++; return posts; };
    const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{}' }), persist: async () => { throw new Error('push rejected'); } });
    assert.equal(r.status, 'persist_failed');
    assert.equal(n, 0, '予約を保存できないなら1回も呼ばない');
  });
});

test('X の話題：usage が無い・途中で失敗したら、予約した最悪の額のまま数える', async () => {
  await withXbuzz(async ({ runXBuzz, worstCost }, dir) => {
    const get = async () => posts;
    await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{"services":[]}' }) });
    const st = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'));
    assert.ok(Math.abs(st.spent_usd - worstCost(3)) < 1e-9, `usage なし＝予約額のまま ${st.spent_usd}`);
  });
  await withXbuzz(async ({ runXBuzz, worstCost }, dir) => {
    const get = async () => { throw new Error('socket hang up'); };
    const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{}' }) });
    assert.equal(r.status, 'error');
    const st = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'));
    assert.ok(Math.abs(st.spent_usd - worstCost(3)) < 1e-9, '応答を受け取れなかった呼び出しも予約額で数える');
    assert.equal(st.last_ok_at, undefined, '失敗した回は「最後に正常に確認した時刻」を進めない');
  });
});

test('X の話題：設定が数でなければ呼ばない・off なら公開中の話題も消す', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    let n = 0;
    const get = async () => { n++; return posts; };
    for (const bad of [{ capUsd: NaN }, { intervalH: NaN }, { intervalH: 0 }, { minCount: NaN }]) {
      const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{}' }), ...bad });
      assert.equal(r.status, 'bad_config', JSON.stringify(bad));
    }
    assert.equal(n, 0);
    await writeFile(path.join(dir, 'rumors.json'), JSON.stringify({ items: [{ service: 'ほげペイ', first_seen: now.toISOString(), last_seen: now.toISOString() }] }));
    const off = await runXBuzz({ now, enabled: false });
    assert.deepEqual(off.items, [], 'off にしたら話題を配らない（誤った話題をすぐ撤回できる）');
  });
});

test('X の話題：名前の検査（2件以上の投稿・英数字は単語の境目・一般の言葉は除く）', async () => {
  const { validateServices } = await import('../src/sources/x_buzz.js?v=names');
  const texts = ['ABC Payから情報が流出', 'ABC Payやばい、個人情報が漏えい', 'ABCDEFの話', 'ほげペイから流出らしい', 'AB社'];
  assert.deepEqual(validateServices({ services: ['ABC Pay'] }, texts), ['ABC Pay']);
  assert.deepEqual(validateServices({ services: ['ほげペイ'] }, texts), [], '1件の投稿だけでは話題にしない');
  assert.deepEqual(validateServices({ services: ['個人情報'] }, texts), [], '一般の言葉は候補にしない');
  assert.deepEqual(validateServices({ services: ['DEF'] }, ['ABCDEF 流出', 'XDEF 漏えい']), [], '英数字は単語の途中で一致させない');
});

test('R4：否定の言い回し・疑問形は漏えい扱いにしない／「ほか、」の「か」で肯定を落とさない（監査 R4 F02・F08）', () => {
  assert.ok(!isLeakHeadline('会員情報の流出は確認できず'));
  assert.ok(!isLeakHeadline('顧客情報は流出しておらず'));
  assert.ok(isLeakHeadline('パスワードの流出はなかったが、氏名 2万件が流出'), '別の項目の否定で肯定の事故を消さない');
  assert.ok(!isCertain('「ほげ」で 2,000万件が流出？'));
  assert.ok(!isCertain('「ほげ」で 2,000万件流出か'));
  assert.ok(isCertain('氏名ほか、2,000万件の個人情報が流出'), '「ほか、」の「か」は疑問ではない');
  assert.ok(isCertain('カード情報 2,000万件が漏えい'));
});

test('R4：漏えいの節に数字が無ければ件数不明（別の節の会員総数を使わない・監査 R4 F03）', () => {
  assert.equal(parseJaCount('会員100万人のサイトに不正アクセス、個人情報が流出'), null);
  assert.equal(parseJaCount('「ほげ」に不正アクセス、会員 1,735,154人の個人情報が流出'), 1735154);
});

test('R4：同じ件数でも名前が違えば別の事故（ID も別・監査 R4 F06）', () => {
  const a = newsOf('「A社」の会員 1,000,000件が流出');
  const b = newsOf('「B社」の会員 1,000,000件が流出', { url: 'https://example.invalid/b2' });
  const out = items({ news: [a, b] });
  assert.equal(out.length, 2);
  assert.notEqual(out[0].id, out[1].id);
});

test('R4：否定に訂正された記事は、ためた分からも撤回される（監査 R4 F07）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news2-'));
  const file = path.join(dir, 'seen.json');
  try {
    const url = 'https://example.invalid/corr';
    const r1 = await accumulateNews(judgeNews([{ source: 'scan', title: '「ほげ」2,000万件が流出', url, date: '2026-10-26T00:00:00Z' }]), { now, file });
    assert.equal(r1.length, 1);
    const r2 = await accumulateNews(judgeNews([{ source: 'scan', title: '「ほげ」の情報流出は確認されず（訂正）', url, date: '2026-10-26T05:00:00Z' }]), { now, file });
    assert.equal(r2.length, 0, '同じ URL の訂正で撤回');
    assert.ok(!(await readFile(file, 'utf8')).includes('ほげ」の情報流出'), 'キャッシュに見出しの文を残さない');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('R4：不正な月・未来の台帳は壊れている扱い（支出を0に戻さない・監査 R4 F09）', async () => {
  for (const month of ['2026-99', '2026-00', '2027-01']) {
    await withXbuzz(async ({ runXBuzz }, dir) => {
      await writeFile(path.join(dir, 'state.json'), JSON.stringify({ month, spent_usd: 14.9, last_run_at: null, runs: [] }));
      let n = 0;
      const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get: async () => { n++; return posts; }, ai: async () => ({ text: '{}' }) });
      assert.equal(r.status, 'bad_state', month);
      assert.equal(n, 0);
    });
  }
});

test('R4：台帳と話題のファイルに X の件数・話題にならなかった候補名を残さない（監査 R4 F12）', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    const many = { data: [{ id: '1', text: 'ほげペイから流出' }, { id: '2', text: 'ほげペイ 漏えい' }, { id: '3', text: 'ふがバンク 流出' }, { id: '4', text: 'ふがバンクもやばい流出' }] };
    const get = async (url) => (url.includes('/counts/') ? { meta: { total_tweet_count: url.includes(encodeURIComponent('ほげペイ')) ? 777 : 3 } } : many);
    await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get, ai: async () => ({ text: '{"services":["ほげペイ","ふがバンク"]}', usage: { input_tokens: 10, output_tokens: 10 } }) });
    const files = (await readFile(path.join(dir, 'state.json'), 'utf8')) + (await readFile(path.join(dir, 'rumors.json'), 'utf8'));
    assert.ok(files.includes('ほげペイ'), '話題になった名前は一覧として載る');
    assert.ok(!files.includes('ふがバンク'), '話題にならなかった候補名は残さない');
    assert.ok(!files.includes('777'), 'X の件数を残さない');
  });
});

test('R5：否定・疑問・調査の言葉が見出しのどこかにあれば通知しない（一覧には出す・監査 R5 F01）', () => {
  for (const h of ['「テストA」、2000万件の個人情報流出は確認されておらず', '「テストA」、2000万件の個人情報が漏えいしたかどうかを調べる', '「テストA」で2000万件の流出、調査を開始', '「テストA」2000万件の流出を訂正']) {
    assert.equal(isCertain(h), false, h);
    assert.ok(!items({ news: [newsOf(h)] }).some((i) => i.notify_eligible), h);
  }
  assert.ok(isLeakHeadline('「テストA」で2000万件が流出したがパスワードの流出はなし'), '先の肯定まで消さない');
});

test('R5：否定している節の数字を件数にしない（監査 R5 F02）', () => {
  assert.equal(parseJaCount('「テストA」で氏名が流出、2000万件のパスワードは流出せず'), null);
  assert.equal(parseJaCount('「テストA」で氏名 30件が流出、2000万件のパスワードは流出せず'), 30);
});

test('R5：同じ URL の名前の追記・件数の訂正・後から届いた前の日付の記事で ID が変わらない（監査 R5 F04）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news3-'));
  const file = path.join(dir, 'seen.json');
  const url = 'https://example.invalid/same';
  const at = '2026-10-27T00:00:00Z';
  const ids = [];
  try {
    for (const title of ['会員2000万件の個人情報が流出', '「テストA」会員2000万件の個人情報が流出', '「テストA」会員2100万件の個人情報が流出']) {
      const news = await accumulateNews(judgeNews([{ source: 'scan', title, url, date: at }]), { now, file });
      ids.push(items({ news })[0].id);
    }
    assert.equal(new Set(ids).size, 1, `ID が変わった: ${ids.join(' / ')}`);
    const news = await accumulateNews(judgeNews([{ source: 'snext', title: '会員2100万件の個人情報が流出', url: 'https://example.invalid/earlier', date: '2026-10-26T20:00:00Z' }]), { now, file });
    const out = items({ news });
    assert.equal(out.length, 1, '同じ件数の後から届いた報道は同じ事故にまとまる');
    assert.equal(out[0].id, ids[0], '前の日付の記事が後から届いても ID は動かない');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('R5：期限より前の日付の記事でも、同じ URL の否定への訂正は効く（監査 R5 F05）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news4-'));
  const file = path.join(dir, 'seen.json');
  const url = 'https://example.invalid/old-corr';
  try {
    await accumulateNews(judgeNews([{ source: 'scan', title: '「テストA」2000万件が流出', url, date: '2026-10-20T00:00:00Z' }]), { now, file });
    const r = await accumulateNews(judgeNews([{ source: 'scan', title: '「テストA」2000万件の流出は確認されず', url, date: '2026-09-01T00:00:00Z' }]), { now, file });
    assert.equal(r.length, 0, '訂正が撤回として効く（初めて見えた日時は最初のまま）');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('R5：旧い形式のキャッシュは判定し直して見出しの文を捨てる（監査 R5 F06）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news5-'));
  const file = path.join(dir, 'seen.json');
  try {
    await writeFile(file, JSON.stringify({ items: [{ source: 'scan', url: 'https://example.invalid/legacy', date: '2026-10-27T00:00:00Z', title: '「テストA」で2000万件の情報が流出', count: 20000000, certain: true, name: 'テストA' }] }));
    const r = await accumulateNews(null, { now, file });
    assert.equal(r.length, 1);
    assert.ok(!(await readFile(file, 'utf8')).includes('情報が流出'), '見出しの文は残らない');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('R5：旧い台帳・話題の候補名と件数を持ち越さない／月と最終実行が食い違う台帳は止める（監査 R5 F07・F11）', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    await writeFile(path.join(dir, 'state.json'), JSON.stringify({ month: '2026-10', spent_usd: 0, last_run_at: '2026-10-26T00:00:00Z', runs: [{ at: '2026-10-26T00:00:00Z', candidates: ['旧候補名'], counts: 1 }] }));
    await writeFile(path.join(dir, 'rumors.json'), JSON.stringify({ items: [{ service: '旧話題', first_seen: '2026-10-27T05:00:00Z', last_seen: '2026-10-27T05:00:00Z', count_24h: 777 }], checked: [{ name: '旧候補名', at: '2026-10-27T05:00:00Z', count_24h: 3 }] }));
    await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get: async () => posts, ai: async () => ({ text: '{"services":[]}', usage: { input_tokens: 1, output_tokens: 1 } }) });
    const files = (await readFile(path.join(dir, 'state.json'), 'utf8')) + (await readFile(path.join(dir, 'rumors.json'), 'utf8'));
    assert.ok(!files.includes('旧候補名') && !files.includes('777'), files);
  });
  await withXbuzz(async ({ runXBuzz }, dir) => {
    await writeFile(path.join(dir, 'state.json'), JSON.stringify({ month: '2026-09', spent_usd: 15, last_run_at: '2026-10-27T00:00:00Z', runs: [] }));
    let n = 0;
    const r = await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get: async () => { n++; return posts; }, ai: async () => ({ text: '{}' }) });
    assert.equal(r.status, 'bad_state');
    assert.equal(n, 0, '前月の台帳に当月の実行が混ざっていたら、支出を0に戻して呼ばない');
  });
});

test('R6：「確認されなかった」「流出したかを確認」「未確認」は通知しない・否定の節の件数は使わない（監査 R6 F01）', () => {
  const hs = ['「架空サービス」2000万件の個人情報流出が確認されなかった', '「架空サービス」2000万件の個人情報が流出したかを確認', '「架空サービス」2000万件の個人情報流出は未確認', '「架空サービス」で氏名が流出、2000万件のパスワード流出が確認されなかった'];
  for (const h of hs) {
    assert.equal(isCertain(h), false, h);
    assert.ok(!items({ news: [newsOf(h)] }).some((i) => i.notify_eligible), h);
  }
  assert.equal(isLeakHeadline(hs[0]), false, '「流出が確認されなかった」は漏えいの報道ではない');
  assert.equal(parseJaCount(hs[3]), null, '否定の節の2000万件を氏名の流出件数にしない');
});

test('R6：名前の無い記事を橋渡しに、名前の違う事故を1つにしない（監査 R6 F03）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secalert-news6-'));
  const file = path.join(dir, 'seen.json');
  try {
    const mk = (title, u, h) => ({ source: 'scan', title, url: `https://example.invalid/${u}`, date: `2026-10-27T${h}:00:00Z` });
    const news = await accumulateNews(judgeNews([mk('「架空A」2000万件の個人情報が流出', 'a', '10'), mk('会員2000万件の個人情報が流出', 'anon', '11'), mk('「架空B」2000万件の個人情報が流出', 'b', '12')]), { now, file });
    const out = items({ news });
    assert.equal(out.length, 2, JSON.stringify(out.map((i) => [i.id, i.service])));
    assert.notEqual(out.find((i) => i.service === '架空A').id, out.find((i) => i.service === '架空B').id);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('R6：旧い台帳の counts 配列などの入れ子は持ち越さない（監査 R6 F07）', async () => {
  await withXbuzz(async ({ runXBuzz }, dir) => {
    await writeFile(path.join(dir, 'state.json'), JSON.stringify({ month: '2026-10', spent_usd: 1, last_run_at: '2026-10-26T00:00:00Z', runs: [{ at: '2026-10-26T00:00:00Z', candidates: ['旧候補名'], counts: [{ service: '旧候補名', count_24h: 3 }], reserved_usd: 0.137, usd: 0.015 }] }));
    await runXBuzz({ now, token: 't', enabled: true, provider: 'anthropic', get: async () => posts, ai: async () => ({ text: '{"services":[]}', usage: { input_tokens: 1, output_tokens: 1 } }) });
    const st = await readFile(path.join(dir, 'state.json'), 'utf8');
    assert.ok(!st.includes('旧候補名') && !st.includes('count_24h'), st);
    assert.ok(JSON.parse(st).runs[0].usd === 0.015, '支出の記録は残す');
  });
});
