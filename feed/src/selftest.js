// 毒味：わざと壊したものを食わせて、落ちるべきときに落ちるかを確かめる。
// 終了値 0＝全部OK／1＝NGあり。CI でも回す。
import { judge, compareVersions } from './version.js';
import { parseChromeReleases, findExploitedCves } from './sources/chrome_releases.js';
import { parseJvn } from './sources/jvn.js';
import { parseEdge } from './sources/edge.js';
import { validateSummary } from './summarize.js';
import { assemble } from './build.js';
import { classify, protectAdvice, kindOf } from './triage.js';

const results = [];
const check = (name, cond, detail = '') => results.push({ name, ok: !!cond, detail });

// 1. 版数の3値判定
check('古い版数は required', judge('155.0.8059.84', '156.0.8078.47') === 'required');
check('同じ版数は ok', judge('156.0.8078.47', '156.0.8078.47') === 'ok');
check('新しい版数は ok', judge('156.0.8078.48', '156.0.8078.47') === 'ok');
check('版数が無いと unknown', judge(null, '156.0.8078.47') === 'unknown');
check('修正版が無いと unknown', judge('156.0.8078.47', null) === 'unknown');
check('壊れた版数は unknown', judge('abc', '156.0.8078.47') === 'unknown');
check('桁違いを文字列で比べない', compareVersions('156.0.8078.9', '156.0.8078.48') < 0);

// 2. 悪用確認の文言
check('in the wild の文の CVE を拾う', findExploitedCves('Fixed 3 bugs. Google is aware that an exploit for CVE-2026-999999 exists in the wild. Thanks.').includes('CVE-2026-999999'));
check('別の文の CVE は拾わない', !findExploitedCves('CVE-2026-111111 was fixed. Google is aware of exploits in the wild for another product.').includes('CVE-2026-111111'));

// 3. 壊れた入力で落ちる
check('Chrome Releases の形違いで落ちる', throws(() => parseChromeReleases({ feed: {} })));
check('JVN のメンテナンスHTMLで落ちる', throws(() => parseJvn('<!DOCTYPE html><html><body>メンテナンス中</body></html>')));
check('Edge の HTML に版数が無ければ落ちる', throws(() => parseEdge('<h2>October 1, 2026</h2><p>nothing here</p>')));

// 4. AI出力の検査（版数の捏造・電話番号・ダウンロード案内）
const item = { fixed_versions: { chrome: '156.0.8078.47' } };
check('無い版数を書いた要約は捨てる', validateSummary({ summary_ja: '157.0.1.1 に更新', who_ja: 'a', action_ja: 'b' }, item) !== null);
check('ある版数なら通る', validateSummary({ summary_ja: '156.0.8078.47 に更新', who_ja: 'a', action_ja: 'b' }, item) === null);
check('電話番号は捨てる', validateSummary({ summary_ja: '0120-000-000 に電話', who_ja: 'a', action_ja: 'b' }, item) !== null);
check('ダウンロード案内は捨てる', validateSummary({ summary_ja: 'ここからダウンロード', who_ja: 'a', action_ja: 'b' }, item) !== null);

// 5. 組み立て：悪用確認つきの Chrome 投稿が速報になり、無いときは速報なし
const now = new Date('2026-10-22T00:00:00Z');
const post = (over) => ({ id: 'x', title: 'Stable Channel Update for Desktop', url: 'https://example.invalid/p', published: '2026-10-20T00:00:00Z', updated: '2026-10-20T00:00:00Z', fixed_version: '156.0.8078.47', versions: ['156.0.8078.47'], cves: ['CVE-2026-1'], exploited_cves: [], text: 'x', ...over });
const a1 = assemble({ chrome: [post({ exploited_cves: ['CVE-2026-1'] })] }, { now });
check('悪用確認つき→速報1件・min_safe が付く', a1.alerts.length === 1 && a1.browsers.chrome.min_safe === '156.0.8078.47');
const a2 = assemble({ chrome: [post({})] }, { now });
check('悪用確認なし→速報0件・min_safe は null', a2.alerts.length === 0 && a2.browsers.chrome.min_safe === null);
const a3 = assemble({ chrome: null }, { now });
check('Chrome の情報源が取れない→status unknown', a3.browsers.chrome.status === 'unknown');
const a4 = assemble({ chrome: [post({ published: '2026-01-01T00:00:00Z', exploited_cves: ['CVE-2026-1'] })] }, { now });
check('期間外の投稿は速報にしない', a4.alerts.length === 0);

// 6. 製品の種類分け
check('KEV の Google/Chromium V8 は chrome', classify('Google', 'Chromium V8') === 'browser-chrome');
check('Fortinet は other（家庭には関係なし）', classify('Fortinet', 'FortiOS') === 'other');
check('Microsoft Edge は edge', classify('Microsoft', 'Edge (Chromium-based)') === 'browser-edge');
check('Fortinet の Multiple Products を Apple にしない', classify('Fortinet', 'Multiple Products') === 'other');
check('Apple の Multiple Products は os-apple', classify('Apple', 'Multiple Products') === 'os-apple');
check('SharePoint は家庭向け office に入れない', classify('Microsoft', 'SharePoint') === 'other');
check('Microsoft Windows は os-windows', classify('Microsoft', 'Windows') === 'os-windows');
check('vendor 無し（日本語タイトル）は文言で見る', classify('', 'Google Chrome の脆弱性について') === 'browser-chrome');
import { parseEnglishDate } from './build.js';
check('英語の日付が前日にずれない', parseEnglishDate('September 4, 2026').toISOString().slice(0, 10) === '2026-09-04');

// 7. 守りの行動（自分では直せない脅威）
const adv = (o) => protectAdvice(o).join(' / ');
check('認証突破（CWE-287）→パスワード変更と二段階認証', /パスワード/.test(adv({ cls: 'other', cwes: ['CWE-287'], exploited: true })) && /二段階認証/.test(adv({ cls: 'other', cwes: ['CWE-287'], exploited: true })));
check('サプライチェーン→鍵の作り直し', /鍵/.test(adv({ cls: 'other', text: 'malicious package published to PyPI (supply chain)', exploited: true })));
check('情報流出（日本語）→ログイン通知の確認', /ログイン通知/.test(adv({ cls: 'other', text: '不正アクセスによる情報漏えいについて' })));
check('フィッシング→添付を開かない', /添付/.test(adv({ cls: 'other', text: 'フィッシングメールに注意' })));
check('サーバー製品の悪用確認→運営の案内に従う', /運営/.test(adv({ cls: 'other', text: 'FortiOS command injection', exploited: true })));
// 「運営からの案内（パスワード変更の依頼など）」の文にも「パスワード」が入るので、判定は「パスワードを変える」の有無で見る
check('「unauthenticated attacker」だけでパスワード変更を出さない', !/パスワードを変える/.test(adv({ cls: 'other', text: 'Plex Media Server contains a server-side request forgery vulnerability that allows an unauthenticated attacker to …', exploited: true })));
check('「authenticated attacker」だけでも出さない', !/パスワードを変える/.test(adv({ cls: 'other', text: 'allows an authenticated attacker to execute code', exploited: true })));
check('improper authentication は出す', /パスワードを変える/.test(adv({ cls: 'os-apple', text: 'Apple macOS Improper Authentication Vulnerability' })));
check('ブラウザの悪用確認→守りは1行だけ', protectAdvice({ cls: 'browser-chrome', text: 'type confusion in V8', exploited: true }).length === 1);
check('守りは最大3つ', protectAdvice({ cls: 'other', text: 'supply chain credential leak phishing', cwes: ['CWE-287', 'CWE-200'], exploited: true }).length <= 3);
check('出す文に電話番号やダウンロード案内が無い', !/\d{2,4}-\d{2,4}-\d{3,4}|ダウンロード/.test(adv({ cls: 'other', text: 'supply chain credential leak phishing', cwes: ['CWE-287', 'CWE-200'], exploited: true })));
check('サーバー製品で修正版なし→protect', kindOf('other', {}) === 'protect');
check('ブラウザ→update', kindOf('browser-chrome', { chrome: '1.0.0.0' }) === 'update');

function throws(fn) { try { fn(); return false; } catch { return true; } }

const ng = results.filter((r) => !r.ok);
for (const r of results) console.log(`${r.ok ? 'OK ' : 'NG '} ${r.name}${r.detail ? ' — ' + r.detail : ''}`);
console.log(`\nselftest: ${results.length - ng.length}/${results.length} OK, NG ${ng.length}`);
process.exit(ng.length ? 1 : 0);
