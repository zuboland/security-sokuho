import { settingsUrl, countLabel } from './common.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const name = (b) => (b === 'edge' ? 'Microsoft Edge' : b === 'chrome' ? 'Google Chrome' : 'このブラウザ');

function renderStatus(state) {
  const r = state?.result;
  const el = $('status');
  if (!r) { el.innerHTML = '<h2>確認中…</h2>'; return; }
  document.body.className = `is-${r.verdict}`;
  $('stripe').className = `stripe ${r.verdict === 'required' ? '' : r.verdict === 'unknown' ? 'amber' : 'quiet'}`;
  // 「取得した時刻」と「配信が作られた時刻」は別物（監査R2/R3）
  $('time').textContent = (state.checked_at ? new Date(state.checked_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) + ' 確認' : '') + (state.generated_at ? '／配信 ' + new Date(state.generated_at).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '');
  const n = name(r.browser);
  const ver = r.version ? esc(r.version) : '—';

  if (r.verdict === 'required') {
    el.innerHTML = `
      <p class="big">更新してください</p>
      <h2>${n} に、悪用が確認された脆弱性があります</h2>
      <div class="vers">
        <div class="v"><span>今の版数</span><b>${ver}</b></div><div class="arrow">→</div>
        <div class="v to"><span>この版数以上に</span><b>${esc(r.info.min_safe)}</b></div>
      </div>
      <p class="tiny">対象：${esc((r.info.exploited_cves || []).join(', '))}（${esc(r.info.alert_date || '')}）</p>
      <button id="update" class="btn">更新画面を開く</button>
      <p class="tiny" style="margin-top:6px">更新が終わると「再起動」ボタンが出ます（約1分）。<a href="alert.html" target="_blank">速報の全文</a></p>`;
  } else if (r.verdict === 'ok') {
    const quiet = r.reason === 'quiet';
    el.innerHTML = `
      <p class="big">${quiet ? '速報なし' : '対応済み'}</p>
      <h2>${quiet ? `いま ${n} に緊急の速報はありません` : `${n} は修正版以上です`}</h2>
      <p class="tiny mono">今の版数 ${ver}${quiet ? '' : `　／　修正版 ${esc(r.info.min_safe)} 以上`}</p>
      ${r.behind_latest ? `<p class="tiny">最新の安定版より少し古い版です。急ぎではありませんが、次の再起動で更新されます。</p><button id="update" class="btn soft">更新画面を開く</button>` : ''}`;
  } else {
    const why = {
      no_data: `${n} の修正版の情報が取れていません（配信側の解析が止まっている可能性）`,
      no_version: 'ブラウザの版数を取得できませんでした',
      fetch_failed: `速報の配信元に届きませんでした${state.fetch_error ? '（' + esc(state.fetch_error) + '）' : ''}`,
      bad_feed: `配信の形が想定と違います（${esc(r.detail || '')}）。配信側の不具合の可能性があるので、古い判定は使いません`,
      stale: `配信が ${r.generated_at ? esc(new Date(r.generated_at).toLocaleString('ja-JP')) : '不明な時刻'} から更新されていません。古い情報で「大丈夫」とは言いません`,
      compare_failed: '版数の形が想定と違います',
    }[r.reason] || '確認できませんでした';
    el.innerHTML = `
      <p class="big">判定不能</p>
      <h2>確認できませんでした</h2>
      <p>${why}。<b>「大丈夫」とは言いません。</b></p>
      <p class="tiny">手で確かめる：メニュー →「ヘルプ」→「${n} について」に「最新です」と出ていれば問題ありません。</p>
      <button id="update" class="btn soft">その画面を開く</button>`;
  }
  $('update')?.addEventListener('click', () => chrome.tabs.create({ url: settingsUrl(r.browser) }));
}

/** 悪用確認済みの CVE を先に、残りは件数で */
function cveLine(i) {
  const ex = i.exploited_cves || [];
  const rest = (i.cves || []).filter((c) => !ex.includes(c));
  const head = [...ex.slice(0, 2), ...rest.slice(0, Math.max(0, 2 - ex.length))];
  if (!head.length) return '';
  const more = (i.cves || []).length - head.length;
  return '　' + esc(head.join(', ')) + (ex.length ? '（悪用確認）' : '') + (more > 0 ? ` 他${more}件` : '');
}

/** 今やること。1件に複数の製品（Chrome と Edge）が入っていれば製品ごとに出す（監査R4-M8） */
function actionsHtml(i) {
  const byP = i.actions_by_product && typeof i.actions_by_product === 'object' ? Object.values(i.actions_by_product).filter((s) => typeof s === 'string') : [];
  const list = byP.length > 1 ? byP : [i.action_ja || ''];
  return list.map((a) => `<div class="a">${esc(a)}</div>`).join('');
}

/** 関連する投稿（Hacker News は見出し・X はリンクだけ＝本文は配信しない） */
function postsHtml(i) {
  const posts = i.related_posts || [];
  if (!posts.length) return '';
  return `<div class="posts">${posts.slice(0, 3).map((p) => p.source === 'x'
    ? `<a href="${esc(p.url)}" target="_blank" rel="noopener"><span class="src">X</span>@${esc(p.author || '')} のポスト</a>`
    : `<a href="${esc(p.url)}" target="_blank" rel="noopener"><span class="src">HN</span>${esc(p.title || '')}</a>`).join('')}</div>`;
}

function renderAlerts(state) {
  const items = state?.alerts || [];
  const el = $('alerts');
  if (state && state.alerts_ok === false) { el.innerHTML = '<p class="tiny">速報の一覧を取得できませんでした（配信元に届かないか、形が違います）。</p>'; return; }
  const days = state?.window_days || null;
  const failed = (state?.sources_failed || []).length ? `<p class="tiny">※ 情報源のうち取れていないもの：${esc(state.sources_failed.join('・'))}</p>` : '';
  if (!items.length) { el.innerHTML = `<p class="tiny">直近${days ? days + '日' : 'の期間'}に、一般の人に関係する「悪用確認済み」の速報はありません。</p>${failed}`; return; }
  el.innerHTML = failed + items.slice(0, 8).map((i) => `
    <div class="row">
      <div class="t"><span class="tag">${esc(i.product_label || '')}</span>${esc(i.title_ja || i.title || '')}</div>
      <div class="tiny mono">${esc(i.published || '')}${cveLine(i)}</div>
      ${i.summary_ja ? `<div class="muted" style="font-size:13px;margin-top:4px">${esc(i.summary_ja)}</div>` : ''}
      ${actionsHtml(i)}
      ${(i.advice_ja || []).length ? `<ul class="advice">${i.advice_ja.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
      ${postsHtml(i)}
      <div class="tiny">${(i.sources || []).slice(0, 2).map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)}</a>`).join('・')}</div>
    </div>`).join('');
}

function breachRow(i) {
  const rumor = i.type === 'rumor';
  const tag = rumor ? '<span class="tag unconfirmed">未確認</span>' : i.basis === 'news' ? '<span class="tag news">報道</span>' : '<span class="tag">確認済み</span>';
  // HIBP は「漏えいが起きた日」と「掲載日」を分けて出す（古い漏えいの新規掲載を最近の事故に見せない）
  const when = i.basis === 'hibp' && i.breach_date ? `漏えい ${i.breach_date}・掲載 ${i.published || ''}` : (i.published || '');
  // 未確認の件は件数を出さない（配信に入っていても。X 由来の数字を確かな数のように見せない）
  const meta = [when, rumor ? '' : countLabel(i.count), (i.data_ja || []).slice(0, 4).join('・')].filter(Boolean).join('　');
  return `
    <div class="row${rumor ? ' rumor' : ''}">
      <div class="t">${tag}${esc(i.title_ja || '')}</div>
      <div class="tiny mono">${esc(meta)}</div>
      ${rumor ? `<p class="caution">${esc(i.caution_ja || '')}</p>` : ''}
      ${i.note_ja ? `<p class="tiny">${esc(i.note_ja)}</p>` : ''}
      ${(i.advice_ja || []).length ? `<ul class="advice">${i.advice_ja.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
      <div class="tiny">${(i.sources || []).filter((s) => /^https:\/\//.test(s?.url || '')).slice(0, 3).map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)}</a>`).join('・')}</div>
    </div>`;
}

function renderBreaches(state) {
  const c = $('breach-confirmed'); const r = $('breach-rumor');
  if (!state || state.breaches_ok === false) { c.innerHTML = '<p class="tiny">漏えいの一覧を取得できませんでした（配信元に届かないか、形が違います）。</p>'; r.innerHTML = ''; return; }
  const items = state.breaches || [];
  const failed = (state.breaches_failed || []).length ? `<p class="tiny">※ 取れていない情報源：${esc(state.breaches_failed.join('・'))}</p>` : '';
  const conf = items.filter((i) => i.type === 'confirmed').slice(0, 10);
  const rum = items.filter((i) => i.type === 'rumor').slice(0, 5);
  const stale = state.breaches_stale ? '<p class="tiny">※ 漏えいの情報源が48時間以上更新されていません。この一覧は古い可能性があり、通知も止めています。</p>' : '';
  c.innerHTML = failed + stale + (conf.length ? conf.map(breachRow).join('') : '<p class="tiny">直近30日に、見ている情報源で報じられた漏えいはありません。</p>')
    + '<p class="tiny">一覧は報道（ScanNetSecurity・Security NEXT の記事）と <a href="https://haveibeenpwned.com/" target="_blank" rel="noopener">Have I Been Pwned</a>（<a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener">CC BY 4.0</a>）によります。すべての漏えいが載るわけではありません。</p>';
  // X の確認が動いていない・止まっているときに「話題はありません」と言わない（監査 R2・R3）
  const w = state.rumor_watch;
  const lastOk = w?.last_ok_at ? Date.parse(w.last_ok_at) : NaN;
  if (!w || !w.enabled) r.innerHTML = '<p class="tiny">X の話題の確認は行っていません。</p>';
  else if (!Number.isFinite(lastOk) || Date.now() - lastOk > 12 * 3600 * 1000) r.innerHTML = (rum.length ? rum.map(breachRow).join('') : '') + '<p class="tiny">X の話題の確認が12時間以上止まっています。</p>';
  else r.innerHTML = rum.length ? rum.map(breachRow).join('') : '<p class="tiny">いま X で話題の未確認の漏えいはありません（3時間ごとに確認）。</p>';
}

async function load() {
  const { state } = await chrome.storage.local.get('state');
  renderStatus(state);
  renderAlerts(state);
  renderBreaches(state);
  if (location.hash === '#breaches') $('breaches').scrollIntoView();
}

$('recheck').addEventListener('click', async () => {
  $('recheck').disabled = true;
  try { await chrome.runtime.sendMessage({ type: 'check-now' }); await load(); }
  catch (e) { $('status').insertAdjacentHTML('beforeend', `<p class="tiny">表示に失敗：${esc(e.message || e)}</p>`); }
  finally { $('recheck').disabled = false; }
});

load();
if (!(await chrome.storage.local.get('state')).state) chrome.runtime.sendMessage({ type: 'check-now' }).then(load);
