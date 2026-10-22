import { settingsUrl } from './common.js';

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

async function load() {
  const { state } = await chrome.storage.local.get('state');
  renderStatus(state);
  renderAlerts(state);
}

$('recheck').addEventListener('click', async () => {
  $('recheck').disabled = true;
  try { await chrome.runtime.sendMessage({ type: 'check-now' }); await load(); }
  catch (e) { $('status').insertAdjacentHTML('beforeend', `<p class="tiny">表示に失敗：${esc(e.message || e)}</p>`); }
  finally { $('recheck').disabled = false; }
});

load();
if (!(await chrome.storage.local.get('state')).state) chrome.runtime.sendMessage({ type: 'check-now' }).then(load);
