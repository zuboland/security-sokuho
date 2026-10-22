// 速報画面。鳴った瞬間に開く1枚。状態（required／ok／unknown）で文言と色を変える。
import { settingsUrl } from './common.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const name = (b) => (b === 'edge' ? 'Microsoft Edge' : b === 'chrome' ? 'Google Chrome' : 'このブラウザ');

function render(state) {
  const r = state?.result;
  if (!r) return;
  document.body.className = `is-${r.verdict}`;
  $('stripe').className = `stripe ${r.verdict === 'required' ? '' : r.verdict === 'unknown' ? 'amber' : 'quiet'}`;
  $('time').textContent = state.checked_at ? new Date(state.checked_at).toLocaleString('ja-JP') : '';
  const alertItem = (state.alerts || []).find((a) => a.id === r.info?.alert_id) || null;
  const n = name(r.browser);

  if (r.verdict === 'required') {
    $('kanji').innerHTML = '緊急速報<small>SECURITY ALERT</small>';
    $('eyebrow').textContent = '緊急セキュリティ速報 ── 悪用が確認された脆弱性';
    $('title').textContent = `${n} を今すぐ更新してください`;
    $('lead').innerHTML = `細工されたページを開くだけで被害を受けるおそれのある欠陥が、<b>実際に攻撃に使われている</b>と公式（${r.browser === 'edge' ? 'Microsoft' : 'Google'}、または CISA）が発表しました。あなたの ${esc(n)} はまだ修正前の版です。`;
    $('vers').hidden = false;
    $('v-now').textContent = r.version || '—';
    $('v-safe').textContent = r.info.min_safe;
    $('steps').innerHTML = [
      '下の「更新画面を開く」を押す（ブラウザ自身の設定画面が開きます）',
      '更新が自動で始まります。終わると「再起動」ボタンが出るので押す',
      '再起動後、右上の盾アイコンの「!」が消えていれば完了',
    ].map((s) => `<li>${s}</li>`).join('');
  } else if (r.verdict === 'ok') {
    $('kanji').innerHTML = '安全確認<small>OK</small>';
    $('eyebrow').textContent = '緊急セキュリティ速報';
    $('title').textContent = r.reason === 'quiet' ? 'いま緊急の速報はありません' : `${n} は対応済みです`;
    $('lead').innerHTML = r.reason === 'quiet' ? `直近90日に、${esc(n)} で悪用が確認された脆弱性は出ていません。` : `修正版（${esc(r.info.min_safe)}）以上の版数です。追加の操作は要りません。`;
    $('vers').hidden = r.reason === 'quiet';
    $('v-now').textContent = r.version || '—';
    $('v-safe').textContent = r.info?.min_safe || '—';
    $('update').textContent = '更新画面を開く（確認だけ）';
    $('update').classList.add('soft');
    $('after').textContent = '';
    $('steps').innerHTML = '';
  } else {
    $('kanji').innerHTML = '判定不能<small>UNKNOWN</small>';
    $('eyebrow').textContent = '緊急セキュリティ速報';
    $('title').textContent = '確認できませんでした';
    const why = r.reason === 'stale' ? '速報の配信が止まっていて、情報が古いままです。' : r.reason === 'bad_feed' ? '配信の形が想定と違います（配信側の不具合の可能性）。' : '版数か、速報の配信元の情報が取れていません。';
    $('lead').innerHTML = `${esc(why)}<b>「大丈夫」とは言いません。</b>手で確かめてください。`;
    $('vers').hidden = true;
    $('update').textContent = `${n} の「〜について」を開く`;
    $('update').classList.add('soft');
    $('after').textContent = 'その画面に「最新です」と出ていれば問題ありません';
    $('steps').innerHTML = '';
  }

  const facts = [];
  if (r.info?.exploited_cves?.length) facts.push(['対象の脆弱性', r.info.exploited_cves.join(', ')]);
  if (r.info?.alert_date) facts.push(['発表日', r.info.alert_date]);
  if (alertItem?.summary_ja) facts.push(['何が起きるか', alertItem.summary_ja]);
  $('facts').innerHTML = facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
  // 助言・関連投稿・他の速報は毎回まとめて置き換える（足し続けると古い件が残る・監査R1 F17）
  let extra = '';
  const posts = alertItem?.related_posts || [];
  if (posts.length) {
    extra += `<div class="advice-title" style="color:var(--fg3)">この件について人が書いていること</div><div class="posts">${posts.slice(0, 5).map((p) => p.source === 'x'
      ? `<a href="${esc(p.url)}" target="_blank" rel="noopener"><span class="src">X</span>@${esc(p.author || '')} のポスト（${esc((p.created_at || '').slice(0, 10))}）</a>`
      : `<a href="${esc(p.url)}" target="_blank" rel="noopener"><span class="src">HN</span>${esc(p.title || '')}（${esc((p.created_at || '').slice(0, 10))}）</a>`).join('')}</div>`;
  }
  // 守りの行動：更新とは別に、それでもできること
  const advice = alertItem?.advice_ja || [];
  if (advice.length) extra += `<div class="advice-title">あわせてできる守り</div><ul class="advice">${advice.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>`;
  // 更新では直せない速報（サーバー側・流出など）が他にあれば、守りの行動として並べる
  const protect = (state.alerts || []).filter((a) => a.kind === 'protect' && (a.advice_ja || []).length).slice(0, 3);
  if (protect.length) extra += `<div class="advice-title">ほかに出ている速報 ── 自分では直せないが、守りはできる</div>${protect.map((a) => `<div class="row"><div class="t"><span class="tag">${esc(a.product_label)}</span>${esc(a.title_ja || a.title)}</div><ul class="advice">${a.advice_ja.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>`).join('')}`;
  $('extra').innerHTML = extra;
  const srcs = alertItem?.sources || [];
  $('sources').innerHTML = srcs.length ? '一次情報：' + srcs.slice(0, 3).map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)}</a>`).join('・') : '';

  $('update').onclick = () => chrome.tabs.create({ url: settingsUrl(r.browser) });
}

const { state } = await chrome.storage.local.get('state');
render(state);
chrome.storage.onChanged.addListener((ch, area) => { if (area === 'local' && ch.state) render(ch.state.newValue); });
