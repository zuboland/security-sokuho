// 画面の司令塔。Rust 側（invoke）→ 解析 → 判定 → 描画 → 通知／更新。
// 設定は localStorage（WebView2 のアプリ領域・外に出ない）。
import { parseWingetList } from './winget_parse.js';
import { judge } from './judge.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const FEED_BASE = localStorage.getItem('feedBase') || 'https://zuboland.github.io/security-sokuho/';
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const LABELS = { required: '要対応', unknown: '判定不能', ok: '対応済み', quiet: '速報なし' };

async function fetchJson(name) {
  const res = await fetch(new URL(name, FEED_BASE).toString(), { cache: 'no-store', signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trimStart().startsWith('{')) throw new Error(`${name}: not JSON`);
  return JSON.parse(text);
}

let busy = false;
let lastUpgradeLog = null; // {id, text, at}
async function check() {
  if (busy) return; busy = true;
  setStatus('確認中…');
  try {
    const [feed, affected, catalog, browsers, wl, reg, os] = await Promise.all([
      fetchJson('feed.json'), fetchJson('affected.json'), fetchJson('catalog.json'), fetchJson('browsers.json'),
      invoke('winget_list'), invoke('registry_apps'), invoke('os_info'),
    ]);
    const parsed = parseWingetList(wl.stdout);
    const installed = [...parsed.items, ...reg]; // winget が主・レジストリは保険（同じ物が2回出たら judge がいちばん新しい版数を採る）
    const result = judge({ installed, catalog, affected, feed, browsers });
    const state = { checked_at: new Date().toISOString(), winget_ok: parsed.ok && wl.ok, winget_error: wl.ok ? null : (wl.stderr || `exit ${wl.code}`), os, result, alerts: (feed.items || []).filter((i) => i.severity === 'critical').slice(0, 10), catalog_count: catalog.products.length };
    localStorage.setItem('state', JSON.stringify(state));
    render(state);
    await notifyIfNeeded(state);
    await invoke('set_tray_tooltip', { text: `緊急セキュリティ速報：${result.summary.required ? '要対応 ' + result.summary.required + ' 件' : 'いま緊急の速報はありません'}` });
    setStatus(`最終確認 ${new Date().toLocaleString('ja-JP')}`);
  } catch (e) {
    const prev = JSON.parse(localStorage.getItem('state') || 'null');
    render(prev, String(e.message || e));
    setStatus(`確認できませんでした：${e.message || e}`);
  } finally { busy = false; }
}

function setStatus(t) { $('status').textContent = t; }

function render(state, error = null) {
  if (!state) {
    document.body.className = 'is-unknown';
    $('headline').textContent = '確認できませんでした';
    $('lead').textContent = error || '';
    return;
  }
  const { result } = state;
  const s = result.summary;
  const overall = s.required ? 'required' : (!state.winget_ok || s.unknown) ? 'unknown' : 'ok';
  document.body.className = `is-${overall}`;
  $('stripe').className = `stripe ${overall === 'required' ? '' : overall === 'unknown' ? 'amber' : 'quiet'}`;
  $('kanji').textContent = overall === 'required' ? '要対応' : overall === 'unknown' ? '判定不能' : '安全確認';
  $('headline').textContent = overall === 'required' ? `更新が必要なソフトが ${s.required} 件あります` : overall === 'unknown' ? (state.winget_ok ? '一部は確認できませんでした' : 'winget が使えず、確認できませんでした') : 'いま、対応が必要なものはありません';
  $('lead').textContent = error ? `（前回の結果を表示しています。今回の確認は失敗：${error}）` : state.winget_ok ? `見ている製品 ${s.watched} 件（対応表 ${state.catalog_count} 製品のうち、このPCに入っている物）。悪用が確認された脆弱性だけを通知します。` : `${state.winget_error || ''}　Windows の「アプリ インストーラー」が入っているか確かめてください。`;
  $('counts').innerHTML = ['required', 'unknown', 'ok', 'quiet'].map((k) => `<span><b>${s[k]}</b> ${LABELS[k]}</span>`).join('');
  $('time').textContent = new Date(state.checked_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) + ' 確認';
  $('grid').innerHTML = result.products.map(cardHtml).join('') || '<p class="muted">対応表にある製品がこのPCに見つかりませんでした。</p>';
  for (const b of document.querySelectorAll('[data-upgrade]')) b.addEventListener('click', () => upgrade(b.dataset.upgrade, b));
  if (lastUpgradeLog) {
    const p = result.products.find((x) => x.update?.id === lastUpgradeLog.id);
    const el = p && document.getElementById(`log-${p.key}`);
    if (el) { el.hidden = false; el.textContent = lastUpgradeLog.text + (p.verdict === 'required' ? '\n→ まだ修正版に届いていません。' : '\n→ 再確認しました（上の版数が今の状態）。'); }
  }
  for (const b of document.querySelectorAll('[data-open]')) b.addEventListener('click', () => invoke('open_external', { url: b.dataset.open }));
  if (state.os?.build) { $('os').hidden = false; $('osver').textContent = `${state.os.product} ${state.os.display_version} (ビルド ${state.os.build}.${state.os.ubr})`; }
  $('watch').textContent = `対応表 ${state.catalog_count} 製品／このPCで見つかった ${s.watched} 件：` + result.products.map((p) => `${p.label} ${p.version || '?'}`).join('、');
  $('alerts').innerHTML = (state.alerts || []).map((i) => `<div class="row"><div class="t"><span class="tag">${esc(i.product_label || '')}</span>${esc(i.title_ja || i.title || '')}</div><div class="a">${esc(i.action_ja || '')}</div></div>`).join('');
}

function cardHtml(p) {
  const f = p.findings.filter((x) => x.verdict !== 'ok');
  const upd = p.update || {};
  let action = '';
  if (p.verdict === 'required' || p.available) {
    if (upd.kind === 'winget' && upd.id) action = `<button class="btn ${p.verdict === 'required' ? '' : 'soft'}" data-upgrade="${esc(upd.id)}">${p.verdict === 'required' ? '今すぐ更新する' : '更新する'}（${esc(p.version || '')} → ${esc(p.available || '最新')}）</button>`;
    else if (upd.kind === 'store') action = `<button class="btn soft" data-open="ms-windows-store://downloadsandupdates">ストアの更新を開く</button>`;
    else action = `<div class="f">${esc(f[0]?.action_ja || '製品の案内に従って更新してください')}</div>`;
  }
  return `<div class="card ${p.verdict}">
    <h3><span class="v ${p.verdict}">${LABELS[p.verdict]}</span>${esc(p.label)}</h3>
    <div class="ver">${esc(p.raw_version || '版数不明')}${p.available ? ` → ${esc(p.available)} が利用可能` : ''}</div>
    ${f.map((x) => `<div class="f"><b>${esc(x.title)}</b>${x.exploited ? ' <span class="tag">悪用確認</span>' : ''}<br>${x.fixed.length ? `修正版 ${esc(x.fixed.join(' / '))} 以上に。` : ''}${esc(x.summary_ja || '')}${x.advice_ja?.length ? `<ul class="advice">${x.advice_ja.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}</div>`).join('')}
    ${action}
    <div class="log" id="log-${esc(p.key)}" hidden></div>
  </div>`;
}

async function upgrade(id, button) {
  if (button.dataset.busy) return; // 二重押し防止
  button.dataset.busy = '1';
  button.disabled = true; button.textContent = '更新しています…（1〜3分。Windows の確認画面が出たら「はい」）';
  const log = button.parentElement.querySelector('.log'); log.hidden = false;
  log.textContent = `winget upgrade --id ${id}\n管理者権限が要るソフトでは Windows の「このアプリがデバイスに変更を加えることを許可しますか？」が出ます。「はい」で続き、「いいえ」なら更新は行われません。\n`;
  // 🚨 UAC を放置すると winget が終わらない（2026-10-22 実測＝VLC で consent.exe 待ちのまま6分超）。10分で「止まっています」を出して押し直せるようにする
  const stuck = setTimeout(() => { button.textContent = 'Windows の確認で止まっています（画面の確認ダイアログを見てください）'; }, 10 * 60 * 1000);
  try {
    const r = await invoke('winget_upgrade', { id });
    clearTimeout(stuck);
    log.textContent += stripControl((r.stdout || '') + (r.stderr || '')) + `\n(exit ${r.code})\n`;
    // 再描画で消えないように、直近の更新ログは state と別に持つ（render が差し込む）
    lastUpgradeLog = { id, text: log.textContent, at: new Date().toISOString() };
    // 🚨 終了値だけで「完了」と言わない。もう一度一覧を取って版数が上がったかを実測する
    button.textContent = '結果を確かめています…';
    await check();
  } catch (e) {
    clearTimeout(stuck);
    log.textContent += `失敗: ${e}\n`;
    button.disabled = false; button.textContent = 'もう一度試す'; delete button.dataset.busy;
  }
}

/** winget の進捗バー（制御文字・CR の上書き）を落として読める形にする */
function stripControl(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').replace(/\r(?!\n)/g, '\n').replace(/[▒█ ]{6,}/g, ' ').replace(/\n{3,}/g, '\n\n');
}

async function notifyIfNeeded(state) {
  if (localStorage.getItem('notify') === 'off') return;
  for (const key of state.result.summary.notify) {
    const p = state.result.products.find((x) => x.key === key);
    const f = p.findings.find((x) => x.verdict === 'required' && x.exploited);
    const nkey = `notified:${key}:${f.item_id}`;
    if (localStorage.getItem(nkey)) continue;
    await invoke('notify', { title: `緊急セキュリティ速報：${p.label} を更新してください`, body: `悪用が確認された脆弱性があります。${p.raw_version || ''} → ${f.fixed[0] || '最新'} 以上に。このアプリを開いて「今すぐ更新する」を押してください。電話やダウンロードを求めることはありません。` });
    localStorage.setItem(nkey, new Date().toISOString());
  }
}

$('recheck').addEventListener('click', check);
$('winupdate').addEventListener('click', () => invoke('open_external', { url: 'ms-settings:windowsupdate' }));
$('notify').checked = localStorage.getItem('notify') !== 'off';
$('notify').addEventListener('change', () => localStorage.setItem('notify', $('notify').checked ? 'on' : 'off'));
invoke('get_autostart').then((v) => { $('autostart').checked = !!v; }).catch(() => {});
$('autostart').addEventListener('change', async () => { try { $('autostart').checked = await invoke('set_autostart', { enabled: $('autostart').checked }); } catch (e) { setStatus(`自動起動の設定に失敗：${e}`); } });
listen('check-now', check);

const prev = JSON.parse(localStorage.getItem('state') || 'null');
if (prev) render(prev);
check();
setInterval(check, CHECK_INTERVAL_MS);
