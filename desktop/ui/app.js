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
const STALE_HOURS = 24; // 30分ごとの配信が24時間止まっていたら「古い」＝判定不能（古い安全判定を現在の確認として出さない・監査R2/R3）
const LABELS = { required: '要対応', unknown: '判定不能', ok: '対応済み', quiet: '速報なし' };
const WHY = { version: '版数が読めない', pending: '影響範囲（NVD）が未取得', no_cpe: 'この製品の影響範囲の対応表がない', source: 'ブラウザの情報源が止まっている' };

async function fetchJson(name) {
  const res = await fetch(new URL(name, FEED_BASE).toString(), { cache: 'no-store', signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trimStart().startsWith('{')) throw new Error(`${name}: not JSON`);
  const j = JSON.parse(text);
  if (j.schema !== 1) throw new Error(`${name}: schema ${j.schema}`);
  return j;
}

function validateFeeds({ feed, affected, catalog, browsers }) {
  if (!Array.isArray(feed.items)) return 'feed.items';
  if (!affected.cves || typeof affected.cves !== 'object') return 'affected.cves';
  if (!Array.isArray(catalog.products)) return 'catalog.products';
  for (const k of ['chrome', 'edge']) {
    const b = browsers[k];
    if (!b || !['ok', 'unknown'].includes(b.status)) return `browsers.${k}`;
    if (!(b.min_safe === null || (typeof b.min_safe === 'string' && /^\d+(\.\d+){1,3}$/.test(b.min_safe)))) return `browsers.${k}.min_safe`;
  }
  return null;
}

let inflight = null; // 確認は同時に1つ
let lastUpgradeLog = null; // {id, text, at}
function check() { if (!inflight) inflight = runCheck().finally(() => { inflight = null; }); return inflight; }

async function runCheck() {
  setStatus('確認中…');
  try {
    const [feed, affected, catalog, browsers, status, wl, reg, os] = await Promise.all([
      fetchJson('feed.json'), fetchJson('affected.json'), fetchJson('catalog.json'), fetchJson('browsers.json'), fetchJson('status.json').catch(() => null),
      invoke('winget_list'), invoke('registry_apps'), invoke('os_info'),
    ]);
    const bad = validateFeeds({ feed, affected, catalog, browsers });
    if (bad) throw new Error(`配信の形が想定と違います（${bad}）`);
    const genAt = status?.generated_at ? Date.parse(status.generated_at) : NaN;
    const stale = Number.isNaN(genAt) || Date.now() - genAt > STALE_HOURS * 3600 * 1000;
    const parsed = parseWingetList(wl.stdout);
    const installed = [...parsed.items, ...reg]; // winget が主・レジストリは保険（同じ実体なら新しい版数を採る）
    const result = judge({ installed, catalog, affected, feed, browsers });
    const state = {
      checked_at: new Date().toISOString(), generated_at: status?.generated_at || null, stale,
      winget_ok: wl.ok && parsed.ok, winget_error: wl.ok ? (parsed.ok ? null : `一覧の形が読めません（${parsed.reason}）`) : (wl.timed_out ? 'winget が3分以内に応答しませんでした' : (wl.stderr || `exit ${wl.code}`).slice(0, 200)),
      os, result, alerts: feed.items.filter((i) => i.severity === 'critical').slice(0, 10), catalog_count: catalog.products.length,
      pending: affected.pending || [], sources_failed: (status?.sources_failed || []).map((f) => f.source || f),
    };
    localStorage.setItem('state', JSON.stringify(state));
    render(state);
    if (!stale) await notifyIfNeeded(state);
    await invoke('set_tray_tooltip', { text: `緊急セキュリティ速報：${stale ? '配信が古く判定不能' : result.summary.required ? '要対応 ' + result.summary.required + ' 件' : result.summary.unknown ? '判定不能 ' + result.summary.unknown + ' 件' : 'いま緊急の速報はありません'}` });
    setStatus(`確認 ${new Date().toLocaleString('ja-JP')}`);
  } catch (e) {
    const prev = JSON.parse(localStorage.getItem('state') || 'null');
    render(prev, String(e.message || e));
    setStatus(`確認できませんでした：${e.message || e}`);
  }
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
  const overall = error || state.stale || !state.winget_ok ? 'unknown' : s.required ? 'required' : s.unknown ? 'unknown' : 'ok';
  document.body.className = `is-${overall}`;
  $('stripe').className = `stripe ${overall === 'required' ? '' : overall === 'unknown' ? 'amber' : 'quiet'}`;
  $('kanji').textContent = overall === 'required' ? '要対応' : overall === 'unknown' ? '判定不能' : '安全確認';
  $('headline').textContent = overall === 'required' ? `更新が必要なソフトが ${s.required} 件あります`
    : error ? '今回の確認は失敗しました（前回の結果を表示）'
    : state.stale ? '速報の配信が止まっていて、判定できません'
    : !state.winget_ok ? 'winget が使えず、確認できませんでした'
    : s.unknown ? `${s.unknown} 件は判定材料が足りません（「大丈夫」とは言いません）`
    : 'いま、対応が必要なものはありません';
  $('lead').textContent = error ? `（${error}）`
    : state.stale ? `配信の最終更新 ${state.generated_at ? new Date(state.generated_at).toLocaleString('ja-JP') : '不明'}。古い情報で「大丈夫」とは言いません。`
    : state.winget_ok ? `見ている製品 ${s.watched} 件（対応表 ${state.catalog_count} 製品のうち、このPCに入っている物）。悪用が確認された脆弱性だけを通知します。${state.sources_failed?.length ? `　※取れていない情報源：${state.sources_failed.join('・')}` : ''}`
    : `${state.winget_error || ''}　Windows の「アプリ インストーラー」が入っているか確かめてください。`;
  $('counts').innerHTML = ['required', 'unknown', 'ok', 'quiet'].map((k) => `<span><b>${s[k]}</b> ${LABELS[k]}</span>`).join('');
  $('time').textContent = `${new Date(state.checked_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })} 確認${state.generated_at ? `／配信 ${new Date(state.generated_at).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}` : ''}`;
  $('grid').innerHTML = result.products.map(cardHtml).join('') || '<p class="muted">対応表にある製品がこのPCに見つかりませんでした。</p>';
  for (const b of document.querySelectorAll('[data-upgrade]')) b.addEventListener('click', () => upgrade(b.dataset.upgrade, b));
  for (const b of document.querySelectorAll('[data-open]')) b.addEventListener('click', () => invoke('open_external', { url: b.dataset.open }));
  if (lastUpgradeLog) {
    const el = document.getElementById(`log-${lastUpgradeLog.id}`);
    if (el) { el.hidden = false; el.textContent = lastUpgradeLog.text; }
  }
  if (state.os?.build) { $('os').hidden = false; $('osver').textContent = `${state.os.product} ${state.os.display_version} (ビルド ${state.os.build}.${state.os.ubr})`; }
  $('watch').textContent = `対応表 ${state.catalog_count} 製品／このPCで見つかった ${s.watched} 件：` + result.products.map((p) => `${p.label} ${p.raw_version || '?'}`).join('、');
  $('alerts').innerHTML = (state.alerts || []).map((i) => `<div class="row"><div class="t"><span class="tag">${esc(i.product_label || '')}</span>${esc(i.title_ja || i.title || '')}</div><div class="a">${esc(i.action_ja || '')}</div></div>`).join('');
}

function cardHtml(p) {
  const shown = p.findings.filter((x) => x.verdict !== 'ok');
  const rows = p.instances.map((inst) => {
    const fs = shown.filter((x) => x.instance === inst.key);
    const worst = fs.find((x) => x.verdict === 'required') ? 'required' : fs.find((x) => x.verdict === 'unknown') ? 'unknown' : null;
    const upd = p.update || {};
    let action = '';
    const wingetId = inst.winget_id || (upd.kind === 'winget' ? upd.id : null);
    if (worst === 'required' || inst.available) {
      if (wingetId) action = `<button class="btn ${worst === 'required' ? '' : 'soft'}" data-upgrade="${esc(wingetId)}">${worst === 'required' ? '今すぐ更新する' : '更新する'}（${esc(inst.raw_version || '')} → ${esc(inst.available || '最新')}）</button>`;
      else if (upd.kind === 'store') action = `<button class="btn soft" data-open="ms-windows-store://downloadsandupdates">ストアの更新を開く</button>`;
      else action = `<div class="f">${esc(fs[0]?.action_ja || '製品の案内に従って更新してください')}</div>`;
    }
    return `<div class="inst">
      <div class="ver">${esc(inst.raw_version || '版数不明')}${inst.available ? ` → ${esc(inst.available)} が利用可能` : ''}${p.instances.length > 1 && inst.winget_id ? ` <span class="tiny">(${esc(inst.winget_id)})</span>` : ''}</div>
      ${fs.map((x) => `<div class="f"><b>${esc(x.title)}</b>${x.exploited ? ' <span class="tag">悪用確認</span>' : ''}${x.verdict === 'unknown' ? ` <span class="tiny">判定不能：${esc(WHY[x.why] || x.why || '')}</span>` : ''}<br>${x.fixed.length ? `修正版 ${esc(x.fixed.join(' / '))} 以上に。` : ''}${x.also_affected.length ? `${esc(x.also_affected.join(' / '))} も対象（公式が示す修正版へ）。` : ''}${esc(x.summary_ja || '')}${x.advice_ja?.length ? `<ul class="advice">${x.advice_ja.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}</div>`).join('')}
      ${action}
      <div class="log" id="log-${esc(wingetId || p.key)}" hidden></div>
    </div>`;
  }).join('');
  return `<div class="card ${p.verdict}"><h3><span class="v ${p.verdict}">${LABELS[p.verdict]}</span>${esc(p.label)}</h3>${rows}</div>`;
}

/** winget の進捗バー（制御文字・CR の上書き）を落として読める形にする */
function stripControl(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').replace(/\r(?!\n)/g, '\n').replace(/[▒█ ]{6,}/g, ' ').replace(/\n{3,}/g, '\n\n');
}

async function upgrade(id, button) {
  if (button.dataset.busy) return; // 二重押し防止
  button.dataset.busy = '1';
  button.disabled = true; button.textContent = '更新しています…（1〜3分。Windows の確認画面が出たら「はい」）';
  const log = button.parentElement.querySelector('.log'); log.hidden = false;
  log.textContent = `winget upgrade --id ${id}\n管理者権限が要るソフトでは Windows の「このアプリがデバイスに変更を加えることを許可しますか？」が出ます。「はい」で続き、「いいえ」なら更新は行われません。15分応答が無ければ中止します。\n`;
  try {
    const r = await invoke('winget_upgrade', { id });
    log.textContent += stripControl((r.stdout || '') + (r.stderr || '')) + `\n(exit ${r.code}${r.timed_out ? '・時間切れで中止' : ''})\n`;
    lastUpgradeLog = { id, text: log.textContent, at: new Date().toISOString() };
    // 🚨 終了値だけで「完了」と言わない。もう一度一覧を取って版数が上がったかを実測する
    button.textContent = '結果を確かめています…';
    await check();
  } catch (e) {
    log.textContent += `失敗: ${e}\n`;
    button.disabled = false; button.textContent = 'もう一度試す'; delete button.dataset.busy;
  }
}

async function notifyIfNeeded(state) {
  if (localStorage.getItem('notify') === 'off') return;
  // 要対応×悪用確認の finding を全部見る（先頭だけ見ると別件の新しい速報が抑止される・監査R1 F13）
  for (const p of state.result.products) {
    for (const f of p.findings.filter((x) => x.verdict === 'required' && x.exploited)) {
      const nkey = `notified:${p.key}:${f.instance}:${f.item_id}`;
      if (localStorage.getItem(nkey)) continue;
      localStorage.setItem(nkey, new Date().toISOString());
      await invoke('notify', { title: `緊急セキュリティ速報：${p.label} を更新してください`, body: `悪用が確認された脆弱性があります。${f.instance_version || ''} → ${f.fixed[0] ? f.fixed[0] + ' 以上' : '公式が示す修正版'}に。このアプリを開いて「今すぐ更新する」を押してください。電話やダウンロードを求めることはありません。` });
    }
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
