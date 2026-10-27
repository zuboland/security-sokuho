// 30分ごとに公開フィードを読み、自分のブラウザが影響を受けるときだけ通知する。
// 通知は1つの件につき1回だけ（既読を記録）。地震速報と同じで、めったに鳴らない。
import { getSettings, fetchFeed, detectBrowser, evaluate, settingsUrl, isStale, validateBrowsers, validateAlerts, validateBreaches, breachesToNotify, breachesStale, countLabel, CHECK_INTERVAL_MIN } from './common.js';

const ALARM = 'secalert-check';

chrome.runtime.onInstalled.addListener(() => { schedule(); check(); });
chrome.runtime.onStartup.addListener(() => { schedule(); check(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) check(); });
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === 'check-now') { check().then((r) => reply(r)).catch((e) => reply({ error: e.message })); return true; }
  if (msg?.type === 'open-update') { openUpdate(msg.browser); reply(true); return false; }
  return false;
});
// 通知本体をクリック→速報画面（何が起きたか・守りの行動・大きな更新ボタン）。ボタン→更新画面を直接
chrome.notifications.onClicked.addListener((id) => {
  if (id.startsWith('secalert:')) openAlertPage();
  // 漏えいの通知→一覧（ポップアップと同じ画面をタブで）。運営のサイトは開かない（偽サイト誘導と見分けがつかなくなる）
  if (id.startsWith('secalert-breach:')) chrome.tabs.create({ url: chrome.runtime.getURL('popup.html#breaches') });
});
chrome.notifications.onButtonClicked.addListener((id) => { if (id.startsWith('secalert:')) openUpdate(id.split(':')[1]); });

async function schedule() {
  const a = await chrome.alarms.get(ALARM);
  if (!a) chrome.alarms.create(ALARM, { periodInMinutes: CHECK_INTERVAL_MIN, delayInMinutes: 1 });
}

// 🚨 確認は同時に1つだけ（アラーム・手動・設定保存が重なると、古い応答が新しい要対応を巻き戻し、通知が2回出た＝監査R1 F06）
let inflight = null;
export function check() {
  if (!inflight) inflight = runCheck().finally(() => { inflight = null; });
  return inflight;
}

async function runCheck() {
  const settings = await getSettings();
  const me = await detectBrowser();
  let browsers = null; let alerts = null; let status = null; let breaches = null;
  let fetchError = null; let alertsOk = false;
  // 4つのファイルはそれぞれ独立に受け取る（browsers.json だけ失敗しても、取れた漏えいの一覧は使う・監査 R5 F10）
  const got = await Promise.allSettled(['browsers.json', 'alerts.json', 'status.json', 'breaches.json'].map((f) => fetchFeed(f, settings.feedBase)));
  [browsers, alerts, status, breaches] = got.map((g) => (g.status === 'fulfilled' ? g.value : null));
  if (got[0].status === 'rejected') fetchError = got[0].reason?.message || String(got[0].reason);
  let result;
  const bad = browsers ? validateBrowsers(browsers) : null;
  if (!browsers) result = { verdict: 'unknown', reason: 'fetch_failed', browser: me.browser, version: me.version, info: null };
  else if (bad) result = { verdict: 'unknown', reason: 'bad_feed', browser: me.browser, version: me.version, info: null, detail: bad };
  else if (isStale(status)) result = { verdict: 'unknown', reason: 'stale', browser: me.browser, version: me.version, info: browsers[me.browser === 'chromium' ? 'chrome' : me.browser] || null, generated_at: status?.generated_at || null };
  else result = evaluate(browsers, me);
  alertsOk = !!alerts && validateAlerts(alerts) === null;
  // 漏えいの一覧も配信の鮮度に従う（止まった配信の古い一覧を「いま」として出さない）
  // 漏えいの一覧はブラウザ用の鮮度（data_as_of）とは別に判定する。古いときは一覧を出して注記し、通知だけ止める（監査 R4 F05）
  const breachesOk = !!breaches && validateBreaches(breaches) === null;
  const state = {
    breaches: breachesOk ? breaches.items.slice(0, 40) : [],
    breaches_ok: breachesOk,
    breaches_failed: breachesOk ? breaches.sources_failed || [] : [],
    breaches_stale: breachesOk ? breachesStale(status) : null,
    rumor_watch: breachesOk && breaches.rumor_watch && typeof breaches.rumor_watch === 'object' ? breaches.rumor_watch : null,
    checked_at: new Date().toISOString(),
    generated_at: status?.generated_at || null,
    me,
    result,
    alerts: alertsOk ? alerts.items.slice(0, 20) : [],
    alerts_ok: alertsOk,
    window_days: alertsOk && Number.isInteger(alerts.window_days) ? alerts.window_days : null,
    sources_failed: alertsOk ? alerts.sources_failed || [] : [],
    fetch_error: fetchError,
  };
  await chrome.storage.local.set({ state });
  await paintBadge(result);
  if (result.verdict === 'required' && settings.notify) await notifyOnce(result);
  // 通知の候補は表示用の40件ではなく配信の全件から作る。漏えいの情報源が古いときは鳴らさない（監査 R3）
  if (breachesOk && settings.notify && !state.breaches_stale) await notifyBreaches(breachesToNotify(breaches.items, settings.breachNotify));
  // 正常な配信を見たときは、今有効な警告（1つ）以外の通知を消す＝解消・撤回のどちらも（監査R3-M4／R4-M7）
  if (result.verdict === 'ok' || result.verdict === 'required') await clearNotificationsExcept(result.browser, result.verdict === 'required' ? notifyId(result) : null);
  return state;
}

/** 通知の同一性＝ブラウザ＋速報 ID＋修正版（統合で同じ item id になった別の Edge 修正版を既読にしない・監査R4-M1） */
function notifyId(result) {
  return `secalert:${result.browser}:${result.info?.alert_id || 'unknown'}:${result.info?.min_safe || ''}`;
}

async function paintBadge(result) {
  const map = {
    required: { text: '!', color: '#C62828', title: '緊急セキュリティ速報：ブラウザの更新が必要です' },
    unknown: { text: '?', color: '#757575', title: '緊急セキュリティ速報：確認できませんでした' },
    ok: { text: '', color: '#2E7D32', title: '緊急セキュリティ速報：いま緊急の速報はありません' },
  };
  const m = map[result.verdict] || map.unknown;
  await chrome.action.setBadgeText({ text: m.text });
  await chrome.action.setBadgeBackgroundColor({ color: m.color });
  await chrome.action.setTitle({ title: m.title });
}

async function notifyOnce(result) {
  const id = notifyId(result);
  const key = `notified:${id}`;
  const seen = await chrome.storage.local.get(key);
  if (seen[key]) return;
  // 先に既読を立ててから通知する（同時実行で2回出さない）
  await chrome.storage.local.set({ [key]: new Date().toISOString() });
  const name = result.browser === 'edge' ? 'Microsoft Edge' : 'Google Chrome';
  const base = {
    iconUrl: 'icons/icon128.png',
    title: `緊急セキュリティ速報：${name} を更新してください`,
    message: `悪用が確認された脆弱性があります。${result.version} → ${result.info.min_safe} 以上に。クリックで詳細、ボタンで更新画面。`,
    contextMessage: 'この速報が電話やダウンロードを求めることはありません',
    priority: 2,
    requireInteraction: true,
    buttons: [{ title: '更新画面を開く' }],
  };
  try {
    // バナー画像つき（対応していない環境では basic に落とす）
    await chrome.notifications.create(id, { ...base, type: 'image', imageUrl: 'icons/banner_alert.png' });
  } catch {
    try { await chrome.notifications.create(id, { ...base, type: 'basic' }); } catch { await chrome.storage.local.remove(key); return; }
  }
  const { notified_ids = [] } = await chrome.storage.local.get('notified_ids');
  await chrome.storage.local.set({ notified_ids: [...new Set([...notified_ids, id])] });
  // 鳴った瞬間に速報画面も1回だけ開く（地震速報の全画面にあたるもの）
  await openAlertPage();
}

/** 漏えいの通知。1件1回・1回の確認で最大2件（まとめて鳴らさない）。速報画面は開かない（ブラウザの更新とは別の知らせ） */
async function notifyBreaches(list) {
  let sent = 0;
  // 既読を飛ばしてから2件（先に2件で切ると、既読の2件が3件目以降を塞ぐ・監査 R1 F03・R3）
  for (const b of list) {
    if (sent >= 2) break;
    const id = `secalert-breach:${b.id}`;
    const key = `notified:${id}`;
    if ((await chrome.storage.local.get(key))[key]) continue;
    await chrome.storage.local.set({ [key]: new Date().toISOString() });
    sent++;
    const n = countLabel(b.count);
    const basis = b.basis === 'news' ? '報道' : '確認済み';
    try {
      await chrome.notifications.create(id, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: `緊急セキュリティ速報：大きな情報漏えい（${basis}）`,
        message: `${String(b.service || b.title_ja).slice(0, 60)}（${n}）。使っているならパスワードを変えてください。クリックで詳細。`,
        contextMessage: 'この速報がパスワードの入力や電話を求めることはありません',
        priority: 1,
      });
    } catch { await chrome.storage.local.remove(key); }
  }
}

async function clearNotificationsExcept(browser, keep) {
  const { notified_ids = [] } = await chrome.storage.local.get('notified_ids');
  const mine = notified_ids.filter((id) => id.startsWith(`secalert:${browser}:`) && id !== keep);
  for (const id of mine) { try { await chrome.notifications.clear(id); } catch { /* 無ければよい */ } }
  if (mine.length) await chrome.storage.local.set({ notified_ids: notified_ids.filter((id) => !mine.includes(id)) });
}

function openUpdate(browser) {
  chrome.tabs.create({ url: settingsUrl(browser) });
}

// 速報画面は1枚だけ。tabs 権限を持たない（閲覧履歴を読む権限を増やさない）ので URL では探せず、開いたタブの id を覚えておく
async function openAlertPage() {
  const url = chrome.runtime.getURL('alert.html');
  const { alertTabId } = await chrome.storage.local.get('alertTabId');
  if (alertTabId != null) {
    try {
      const t = await chrome.tabs.get(alertTabId);
      // 覚えているタブが別のページに使われていても速報画面に戻す（監査R1 F14）
      if (t) { await chrome.tabs.update(t.id, { url, active: true }); await chrome.windows.update(t.windowId, { focused: true }); return; }
    } catch { /* 閉じられていた */ }
  }
  const tab = await chrome.tabs.create({ url });
  await chrome.storage.local.set({ alertTabId: tab.id });
}

// 実機テスト（tools/e2e_extension.py）から呼ぶため。サービスワーカーでは import() が使えない
globalThis.__secalert = { check, detectBrowser, evaluate };
