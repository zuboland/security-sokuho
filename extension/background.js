// 30分ごとに公開フィードを読み、自分のブラウザが影響を受けるときだけ通知する。
// 通知は1つの件につき1回だけ（既読を記録）。地震速報と同じで、めったに鳴らない。
import { getSettings, fetchFeed, detectBrowser, evaluate, settingsUrl, CHECK_INTERVAL_MIN } from './common.js';

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
chrome.notifications.onClicked.addListener((id) => { if (id.startsWith('secalert:')) openAlertPage(); });
chrome.notifications.onButtonClicked.addListener((id) => { if (id.startsWith('secalert:')) openUpdate(id.split(':')[1]); });

async function schedule() {
  const a = await chrome.alarms.get(ALARM);
  if (!a) chrome.alarms.create(ALARM, { periodInMinutes: CHECK_INTERVAL_MIN, delayInMinutes: 1 });
}

export async function check() {
  const settings = await getSettings();
  const me = await detectBrowser();
  let browsers = null;
  let alerts = null;
  let fetchError = null;
  try {
    [browsers, alerts] = await Promise.all([fetchFeed('browsers.json', settings.feedBase), fetchFeed('alerts.json', settings.feedBase)]);
  } catch (e) {
    fetchError = e.message;
  }
  const result = browsers ? evaluate(browsers, me) : { verdict: 'unknown', reason: 'fetch_failed', browser: me.browser, version: me.version, info: null };
  const state = {
    checked_at: new Date().toISOString(),
    me,
    result,
    alerts: alerts?.items?.slice(0, 20) || [],
    fetch_error: fetchError,
  };
  await chrome.storage.local.set({ state });
  await paintBadge(result);
  if (result.verdict === 'required' && settings.notify) await notifyOnce(result);
  return state;
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
  const alertId = result.info?.alert_id || 'unknown';
  const key = `notified:${result.browser}:${alertId}`;
  const seen = await chrome.storage.local.get(key);
  if (seen[key]) return;
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
  const id = `secalert:${result.browser}:${alertId}`;
  try {
    // バナー画像つき（対応していない環境では basic に落とす）
    await chrome.notifications.create(id, { ...base, type: 'image', imageUrl: 'icons/banner_alert.png' });
  } catch {
    await chrome.notifications.create(id, { ...base, type: 'basic' });
  }
  await chrome.storage.local.set({ [key]: new Date().toISOString() });
  // 鳴った瞬間に速報画面も1回だけ開く（地震速報の全画面にあたるもの）
  await openAlertPage();
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
      if (t) { await chrome.tabs.update(t.id, { active: true }); await chrome.windows.update(t.windowId, { focused: true }); return; }
    } catch { /* 閉じられていた */ }
  }
  const tab = await chrome.tabs.create({ url });
  await chrome.storage.local.set({ alertTabId: tab.id });
}

// 実機テスト（tools/e2e_extension.py）から呼ぶため。サービスワーカーでは import() が使えない
globalThis.__secalert = { check, detectBrowser, evaluate };
