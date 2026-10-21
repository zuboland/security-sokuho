import { getSettings, DEFAULT_BASE, isAllowedBase } from './common.js';

const $ = (id) => document.getElementById(id);

async function load() {
  const s = await getSettings();
  $('feedBase').value = s.feedBase;
  $('notify').checked = s.notify;
}

$('save').addEventListener('click', async () => {
  let feedBase = $('feedBase').value.trim();
  if (!feedBase.endsWith('/')) feedBase += '/';
  if (!isAllowedBase(feedBase)) { $('msg').textContent = 'https で始まるURLにしてください'; return; }
  await chrome.storage.sync.set({ feedBase, notify: $('notify').checked });
  $('msg').textContent = '保存しました。次の確認から反映されます。';
  chrome.runtime.sendMessage({ type: 'check-now' });
});

$('reset').addEventListener('click', async () => {
  await chrome.storage.sync.set({ feedBase: DEFAULT_BASE, notify: true });
  await load();
  $('msg').textContent = '既定に戻しました。';
});

$('test').addEventListener('click', () => {
  chrome.notifications.create('secalert:test', {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '（テスト）緊急セキュリティ速報：ブラウザを更新してください',
    message: '本物のときはこの見た目で届きます。クリックで更新画面が開きます。',
    contextMessage: 'この速報が電話やダウンロードを求めることはありません',
    priority: 2,
  });
});

load();
