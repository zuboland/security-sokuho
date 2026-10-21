// 取得の共通部。時間切れ・再試行・テスト用の固定応答（SECALERT_FIXTURES）をここに集める。
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const FIXTURE_DIR = process.env.SECALERT_FIXTURES || null;

export class SourceError extends Error {
  constructor(source, message, cause) {
    super(`${source}: ${message}`);
    this.source = source;
    this.cause = cause;
  }
}

/** URL→固定応答ファイル名。index.json に {url: file} の対応を書く */
async function readFixture(url) {
  const index = JSON.parse(await readFile(path.join(FIXTURE_DIR, 'index.json'), 'utf8'));
  const hit = Object.entries(index).find(([prefix]) => url.startsWith(prefix));
  if (!hit) throw new Error(`fixture not found for ${url}`);
  return readFile(path.join(FIXTURE_DIR, hit[1]), 'utf8');
}

export async function fetchText(url, { timeoutMs = 30000, retries = 2, headers = {} } = {}) {
  if (FIXTURE_DIR) return readFixture(url);
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        headers: { 'user-agent': 'secalert-feed/0.1 (+https://github.com/zuboland)', ...headers },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      lastErr = e;
      if (i < retries) await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastErr;
}

export async function fetchJson(url, opts) {
  const text = await fetchText(url, opts);
  // 🚨 HTTP 200 でも中身が HTML（メンテナンス画面）のことがある。先頭で見分ける
  const head = text.trimStart().slice(0, 1);
  if (head !== '{' && head !== '[') throw new Error(`not JSON (starts with ${JSON.stringify(text.trimStart().slice(0, 20))})`);
  return JSON.parse(text);
}
