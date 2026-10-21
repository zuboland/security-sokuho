// AI要約（任意・上に載せるだけ）。1件1回。結果は data/summaries/<id>.json に保存してコミットする＝リポジトリがキャッシュ。
//
// 🚨 AIに版数・製品名を生成させない。要約の中に、その件に無い版数が出たら捨てて定型文に戻す。
// 🚨 電話番号・ダウンロード案内が出たら捨てる（サポート詐欺と見分けがつかなくなる）。
// 使う：SECALERT_AI=anthropic|openai|none（既定 none）／SECALERT_AI_MODEL／SECALERT_AI_MAX（1回の実行で最大件数・既定20）
// Gemini は使わない（会社ルール）。

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SUMMARY_DIR = process.env.SECALERT_SUMMARY_DIR || path.join(here, '..', 'data', 'summaries');

const PROVIDER = (process.env.SECALERT_AI || 'none').toLowerCase();
const MAX_PER_RUN = Number(process.env.SECALERT_AI_MAX || 20);

const SYSTEM = `あなたは一般の人向けにセキュリティ情報を日本語で説明する係です。
入力は公開されている脆弱性情報です。次の3つを JSON で返してください。
{"summary_ja": "何が起きるかを2文以内。専門用語は言い換える", "who_ja": "誰に関係するかを1文", "action_ja": "今やることを1文。与えられた『定型の手順』を自然に言い換える"}
守ること：
- 版数（例 156.0.8078.47）や製品名を自分で考えて書かない。入力にあるものだけを使う
- 電話番号・ダウンロード先・外部サイトの案内を書かない
- 不安をあおらない。「必ず」「今すぐ」は悪用が確認済みのときだけ
- JSON 以外は出力しない`;

function buildPrompt(item) {
  return [
    `タイトル: ${item.title_ja || item.title || ''}`,
    `CVE: ${item.cves.join(', ') || 'なし'}`,
    `悪用の確認: ${item.exploited ? 'あり（' + item.exploit_evidence.join('／') + '）' : 'なし'}`,
    `対象の製品: ${item.product_label || ''}`,
    `修正版: ${Object.entries(item.fixed_versions).map(([k, v]) => `${k} ${v}`).join(', ') || '不明'}`,
    `定型の手順: ${item.action_ja}`,
    `原文（公開情報）:\n${(item.summary_ja || item.summary || '').slice(0, 3000)}`,
  ].join('\n');
}

const VERSION_RE = /\b\d+\.\d+\.\d+(\.\d+)?\b/g;
const PHONE_RE = /0\d{1,4}-\d{1,4}-\d{3,4}|\b0120[-\d]+/;

/** AIの出力を検査する。通らなければ理由を返す（null なら合格） */
export function validateSummary(out, item) {
  if (!out || typeof out !== 'object') return 'not an object';
  for (const k of ['summary_ja', 'who_ja', 'action_ja']) {
    if (typeof out[k] !== 'string' || out[k].trim().length === 0) return `${k} missing`;
    if (out[k].length > 300) return `${k} too long`;
    if (PHONE_RE.test(out[k])) return `${k} has phone number`;
    if (/ダウンロード|download|http/i.test(out[k])) return `${k} has download/url`;
  }
  const allowed = new Set(Object.values(item.fixed_versions));
  const text = `${out.summary_ja} ${out.who_ja} ${out.action_ja}`;
  for (const v of text.match(VERSION_RE) || []) {
    if (!allowed.has(v)) return `version ${v} not in item`;
  }
  return null;
}

async function callAnthropic(prompt) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();
  const model = process.env.SECALERT_AI_MODEL || 'claude-opus-5-5';
  const res = await client.messages.create({
    model,
    max_tokens: 1024,
    system: SYSTEM,
    messages: [{ role: 'user', content: prompt }],
  });
  const text = res.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
  return { text, model, usage: res.usage };
}

async function callOpenAI(prompt) {
  const { default: OpenAI } = await import('openai');
  const client = new OpenAI();
  const model = process.env.SECALERT_AI_MODEL || 'gpt-5.5';
  const res = await client.chat.completions.create({
    model,
    messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: prompt }],
    response_format: { type: 'json_object' },
  });
  return { text: res.choices?.[0]?.message?.content || '', model, usage: res.usage };
}

function parseJson(text) {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

export async function loadCached(id) {
  try { return JSON.parse(await readFile(path.join(SUMMARY_DIR, `${id}.json`), 'utf8')); } catch { return null; }
}

/** items に要約を載せる。キャッシュがあれば使い、無ければ（provider が none でなければ）AIを呼ぶ */
export async function applySummaries(items, { provider = PROVIDER, maxPerRun = MAX_PER_RUN } = {}) {
  await mkdir(SUMMARY_DIR, { recursive: true });
  let calls = 0;
  for (const item of items) {
    const cached = await loadCached(item.id);
    if (cached && validateSummary(cached, item) === null) { Object.assign(item, pick(cached)); item.summary_by = cached.model || 'cache'; continue; }
    if (provider === 'none' || calls >= maxPerRun) continue;
    // 日本語の要約が既にある件（JPCERT／IPA 由来）は AI を使わない
    if (item.summary_ja && item.title_ja) continue;
    calls++;
    try {
      const r = provider === 'anthropic' ? await callAnthropic(buildPrompt(item)) : provider === 'openai' ? await callOpenAI(buildPrompt(item)) : null;
      if (!r) continue;
      const out = parseJson(r.text);
      const why = validateSummary(out, item);
      if (why) { console.warn(`[summarize] ${item.id} を捨てた: ${why}`); continue; }
      const record = { ...pick(out), model: r.model, created_at: new Date().toISOString() };
      await writeFile(path.join(SUMMARY_DIR, `${item.id}.json`), JSON.stringify(record, null, 1) + '\n');
      Object.assign(item, pick(out));
      item.summary_by = r.model;
    } catch (e) {
      console.warn(`[summarize] ${item.id} 失敗: ${e.message}`);
    }
  }
  return items;
}

function pick(o) {
  return { summary_ja: o.summary_ja, who_ja: o.who_ja, action_ja: o.action_ja };
}
