// `winget list` の表（ロケール依存・列はヘッダー位置で切る）を機械で読む。
// 2026-10-22 のこのPCの実出力（243行・日本語ヘッダー）を固定応答にしてテストする。
//
// 出力の形：
//   名前   ID   バージョン   利用可能   ソース
//   -----------------------------------------
//   Google Chrome   Google.Chrome   155.0.8059.85   156.0.8078.48   winget
// 列の開始位置はヘッダー行の各語の位置。名前に全角文字が混ざると表示幅がずれるので、
// ヘッダーの位置で切った後、ID 列は「空白を含まない1語」として再確認する。

const HEADER_WORDS = [
  ['名前', 'Name'], ['ID', 'Id'], ['バージョン', 'Version'], ['利用可能', 'Available'], ['ソース', 'Source'],
];

/** 表示幅（全角＝2）。列の切り出しに使う */
export function displayWidth(s) {
  let w = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    w += (c >= 0x1100 && (c <= 0x115f || c === 0x2329 || c === 0x232a || (c >= 0x2e80 && c <= 0xa4cf && c !== 0x303f) || (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff) || (c >= 0xfe30 && c <= 0xfe6f) || (c >= 0xff00 && c <= 0xff60) || (c >= 0xffe0 && c <= 0xffe6) || (c >= 0x20000 && c <= 0x3fffd))) ? 2 : 1;
  }
  return w;
}

/** 表示幅 from〜to の部分文字列（全角を考慮） */
function sliceByWidth(s, from, to) {
  let w = 0; let out = '';
  for (const ch of s) {
    const cw = displayWidth(ch);
    if (w >= from && (to == null || w < to)) out += ch;
    w += cw;
    if (to != null && w >= to) break;
  }
  return out;
}

export function parseWingetList(text) {
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  // 進捗バーなどの前置きを飛ばして、ヘッダー行（名前…ID…バージョン）を探す
  const hi = lines.findIndex((l) => HEADER_WORDS.every(([ja, en]) => l.includes(ja) || l.includes(en)));
  if (hi < 0) return { ok: false, reason: 'header not found', items: [] };
  const header = lines[hi];
  const cols = HEADER_WORDS.map(([ja, en]) => {
    const i = header.indexOf(ja) >= 0 ? header.indexOf(ja) : header.indexOf(en);
    return displayWidth(header.slice(0, i));
  });
  const items = [];
  for (const line of lines.slice(hi + 2)) {
    if (!line.trim() || /^-{5,}$/.test(line.trim())) continue;
    const cells = cols.map((start, i) => sliceByWidth(line, start, cols[i + 1] ?? null).trim());
    let [name, id, version, available, source] = cells;
    // 幅ずれの保険：winget の ID は空白を含まない（ARP\… の ID はレジストリのキー名なので空白を含むことがある＝2026-10-22 実測で6件）。
    // winget の ID が崩れていたら、行を2つ以上の空白で分けて取り直す
    if (!id || (!/^(ARP|MSIX)\\/.test(id) && /\s/.test(id))) {
      const parts = line.trim().split(/\s{2,}/);
      if (parts.length >= 3) { name = parts[0]; id = parts[1]; version = parts[2]; available = parts.length >= 5 ? parts[3] : ''; source = parts.at(-1); }
    }
    if (!id) continue;
    const kind = id.startsWith('MSIX\\') ? 'msix' : id.startsWith('ARP\\') ? 'arp' : 'winget';
    if (available && !/^\d/.test(available)) available = ''; // 「利用可能」列にソース名が流れ込むことがある
    items.push({ kind, id, name, version: version || null, available: available || null, source: source || null });
  }
  return { ok: true, items };
}

/** 「7.1.9 (48550)」「17.0.20.101」「Unknown」などから比べられる版数を取り出す（取れなければ null） */
export function normalizeVersion(v) {
  if (!v) return null;
  const m = String(v).match(/\d+(?:\.\d+)+|\d+/);
  return m ? m[0] : null;
}
