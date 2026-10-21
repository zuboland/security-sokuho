// 版数の比較。拡張側（extension/version.js）と同じ内容を置く（テストで一致を確かめる）。
// 判定は3値：required（要対応）／ok（対応不要）／unknown（判定不能）。

export function parseVersion(s) {
  if (typeof s !== 'string') return null;
  const t = s.trim();
  if (!/^\d+(\.\d+){0,3}$/.test(t)) return null;
  return t.split('.').map(Number);
}

export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return null;
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function minVersion(list) {
  let best = null;
  for (const v of list || []) {
    if (!parseVersion(v)) continue;
    if (best === null || compareVersions(v, best) < 0) best = v;
  }
  return best;
}

export function maxVersion(list) {
  let best = null;
  for (const v of list || []) {
    if (!parseVersion(v)) continue;
    if (best === null || compareVersions(v, best) > 0) best = v;
  }
  return best;
}

/** 自分の版数 current が、修正版 minSafe 以上なら ok、未満なら required、比べられなければ unknown */
export function judge(current, minSafe) {
  const c = compareVersions(current, minSafe);
  if (c === null) return 'unknown';
  return c < 0 ? 'required' : 'ok';
}
