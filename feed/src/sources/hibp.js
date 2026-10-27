// Have I Been Pwned（HIBP）の漏えい一覧。鍵なしの公開API。
// 🚨 ライセンスは CC BY 4.0＝公開物に出典（Have I Been Pwned へのリンク）を必ず付ける
// 🚨 説明文（Description）は配らない。名前・ドメイン・件数・漏れた項目・日付だけ
// 載せないもの：確認されていない件／スパム用リスト／作り物／取り下げ／情報窃取マルウェアのログ（サービスの漏えいではない）／
//              機微な件（IsSensitive＝HIBP 自身が名前で検索させない件）
import { fetchJson, SourceError } from '../fetch.js';

export const HIBP_URL = 'https://haveibeenpwned.com/api/v3/breaches';

export function parseHibp(json) {
  if (!Array.isArray(json)) throw new Error('not an array');
  if (json.length < 100) throw new Error(`too few breaches (${json.length})`);
  return json
    .filter((b) => b && b.Name && b.AddedDate && b.IsVerified && !b.IsSpamList && !b.IsFabricated && !b.IsRetired && !b.IsStealerLog && !b.IsMalware && !b.IsSensitive)
    .map((b) => ({
      name: String(b.Name),
      title: String(b.Title || b.Name),
      domain: b.Domain ? String(b.Domain) : null,
      breach_date: b.BreachDate || null,
      added_date: String(b.AddedDate).slice(0, 10),
      added_at: Number.isFinite(Date.parse(b.AddedDate)) ? new Date(b.AddedDate).toISOString() : null,
      count: Number.isFinite(b.PwnCount) ? b.PwnCount : null,
      data_classes: Array.isArray(b.DataClasses) ? b.DataClasses.map(String) : [],
    }));
}

export async function fetchHibp() {
  try {
    // HIBP は user-agent が無いと 403 を返す（fetchText が付ける）
    return parseHibp(await fetchJson(HIBP_URL));
  } catch (e) {
    throw new SourceError('hibp', e.message, e);
  }
}
