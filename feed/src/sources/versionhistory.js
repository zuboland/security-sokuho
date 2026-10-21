// Chrome VersionHistory API。いま配信中の安定版（Win／Mac／Linux）。
import { fetchJson, SourceError } from '../fetch.js';

export const PLATFORMS = ['win', 'mac', 'linux'];
export const versionHistoryUrl = (platform) =>
  `https://versionhistory.googleapis.com/v1/chrome/platforms/${platform}/channels/stable/versions?pageSize=1`;

export async function fetchChromeStable() {
  const out = {};
  const errors = [];
  for (const p of PLATFORMS) {
    try {
      const json = await fetchJson(versionHistoryUrl(p));
      const v = json?.versions?.[0]?.version;
      if (!v) throw new Error('no version');
      out[p] = v;
    } catch (e) {
      errors.push(`${p}: ${e.message}`);
    }
  }
  if (Object.keys(out).length === 0) throw new SourceError('versionhistory', errors.join('; '));
  return out;
}
