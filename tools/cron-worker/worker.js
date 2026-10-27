// GitHub Actions の schedule は混雑すると間引かれる（30分指定で実際は2.5〜6.8時間おき・2026-10-27 実測）。
// Cloudflare の Cron Trigger から30分ごとに feed.yml を workflow_dispatch で起こす。
//
// 鍵：GITHUB_TOKEN（Worker の secret）＝ zuboland/security-sokuho の Actions だけ書ける細かい権限のトークン。値はコードに書かない
// GitHub 側の schedule は残す（この Worker が止まっても、間引かれた頻度で配信は続く）
export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(dispatch(env));
  },
  // 手で叩いて確かめる口は作らない（外から誰でも Actions を起こせてしまう）
  async fetch() {
    return new Response('not found', { status: 404 });
  },
};

async function dispatch(env) {
  const repo = env.REPO || 'zuboland/security-sokuho';
  const res = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/feed.yml/dispatches`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'secalert-cron-worker',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ ref: 'main' }),
  });
  // 成功は 204。それ以外は throw して Cron の実行を「失敗」にする（ログだけだと止まっても気づけない・監査 R3）
  if (res.status !== 204) throw new Error(`dispatch failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  console.log('dispatch ok');
}
