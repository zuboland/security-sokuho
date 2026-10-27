# 緊急セキュリティ速報

**悪用が確認された脆弱性で、あなたのブラウザが影響を受けるときだけ知らせる Chrome／Edge 拡張**と、その元になる公開フィードです。
地震速報と同じ考え方で、**めったに鳴りません**。鳴ったら「更新画面を開く」を押して再起動するだけです。

> この速報が電話やダウンロードを求めることはありません。
> 「ウイルスに感染しました」と電話番号を出す画面は、この拡張ではなく詐欺です。

- Chrome ウェブストア：https://chromewebstore.google.com/detail/kcgjkmndebbahngomgielflgiilhnbak （Edge でも入ります）
- 公開フィード：https://zuboland.github.io/security-sokuho/ （`browsers.json` / `alerts.json` / `feed.json` / `status.json`）
- リポジトリ：https://github.com/zuboland/security-sokuho （MIT）

<p align="center"><img src="docs/alert_required.png" width="720" alt="速報画面：Google Chrome を今すぐ更新してください。今の版数→この版数以上に、更新画面を開くボタン、守りの行動"></p>
<p align="center"><img src="docs/popup_real_feed.png" width="380" alt="ポップアップ：更新してください／直近の速報の一覧"></p>

## 何が分かるか

| 表示 | 意味 |
|---|---|
| 🔴 更新してください | 悪用が確認された脆弱性があり、あなたの版数が修正版より古い |
| ✅ 対応済みです／いま緊急の速報はありません | 修正版以上、または直近に悪用確認済みの件が無い |
| ⚪ 確認できませんでした | 版数が取れない・情報源が止まっている。**「大丈夫」とは言いません**。手で確かめる手順を出します |

「確認できない」を「大丈夫」と言わないのが、この道具のいちばん大事な約束です。

### サービスの情報漏えい（0.2.0〜）

あなたのPCではなく、**使っているサービスの運営会社のほうで起きた漏えい**も知らせます（`breaches.json`）。

| 札 | 意味 | 通知 |
|---|---|---|
| 確認済み | [Have I Been Pwned](https://haveibeenpwned.com/) が流出データを確認した件 | 1年以内に起きた漏えいで、パスワードかお金の情報を含み、件数がしきい値以上のときだけ |
| 報道 | 日本の報道（ScanNetSecurity・Security NEXT の記事）が企業の公表を伝えた件 | 見出しが「漏えいした」と言い切っていて（「可能性」「〜か」は鳴らさない）、件数がしきい値以上のときだけ |
| ⚠ 未確認 | X で投稿が増えているだけで、公式の発表や報道を確認できていない件 | **鳴らしません。** 一覧に注意書きを付けて出すだけ |

- しきい値は拡張の設定で選べます：**1,000万件以上（既定・週に1〜2件ほど）**／100万件以上／通知しない
- 漏えいの通知は、発表から72時間以内の件だけです（入れた直後に過去の件をまとめて鳴らしません）。漏えいの情報源が48時間以上更新されていないときは通知しません
- 報道の見出しは件数と名前を読み取るためだけに使い、**見出しの文はそのまま配りません**（「」の中のサービス名と件数から短い題名を作り、記事へリンクします）。否定・対策の見出し（「漏えいは確認されず」「漏えい対策」）は入れません。件数は漏えいを述べている部分の数字だけを使います（「会員100万人のうち30件」は30件）
- 未確認の件は、X の投稿から Claude がサービス名を抜き出し、**2件以上の投稿の本文に文字どおり出てくる名前だけ**（英数字の名前は単語の途中に埋もれていないもの・一般の言葉は除く）を候補にして、X の件数カウント（直近24時間・既定50件以上）で話題になっているかを確かめてから載せます。投稿の本文・投稿者・X から数えた件数は配らず、X の検索結果へのリンクだけを載せます。最後に話題として見えてから12時間で一覧から外れ、`SECALERT_XBUZZ=off` にするとすぐ全部消えます
- X の有料呼び出しは、**呼ぶ前に最悪の費用を支出台帳（`feed/data/xbuzz/state.json`）に予約して push できた回だけ**行います。台帳が無い・壊れている・設定が数でないときは呼びません
- 確認済み・報道に同じ名前が出たら、未確認の一覧からは消えます

## 仕組み

```
[GitHub Actions（30分ごと）] 公式の情報源を取得 → public/*.json → GitHub Pages で配信
[拡張]                       30分ごとに JSON を読む → 自分の版数と比べる → 要対応のときだけ通知
```

- **判定に AI を使いません。** 修正版の版数は Google／Microsoft／CISA の公式データから機械で取り、あなたの版数と比べます
- **あなたのPCの情報は外に出ません。** 外へ出る通信は公開フィード（静的JSON）の取得だけで、利用者を識別する情報は送りません
- **AI は日本語の要約（summary_ja）にだけ**（任意）。「誰に関係するか」「今やること」「守りの行動」は機械生成の定型文で、AI の文で上書きしません。ニュース1件につき1回、配信側で作って全員に配るので、利用者ごとの費用も鍵も要りません。AI を切っても判定は同じです
- **配信が止まったら「判定不能」になります。** 拡張も常駐アプリも配信の生成時刻（`status.json`）を見て、24時間更新が無ければ古い安全判定を出しません

## 情報源（すべて無料・公式）

| 情報源 | 使いどころ |
|---|---|
| [Chrome Releases](https://chromereleases.googleblog.com/) | 修正版の版数・直した CVE・「exists in the wild」（悪用確認） |
| [Microsoft Edge セキュリティ更新](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security) | Edge の修正版・「exploit in the wild」 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 悪用が確認された脆弱性の一覧 |
| [Chrome VersionHistory API](https://developer.chrome.com/docs/web-platform/versionhistory/guide) | いま配信中の安定版 |
| [EPSS](https://www.first.org/epss/) | 悪用される見込み（参考値） |
| [JPCERT/CC 注意喚起](https://www.jpcert.or.jp/) ／ [IPA 重要なセキュリティ情報](https://www.ipa.go.jp/security/) | 日本語の一次情報 |
| [JVN iPedia](https://jvndb.jvn.jp/) | 日本語の脆弱性DB（止まっていることがあるので、無くても動く作り） |
| [Have I Been Pwned](https://haveibeenpwned.com/)（[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)） | 流出データが確認された漏えいの一覧。名前・件数・漏れた項目・日付だけを抜き出し、日本語の題名・項目名を付け、件数を概数にして配る（説明文は配らない）。ソースコードの MIT とは別のライセンス |
| [ScanNetSecurity](https://scan.netsecurity.ne.jp/) ／ [Security NEXT](https://www.security-next.com/) の RSS | 日本の漏えい報道（見出しから名前と件数を読み、記事へリンクするだけ。見出しの文・本文は配らない）。**公式発表そのものではない**ので「報道」と表示 |
| X API（有料・任意） | 話題になっている未確認の漏えい。`SECALERT_XBUZZ=on` と `SECALERT_XBUZZ_AI=anthropic`（名前の抜き出しに使う AI・要約の `SECALERT_AI` とは別）のときだけ・3時間に1回・月の上限つき（`SECALERT_XBUZZ_CAP_USD`・X と AI の合計） |

## 使う

### 拡張（ストア版）

[Chrome ウェブストア](https://chromewebstore.google.com/detail/kcgjkmndebbahngomgielflgiilhnbak)で「Chrome に追加」を押すだけです。Edge でも同じページから入れられます（「他のストアからの拡張機能を許可」をオン）。

### 拡張（開発版）

1. `chrome://extensions` を開き「デベロッパーモード」をオン
2. 「パッケージ化されていない拡張機能を読み込む」→ `extension/` フォルダを選ぶ
3. アイコンを押すと今の判定が出ます。設定で配信元を変えられます

### フィードを自分で作る

```bash
cd feed
npm ci
node src/selftest.js   # 毒味：わざと壊した入力で落ちるか（23件）
npm test               # 実データの固定応答で解析と冪等性を確かめる
node src/build.js      # public/ に feed.json / alerts.json / browsers.json / status.json
```

AI 要約を使うとき（任意）：

```bash
npm i @anthropic-ai/sdk        # または openai
SECALERT_AI=anthropic ANTHROPIC_API_KEY=... node src/build.js
```

要約は `feed/data/summaries/<id>.json` に保存され、次からは AI を呼びません。
AI の出力は機械で検査し、**その件に無い版数・電話番号・ダウンロード案内が入っていたら捨てて定型文に戻します**。

### 公開 JSON の形

- `browsers.json` … ブラウザごとの `min_safe`（この版数以上なら安全）・`exploited_cves`・`latest_stable`・`status`（`ok`／`unknown`）
- `alerts.json` … 速報の候補（悪用確認済み かつ 一般の人に関係する製品）
- `breaches.json` … サービスの情報漏えい（`type`＝`confirmed`／`rumor`・`basis`＝`hibp`／`news`／`x`・`count`・`published_at`・`notify_eligible`・`advice_ja`・`caution_ja`（未確認のみ）・`sources`・`rumor_watch`（X の確認が動いているか））。鮮度は `status.json` の `breaches_as_of`
- `feed.json` … 直近90日の全件。各件に `action_ja`（今やること）・`who_ja`（誰に関係するか）・`advice_ja[]`（自分では直せない脅威のときの守りの行動：パスワード変更・二段階認証など）・`kind`（`update`＝自分で直せる／`protect`＝守りが中心）が必ず付きます。速報の件には `related_posts[]`（Hacker News の記事。X は ID と URL だけ＝本文は配りません）
- `status.json` … 生成時刻と、取れなかった情報源（`sources_failed`）

## 開発

- 実機テスト：`python tools/e2e_extension.py`（Playwright の Chromium に拡張を読み込み、偽フィードで3値の判定・通知・更新画面を確かめる）
- アイコン：`python tools/make_icons.py`（社内のアイコン正本の盾 SVG から作る。AI画像は使わない）
- 設計の決まり：判定は3値／版数の判定に AI を使わない／PCの中身を外に出さない／速報は「悪用確認済み × 自分が影響を受ける」の両方がそろったときだけ

## 常駐アプリ（Windows・プレリリース）

ブラウザだけでなく、**PC に入っているソフト全体**（対応表にある 40 製品）を公開フィードと照合し、要対応のときだけ通知して「今すぐ更新する」ボタンで `winget upgrade` を実行する常駐アプリです（`desktop/`・Tauri 2）。

- 判定の材料：`affected.json`（NVD の CPE と修正版の範囲）× `catalog.json`（winget の ID／レジストリの表示名 → CPE の対応表）× `winget list`／レジストリ
- 3値：要対応／対応済み／判定不能。対応表に無い物は「分からない」ので出しません（設定で見ている製品を確認できます）。Windows 本体はこの版では判定せず「Windows Update を開く」だけ
- PC の中身は外に送りません。通信は公開フィードの取得と、更新時の winget（Microsoft のソース）だけ
- 配布は [Releases](https://github.com/zuboland/security-sokuho/releases) から（最新のプレリリース＝[desktop-v0.1.1](https://github.com/zuboland/security-sokuho/releases/tag/desktop-v0.1.1)・`security-sokuho-desktop_0.1.1_x64-setup.exe`・ZUBOLAND株式会社の署名付き。未署名だった 0.1.0 は 2026-10-22 に取り下げました）。署名（ZUBOLAND株式会社・Azure Trusted Signing）は鍵を持つ CI のビルドだけに付きます。**署名の無いビルドは配りません**（鍵の無い fork でビルドすると Releases の説明に未署名と出る作りです）
- 開発：`cd desktop && npm ci && npm test`（winget の実出力 243 行を固定応答にした解析・判定テスト）／`npm run dev`（Rust ツールチェーンが要ります）
- 対応表の実在検査：`python tools/catalog_check.py`（winget の ID と NVD の CPE が本当にあるか。手書きの表は必ず古くなるため）

## 予定

- 常駐アプリ：Windows 本体の判定（KB・ビルドの対応表）、Mac 版
- 「自分の状況についての質問」（自分の鍵で使う／有料）

## ライセンス

MIT
