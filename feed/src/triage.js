// 製品の種類分けと、AIなしで出す「今やること」の定型文。
// 一般の人に関係する製品だけを速報の対象にする（サーバー製品・ネットワーク機器は一覧にだけ出す）。

// vendor（メーカー名）で縛れるものは縛る。🚨「Multiple Products」は Fortinet／Atlassian／Check Point にもあり、
// 製品名だけで見ると家庭向け（Apple）に化ける（2026-10-22 実測＝速報17件中6件が誤って iPhone 扱いになった）
const CLASSES = [
  // Edge は「Chromium-based」と書かれるので Chrome より先に見る
  { key: 'browser-edge', vendor: /microsoft/i, re: /\bedge\b/i, label: 'Microsoft Edge' },
  { key: 'browser-chrome', vendor: /google|chromium/i, re: /\b(google chrome|chromium|chrome)\b|\bV8\b|\bblink\b|\bskia\b|\bANGLE\b/i, label: 'Google Chrome' },
  { key: 'browser-firefox', vendor: /mozilla/i, re: /firefox/i, label: 'Firefox' },
  { key: 'browser-safari', vendor: /apple/i, re: /safari|webkit/i, label: 'Safari' },
  { key: 'os-windows', vendor: /microsoft/i, re: /\bwindows\b/i, label: 'Windows' },
  { key: 'os-apple', vendor: /apple/i, re: /\b(ios|ipados|macos|watchos|tvos|visionos)\b|\bmultiple products\b/i, label: 'iPhone・iPad・Mac' },
  { key: 'os-android', vendor: /google|android|samsung/i, re: /\bandroid\b|\bpixel\b/i, label: 'Android' },
  // SharePoint・Exchange はサーバー製品なので家庭向けに入れない
  { key: 'office', vendor: /microsoft/i, re: /\boffice\b|\bword\b|\bexcel\b|\boutlook\b|\bonenote\b|\bpowerpoint\b/i, label: 'Microsoft Office' },
  { key: 'pdf', vendor: /adobe|foxit/i, re: /acrobat|\breader\b|foxit/i, label: 'PDF ソフト' },
  { key: 'archiver', vendor: /7-zip|igor pavlov|rarlab|win\.rar/i, re: /7-zip|winrar/i, label: '圧縮・解凍ソフト' },
  { key: 'runtime-java', vendor: /oracle|microsoft|eclipse|adoptium/i, re: /\bjava\b|\bjre\b|\bjdk\b/i, label: 'Java' },
  { key: 'messaging', vendor: /zoom|microsoft|slack|discord|line|meta|whatsapp|telegram/i, re: /\bzoom\b|\bteams\b|\bslack\b|\bdiscord\b|\bline\b|\bwhatsapp\b|\btelegram\b/i, label: 'メッセージ・会議アプリ' },
];

export const CONSUMER_CLASSES = new Set(CLASSES.map((c) => c.key));

/**
 * vendor／product から製品の種類を決める。分からなければ 'other'。
 * vendor が空（JPCERT／IPA の日本語タイトルなど）のときは product（タイトル）の文言だけで見る。
 */
export function classify(vendor, product, _text = '') {
  const v = String(vendor || '');
  const p = String(product || '');
  for (const c of CLASSES) {
    const vendorOk = v ? c.vendor.test(v) : true;
    if (vendorOk && c.re.test(v ? p : `${p}`)) return c.key;
  }
  return 'other';
}

export function classLabel(key) {
  return CLASSES.find((c) => c.key === key)?.label || 'その他';
}

/** AIなしの「今やること」。製品の種類ごとの定型文。 */
export function actionTemplate(key, { fixedVersion } = {}) {
  const v = fixedVersion ? `（${fixedVersion} 以上）` : '';
  switch (key) {
    case 'browser-chrome':
      return `Chrome を更新${v}：右上の「︙」→「ヘルプ」→「Google Chrome について」を開き、更新が終わったら「再起動」を押す（1分）`;
    case 'browser-edge':
      return `Edge を更新${v}：右上の「…」→「ヘルプとフィードバック」→「Microsoft Edge について」を開き、更新が終わったら「再起動」を押す（1分）`;
    case 'browser-firefox':
      return `Firefox を更新${v}：右上の「≡」→「ヘルプ」→「Firefox について」を開き、更新が終わったら「再起動」を押す（1分）`;
    case 'browser-safari':
    case 'os-apple':
      return 'iPhone・iPad は「設定」→「一般」→「ソフトウェア・アップデート」、Mac は「システム設定」→「一般」→「ソフトウェアアップデート」で更新する';
    case 'os-windows':
      return '「設定」→「Windows Update」→「更新プログラムのチェック」を押し、終わったら再起動する';
    case 'os-android':
      return '「設定」→「システム」→「ソフトウェア・アップデート」（機種により「セキュリティ・アップデート」）で更新する';
    case 'office':
      return 'Word や Excel を開き、「ファイル」→「アカウント」→「更新オプション」→「今すぐ更新」を押す';
    case 'pdf':
      return 'PDF ソフトを開き、「ヘルプ」→「アップデートの有無をチェック」で更新する';
    case 'archiver':
      // 🚨「ダウンロードを求めない」約束と矛盾しない言い方にする（監査R2）。配布先の URL は案内しない
      return 'ソフト自身の更新機能か、Windows の「winget upgrade」で更新する。この速報がダウンロード先を案内することはありません';
    case 'runtime-java':
      return 'Java を使っていないなら削除してよい。使っているなら配布元（Oracle／Microsoft／Adoptium）の最新版に更新する';
    case 'messaging':
      return 'アプリを一度終了して、ストアまたはアプリ内の「アップデート」で最新版にする';
    default:
      return '家庭のPC・スマホには通常関係ありません。会社で使っている製品なら、担当者（情シス）に「この件は対応済みか」を確認する';
  }
}

// ---- 守りの行動（自分では直せない脅威のときに、それでもできること） ----
// 版数の更新とは別の軸。脅威の種類（認証突破・情報流出・サプライチェーン・フィッシング・サーバー側）から規則で出す。
// 🚨 文に電話番号・ダウンロード先を入れない。出すのは最大3つ（並べすぎると全部読まれない）。
const ADVICE = {
  password: 'そのサービス・製品で使っているパスワードを変える（同じものを他でも使っていれば、そちらも）',
  twofa: 'ログインの二段階認証（2要素認証）をオンにする。これだけで、パスワードが漏れても乗っ取られにくくなる',
  manager: 'パスワードの使い回しをやめる。覚えきれない分はブラウザやパスワード管理ツールに任せる',
  loginlog: '身に覚えのないログイン通知・「新しい端末からのログイン」メールが来ていないか確認する',
  keys: 'そのソフトを入れていた期間に使った鍵・パスワード・ログイン情報を全部作り直す（漏れた前提で動く）',
  reinstall: '入れ直すときは公式の配布元からだけ。検索広告のリンクや再配布サイトは使わない',
  mail: '届いたメールの添付ファイル・リンクを開かない。送り主に心当たりがあっても、公式サイトから自分で開く',
  provider: 'あなたが使っているサービスがこの製品を使っている場合、運営からの案内（パスワード変更の依頼など）に従う。案内が無ければ何もしなくてよい',
  browserhint: '更新する前に心当たりのないページを開いていた場合は、よく使うサービスのパスワード変更と二段階認証もおすすめ',
};

const AUTH_CWES = new Set(['CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-306', 'CWE-307', 'CWE-284', 'CWE-862', 'CWE-863', 'CWE-522', 'CWE-798', 'CWE-1390', 'CWE-1391']);
const LEAK_CWES = new Set(['CWE-200', 'CWE-22', 'CWE-209', 'CWE-532', 'CWE-538', 'CWE-312', 'CWE-359']);

/**
 * 守りの行動を返す（配列・最大3つ）。
 * @param {object} o  { cls, text, cwes, exploited }
 */
export function protectAdvice({ cls = 'other', text = '', cwes = [], exploited = false } = {}) {
  const t = String(text || '');
  const set = new Set(cwes || []);
  const out = [];
  const push = (k) => { if (!out.includes(ADVICE[k])) out.push(ADVICE[k]); };

  // 🚨 KEV の説明文は「unauthenticated attacker」「authenticated attacker」だらけ。単に authenticat を含むかで見ると全件が認証突破になる
  //    （2026-10-22 実測＝Plex の SSRF や Siemens の検索パスの件にパスワード変更が付いた）。欠陥そのものを指す言い方だけに絞る
  const isAuth = [...set].some((c) => AUTH_CWES.has(c))
    || /(authentication|authorization) bypass|bypass (of )?authentication|improper (authentication|authorization)|missing authentication|weak authentication|hard-?coded credential|credential (theft|leak|exposure|stuffing)|password (reset|disclosure|leak)|account takeover|session (hijack|fixation)|token (theft|leak|forgery)|認証(回避|不備|の不備|バイパス)|パスワード(漏|流出|窃取)|なりすまし|不正ログイン/i.test(t);
  const isLeak = [...set].some((c) => LEAK_CWES.has(c))
    || /information (disclosure|exposure|leak)|sensitive (data|information)|data breach|exfiltrat|credential-?steal|info-?stealer|read arbitrary files?|path traversal|directory traversal|情報漏えい|情報漏洩|情報流出|不正アクセス/i.test(t);
  const isSupply = /supply.?chain|malicious (package|version|update)|compromised (package|version|build|library)|backdoor|typosquat|サプライチェーン|不正なパッケージ|改ざん/i.test(t);
  const isPhish = /phishing|spoof|lure|malicious (document|attachment|office)|crafted (document|file|email)|フィッシング|不審なメール|偽サイト|添付ファイル/i.test(t);

  if (isSupply) { push('keys'); push('twofa'); push('reinstall'); }
  if (isAuth) { push('password'); push('twofa'); }
  if (isLeak) { push('password'); push('loginlog'); push('manager'); }
  if (isPhish) { push('mail'); }
  // 家庭では直せないサーバー製品：使っているサービスの運営に任せるべきことを1行
  if (cls === 'other' && exploited) push('provider');
  // ブラウザの悪用確認済み：更新が本筋。守りは1行だけ添える
  if (cls.startsWith('browser-') && exploited && out.length === 0) push('browserhint');
  return out.slice(0, 3);
}

/** 自分で直せる（update）か、守りの行動が中心（protect）か */
export function kindOf(cls, fixedVersions = {}) {
  if (cls !== 'other' || Object.keys(fixedVersions).length > 0) return 'update';
  return 'protect';
}

export function whoTemplate(key) {
  switch (key) {
    case 'browser-chrome':
      return 'Google Chrome を使っている人';
    case 'browser-edge':
      return 'Microsoft Edge を使っている人';
    case 'browser-firefox':
      return 'Firefox を使っている人';
    case 'browser-safari':
    case 'os-apple':
      return 'iPhone・iPad・Mac を使っている人';
    case 'os-windows':
      return 'Windows のパソコンを使っている人';
    case 'os-android':
      return 'Android のスマホ・タブレットを使っている人';
    case 'office':
      return 'Word・Excel・Outlook を使っている人';
    case 'pdf':
      return 'Acrobat Reader などの PDF ソフトを使っている人';
    case 'archiver':
      return '7-Zip・WinRAR などを入れている人';
    case 'runtime-java':
      return 'Java を入れている人（入れた覚えがなければ関係ない可能性が高い）';
    case 'messaging':
      return 'そのアプリを使っている人';
    default:
      return '主に会社のサーバー・ネットワーク機器を管理している人（家庭では通常関係なし）';
  }
}
