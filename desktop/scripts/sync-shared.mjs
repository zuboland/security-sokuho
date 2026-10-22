// 拡張と共用するファイル（版数の比較・体裁）を ui/ に写す。正本は extension/ 側。テストで一致を確かめる
import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ext = path.join(here, '..', '..', 'extension');
const ui = path.join(here, '..', 'ui', 'shared');
await mkdir(ui, { recursive: true });
for (const f of ['version.js', 'theme.css']) {
  await copyFile(path.join(ext, f), path.join(ui, f));
  console.log('synced', f);
}
