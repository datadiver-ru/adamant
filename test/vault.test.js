'use strict';
/**
 * Шифрование папки данных (server/vault.js) и пароль автовхода в записях отката (fix.ps1).
 * DPAPI в большинстве тестов поддельный; один тест - с настоящим DPAPI текущего пользователя (только чтение, временная папка).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createVault, seal, unseal, isSealed, KEY_FILE } = require('../server/vault');
const { createStore } = require('../server/store');
const { createTelegram } = require('../server/telegram');
const { createCanary } = require('../server/canary');

const ROOT = path.join(__dirname, '..');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-vault-'));
const FAKE = Buffer.from('FAKE');
const fakeProtect = async (b) => Buffer.concat([FAKE, Buffer.from(b.map((x) => x ^ 0x5a))]);
const fakeUnprotect = async (b) => {
  if (!b.subarray(0, 4).equals(FAKE)) throw new Error('not ours');
  return Buffer.from(b.subarray(4).map((x) => x ^ 0x5a));
};
const vaultOf = (dataDir, extra = {}) => createVault({ dataDir, protect: fakeProtect, unprotect: fakeUnprotect, ...extra });
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from('PHOTO-OF-INTRUDER'), Buffer.alloc(200, 7)]);
const TOKEN = '123456789:SECRET-BOT-TOKEN-abcdef';

function allFiles(dir) {
  const out = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  })(dir);
  return out;
}
const rel = (dir, p) => path.relative(dir, p).split(path.sep).join('/');

/** Папка данных старой версии: всё открытым текстом. */
function oldDataDir() {
  const d = tmp();
  const w = (n, v) => { fs.mkdirSync(path.dirname(path.join(d, n)), { recursive: true }); fs.writeFileSync(path.join(d, n), typeof v === 'string' || Buffer.isBuffer(v) ? v : JSON.stringify(v)); };
  w('report.json', { at: '2026-11-20T10:00:00Z', facts: { meta: { computer: 'SECRET-PC-NAME' } } });
  w('telegram.json', { enabled: true, token: TOKEN, chatId: 42 });
  w('license.json', { key: 'ADAMANT1.SECRET-LICENSE-KEY' });
  w('away.json', { v: 1, spans: [], meta: { note: 'SECRET-AWAY' } });
  w('canary.json', { files: [{ path: 'C:\\Users\\x\\Documents\\SECRET-DECOY.docx' }] });
  w('journal.json', [{ record: 'r1', id: 'firewall-on' }]);
  w('away/photos/0123456789abcdef0123456789abcdef.jpg', JPEG);
  w('settings.json', { lang: 'en', background: true });
  w('server.json', { port: 1234, key: 'run-key' });
  w('window/Default/Preferences', 'edge profile');
  return d;
}

test('AES-256-GCM: туда и обратно; подмена байта или имени файла не проходит', () => {
  const dek = Buffer.alloc(32, 9);
  const s = seal(dek, 'report.json', Buffer.from('{"a":1}'));
  assert.ok(isSealed(s));
  assert.equal(unseal(dek, 'report.json', s).toString(), '{"a":1}');
  assert.equal(unseal(dek, 'REPORT.JSON', s).toString(), '{"a":1}', 'имя без учёта регистра (Windows)');
  const bad = Buffer.from(s);
  bad[bad.length - 1] ^= 1;
  assert.throws(() => unseal(dek, 'report.json', bad));
  assert.throws(() => unseal(dek, 'license.json', s), 'файл нельзя подложить под другим именем');
  assert.throws(() => unseal(Buffer.alloc(32, 8), 'report.json', s), 'чужой ключ не подходит');
  assert.notEqual(seal(dek, 'x', Buffer.from('a')).toString('hex'), seal(dek, 'x', Buffer.from('a')).toString('hex'), 'новый iv каждый раз');
});

test('первый запуск: ключ создаётся и хранится только обёрнутым', async () => {
  const d = tmp();
  try {
    const v = vaultOf(d);
    assert.equal((await v.open()).state, 'ok');
    const j = JSON.parse(fs.readFileSync(path.join(d, KEY_FILE), 'utf8'));
    assert.equal(j.kind, 'dpapi-user');
    const dek = await fakeUnprotect(Buffer.from(j.key, 'base64'));
    assert.equal(dek.length, 32);
    // Открытого ключа нет ни в data.key, ни где-либо ещё.
    for (const f of allFiles(d)) assert.ok(!fs.readFileSync(f).includes(dek), rel(d, f));
    const store = createStore(d, { vault: v });
    store.write('report.json', { ok: 1 });
    assert.ok(isSealed(fs.readFileSync(path.join(d, 'report.json'))));
    assert.deepEqual(store.read('report.json', null), { ok: 1 });
    // Повторное открытие тем же ключом.
    const v2 = vaultOf(d);
    assert.equal((await v2.open()).state, 'ok');
    assert.deepEqual(createStore(d, { vault: v2 }).read('report.json', null), { ok: 1 });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('переход со старой версии: открытые файлы зашифрованы, секретов на диске не осталось', async () => {
  const d = oldDataDir();
  try {
    const v = vaultOf(d);
    const st = await v.open();
    assert.equal(st.state, 'ok');
    assert.equal(st.migrated, 7, JSON.stringify(st));
    assert.equal(st.migrateErrors, undefined);
    const SECRETS = ['SECRET-PC-NAME', 'SECRET-BOT-TOKEN', 'SECRET-LICENSE-KEY', 'SECRET-AWAY', 'SECRET-DECOY', 'PHOTO-OF-INTRUDER', 'firewall-on'];
    for (const f of allFiles(d)) {
      const r = rel(d, f);
      const buf = fs.readFileSync(f);
      if (['settings.json', 'server.json', 'data.key'].includes(r) || r.startsWith('window/')) continue;
      assert.ok(isSealed(buf), `${r} не зашифрован`);
      for (const s of SECRETS) assert.ok(!buf.includes(s), `${r}: ${s}`);
    }
    assert.ok(!allFiles(d).some((f) => f.endsWith('.tmp')), 'временных файлов не осталось');
    // Открытыми остались только файлы без личных сведений.
    assert.equal(JSON.parse(fs.readFileSync(path.join(d, 'settings.json'), 'utf8')).lang, 'en');
    assert.equal(fs.readFileSync(path.join(d, 'window/Default/Preferences'), 'utf8'), 'edge profile');
    // Программа читает всё как раньше.
    const store = createStore(d, { vault: v });
    assert.equal(store.read('report.json', null).facts.meta.computer, 'SECRET-PC-NAME');
    assert.equal(store.settings().background, true);
    const tg = createTelegram({ dataDir: d, store });
    assert.equal(tg.status().hasToken, true);
    assert.equal(tg.status().tokenHint, '…cdef');
    const photo = path.join(d, 'away/photos/0123456789abcdef0123456789abcdef.jpg');
    assert.ok(v.decode('away/photos/0123456789abcdef0123456789abcdef.jpg', fs.readFileSync(photo)).equals(JPEG));
    // Повторный запуск ничего не перешифровывает.
    const again = await vaultOf(d).open();
    assert.equal(again.state, 'ok');
    assert.equal(again.migrated, undefined);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('Telegram и приманки с store пишут свои файлы зашифрованными', async () => {
  const d = tmp();
  try {
    const v = vaultOf(d);
    await v.open();
    const store = createStore(d, { vault: v });
    const tg = createTelegram({ dataDir: d, store });
    tg.status(); // чтение пустого
    store.write('telegram.json', { token: TOKEN });
    assert.ok(!fs.readFileSync(path.join(d, 'telegram.json')).includes('SECRET-BOT-TOKEN'));
    assert.equal(tg.status().hasToken, true);
    const canary = createCanary({ dataDir: d, store, dirs: [d], hide: () => {} });
    assert.ok(canary);
    store.write('canary.json', { files: [{ path: 'C:\\SECRET-DECOY.docx' }] });
    assert.ok(!fs.readFileSync(path.join(d, 'canary.json')).includes('SECRET-DECOY'));
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('data.key пропал: программа не падает, данные не перезаписываются, «Начать заново» работает', async () => {
  const d = oldDataDir();
  try {
    await vaultOf(d).open();
    fs.unlinkSync(path.join(d, KEY_FILE));
    const sealedReport = fs.readFileSync(path.join(d, 'report.json'));
    const v = vaultOf(d);
    const st = await v.open();
    assert.equal(st.state, 'broken');
    assert.equal(st.reason, 'key-missing');
    assert.ok(!fs.existsSync(path.join(d, KEY_FILE)), 'новый ключ молча не создаётся');
    const store = createStore(d, { vault: v });
    assert.equal(store.read('report.json', 'нет'), 'нет');
    assert.equal(store.settings().lang, 'en', 'настройки читаются');
    // Новые результаты - только в памяти, на диске ничего открытым текстом.
    store.write('report.json', { fresh: 'NEW-RESULT' });
    assert.deepEqual(store.read('report.json', null), { fresh: 'NEW-RESULT' });
    assert.ok(fs.readFileSync(path.join(d, 'report.json')).equals(sealedReport));
    for (const f of allFiles(d)) assert.ok(!fs.readFileSync(f).includes('NEW-RESULT'), rel(d, f));
    // «Начать заново»: старое - в unreadable-*, новый ключ, данные из памяти сохранены зашифрованными.
    const r = await v.reset();
    assert.equal(r.state, 'ok');
    assert.match(r.movedTo, /^unreadable-\d{8}-\d{6}$/);
    assert.ok(fs.existsSync(path.join(d, r.movedTo, 'report.json')));
    assert.ok(fs.existsSync(path.join(d, r.movedTo, 'away/photos/0123456789abcdef0123456789abcdef.jpg')));
    assert.ok(fs.existsSync(path.join(d, KEY_FILE)));
    const buf = fs.readFileSync(path.join(d, 'report.json'));
    assert.ok(isSealed(buf) && !buf.includes('NEW-RESULT'));
    assert.deepEqual(createStore(d, { vault: v }).read('report.json', null), { fresh: 'NEW-RESULT' });
    assert.ok(!fs.existsSync(path.join(d, 'telegram.json')), 'старый токен перенесён, не прочитан');
    // Следующий запуск открывает новый ключ.
    assert.equal((await vaultOf(d).open()).state, 'ok');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('data.key испорчен, чужой или DPAPI не открывает его: понятное состояние вместо падения', async () => {
  const d = oldDataDir();
  try {
    await vaultOf(d).open();
    const good = fs.readFileSync(path.join(d, KEY_FILE));
    // Мусор вместо ключа.
    fs.writeFileSync(path.join(d, KEY_FILE), 'не json');
    assert.deepEqual(await vaultOf(d).open(), { state: 'broken', reason: 'key-unreadable' });
    // Ключ с другого компьютера: DPAPI отказывает.
    fs.writeFileSync(path.join(d, KEY_FILE), good);
    assert.equal((await vaultOf(d, { unprotect: async () => { throw new Error('Key not valid for use in specified state.'); } }).open()).reason, 'key-unreadable');
    // Ключ от другой папки данных: проверочная запись не сходится.
    const other = tmp();
    try {
      await vaultOf(other).open();
      fs.copyFileSync(path.join(other, KEY_FILE), path.join(d, KEY_FILE));
      assert.equal((await vaultOf(d).open()).reason, 'key-mismatch');
    } finally { fs.rmSync(other, { recursive: true, force: true }); }
    // С правильным ключом всё снова открывается.
    fs.writeFileSync(path.join(d, KEY_FILE), good);
    const v = vaultOf(d);
    assert.equal((await v.open()).state, 'ok');
    assert.equal(createStore(d, { vault: v }).read('license.json', null).key, 'ADAMANT1.SECRET-LICENSE-KEY');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('DPAPI недоступен при создании ключа: данные остаются как были, программа работает', async () => {
  const d = oldDataDir();
  try {
    const v = vaultOf(d, { protect: async () => { throw new Error('DPAPI'); } });
    const st = await v.open();
    assert.equal(st.state, 'broken');
    assert.equal(st.reason, 'dpapi');
    assert.equal(JSON.parse(fs.readFileSync(path.join(d, 'license.json'), 'utf8')).key, 'ADAMANT1.SECRET-LICENSE-KEY', 'ничего не потеряно');
    const store = createStore(d, { vault: v });
    assert.equal(store.read('license.json', null).key, 'ADAMANT1.SECRET-LICENSE-KEY', 'старые открытые файлы читаются');
    store.write('report.json', { x: 'MEMORY-ONLY' });
    assert.ok(!fs.readFileSync(path.join(d, 'report.json')).includes('MEMORY-ONLY'));
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('без vault хранилище работает как раньше (тесты и старые вызовы)', () => {
  const d = tmp();
  try {
    const s = createStore(d);
    s.write('report.json', { a: 1 });
    assert.equal(JSON.parse(fs.readFileSync(path.join(d, 'report.json'), 'utf8')).a, 1);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('сервер открывает ключ до работы с данными и показывает его состояние окну', () => {
  const idx = fs.readFileSync(path.join(ROOT, 'server', 'index.js'), 'utf8');
  assert.ok(idx.indexOf('await vault.open()') > idx.indexOf("fs.openSync(lockFile, 'wx')"), 'ключ - после захвата server.lock');
  assert.ok(idx.indexOf('await vault.open()') < idx.indexOf('createGuard(store)'), 'ключ - до того, как модули читают данные');
  for (const m of ['createCanary({ dataDir: cfg.dataDir, store,', 'store, vault, dataDir: cfg.dataDir,', 'createTelegram({ dataDir: cfg.dataDir, store,']) assert.ok(idx.includes(m), m);
  const app = fs.readFileSync(path.join(ROOT, 'server', 'app.js'), 'utf8');
  assert.ok(app.includes("'POST /api/vault/reset'") && app.includes('vault: vault ? safe(() => vault.state(), null) : null'));
  const ui = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  assert.ok(ui.includes("api('/api/vault/reset', {})") && ui.includes('vaultNotice(),'));
});

test('dpapi.ps1: только DPAPI текущего пользователя, данные - через стандартный ввод', () => {
  const src = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'dpapi.ps1'), 'utf8');
  assert.match(src, /DataProtectionScope\]::CurrentUser/);
  assert.doesNotMatch(src, /LocalMachine|Set-Content|Out-File|WriteAll|Remove-Item/i);
  assert.match(src, /\[Console\]::In\.ReadToEnd\(\)/);
});

test('настоящий DPAPI: ключ создаётся и открывается в этой учётной записи', { skip: process.platform !== 'win32', timeout: 120_000 }, async () => {
  const d = tmp();
  try {
    fs.writeFileSync(path.join(d, 'report.json'), '{"real":true}');
    const v = createVault({ dataDir: d });
    assert.equal((await v.open()).state, 'ok');
    const v2 = createVault({ dataDir: d });
    assert.equal((await v2.open()).state, 'ok');
    assert.deepEqual(createStore(d, { vault: v2 }).read('report.json', null), { real: true });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- пароль автовхода

const FIX_HARNESS = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$src = [IO.File]::ReadAllText($env:FIX_PS)
$ast = [Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
$want = @('Msg', 'Change', 'Shown', 'Restore-Reg', 'Reg-Capture', 'Reg-Undo', 'Remove-StoredSecrets')
foreach ($f in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  if ($want -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$ADMINS = 'S-1-5-32-544'; $SYSTEM = 'S-1-5-18'; $Store = $env:STORE_DIR
function Get-OwnerSid($p) { return $ADMINS }
function Save-Record([string]$rec, $data) { [IO.File]::WriteAllText((Join-Path $Store "$rec.json"), ($data | ConvertTo-Json -Depth 8)) }
$script:reg = @{ AutoAdminLogon = '1'; DefaultPassword = 'Pa55-word-XYZ' }
function Get-RegState([string]$path, [string]$name) { return [ordered]@{ path = $path; name = $name; existed = $true; kind = 'String'; value = $script:reg[$name] } }
$script:sets = @()
function Set-Reg($path, $name, $value, $kind) { $script:sets += $name }
function Remove-ItemProperty { }
$specs = @(@{ path = 'HKLM:\X'; name = 'AutoAdminLogon'; value = '0'; kind = 'String' }, @{ path = 'HKLM:\X'; name = 'DefaultPassword'; remove = $true; secret = $true })
$cap = ConvertTo-Json -InputObject @(Reg-Capture $specs) -Depth 5 -Compress
$undo = ConvertTo-Json -InputObject @(Reg-Undo ($cap | ConvertFrom-Json)) -Depth 5 -Compress
$old = [ordered]@{ id = 'autologon-off'; backup = [ordered]@{ specs = @(); regs = @([ordered]@{ path = 'HKLM:\X'; name = 'DefaultPassword'; existed = $true; kind = 'String'; value = 'Old-Secret-777' }) } }
[IO.File]::WriteAllText((Join-Path $Store 'r1.json'), ($old | ConvertTo-Json -Depth 8))
Remove-StoredSecrets
$after = [IO.File]::ReadAllText((Join-Path $Store 'r1.json'))
[Console]::Out.Write((@{ cap = $cap; undo = $undo; sets = @($script:sets); after = $after } | ConvertTo-Json -Depth 5 -Compress))
`;

test('fix.ps1: пароль автовхода не попадает в запись отката, старые записи очищаются', { skip: process.platform !== 'win32', timeout: 120_000 }, () => {
  const d = tmp();
  try {
    const script = path.join(d, 'harness.ps1');
    fs.writeFileSync(script, FIX_HARNESS);
    const store = path.join(d, 'undo');
    fs.mkdirSync(store);
    const out = execFileSync(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script],
      { env: { ...process.env, FIX_PS: path.join(ROOT, 'server', 'ps', 'fix.ps1'), STORE_DIR: store }, encoding: 'utf8', windowsHide: true });
    const r = JSON.parse(out.replace(/^\uFEFF/, ''));
    assert.ok(!r.cap.includes('Pa55-word-XYZ'), 'пароль не сохраняется');
    const cap = JSON.parse(r.cap);
    const pw = cap.find((x) => x.name === 'DefaultPassword');
    assert.equal(pw.secret, true);
    assert.equal(pw.existed, true);
    assert.equal(cap.find((x) => x.name === 'AutoAdminLogon').value, '1', 'обычные значения сохраняются');
    assert.deepEqual([].concat(r.sets), ['AutoAdminLogon'], 'откат не пишет пароль в реестр');
    assert.ok(r.undo.includes('введите пароль автовхода заново'), r.undo);
    assert.ok(!r.after.includes('Old-Secret-777'), 'старая запись очищена');
    assert.match(r.after, /"secret":\s*true/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
