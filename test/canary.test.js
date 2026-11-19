'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createCanary, defaultDirs, NAMES, PREFIX } = require('../server/canary');

function setup(opts = {}) {
  // Полный путь: %TEMP% бывает с коротким именем (C:UsersABCD~1), а приманки хранят полные пути.
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-canary-')));
  const dataDir = path.join(root, 'data');
  const docs = path.join(root, 'Documents');
  const desk = path.join(root, 'Desktop');
  fs.mkdirSync(docs);
  fs.mkdirSync(desk);
  const hidden = [];
  const alerts = [];
  const c = createCanary({ dataDir, dirs: [docs, desk], hide: async (p) => { hidden.push(p); }, onAlert: (a) => alerts.push(a), ...opts });
  return { root, dataDir, docs, desk, hidden, alerts, c, cleanup: () => { c.stop(); fs.rmSync(root, { recursive: true, force: true }); } };
}

const waitFor = async (cond, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return cond();
};

test('приманки: имена стоят первыми по алфавиту', () => {
  for (const n of NAMES) {
    assert.ok(n.startsWith(PREFIX));
    assert.ok(n.startsWith('!'), n);
    assert.ok([n, 'Анкета.docx', 'Archive.xlsx', '0 Отчёт.docx', '_old.docx'].sort()[0] === n, n);
  }
  assert.equal(new Set(NAMES.map((n) => path.extname(n))).size, 2);
});

test('arm: по два файла в каждой папке, скрыты, список в canary.json', async () => {
  const s = setup();
  try {
    const st = await s.c.arm();
    assert.equal(st.armed, true);
    assert.equal(st.files.length, 4);
    for (const dir of [s.docs, s.desk]) for (const n of NAMES) {
      const p = path.join(dir, n);
      assert.match(fs.readFileSync(p, 'utf8'), /контрольный файл программы «Адамант»/);
      assert.ok(s.hidden.includes(p), `скрыт: ${p}`);
    }
    const m = JSON.parse(fs.readFileSync(path.join(s.dataDir, 'canary.json'), 'utf8'));
    assert.ok(m.armedAt);
    assert.equal(m.files.length, 4);
    for (const f of m.files) assert.match(f.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(s.c.check(), []);
    // Повторное включение не плодит файлы и не ломает список.
    const again = await s.c.arm();
    assert.equal(again.files.length, 4);
    assert.deepEqual(s.c.check(), []);
  } finally {
    s.cleanup();
  }
});

test('check: изменение, удаление, переименование', async () => {
  const s = setup();
  try {
    await s.c.arm();
    const [docx, xlsx] = NAMES.map((n) => path.join(s.docs, n));
    const deskDocx = path.join(s.desk, NAMES[0]);
    fs.writeFileSync(docx, 'зашифровано');
    fs.unlinkSync(xlsx);
    fs.renameSync(deskDocx, `${deskDocx}.locked`);
    const r = s.c.check();
    const by = Object.fromEntries(r.map((x) => [x.path, x.change]));
    assert.equal(by[docx], 'modified');
    assert.equal(by[xlsx], 'deleted');
    assert.equal(by[deskDocx], 'renamed');
    assert.equal(r.length, 3);
    for (const x of r) assert.ok(x.at);
    assert.ok(s.c.status().lastCheck);
  } finally {
    s.cleanup();
  }
});

test('arm не перезаписывает чужой файл с тем же именем, disarm не удаляет чужие файлы', async () => {
  const s = setup();
  try {
    const foreign = path.join(s.desk, NAMES[1]);
    fs.writeFileSync(foreign, 'мой документ');
    const st = await s.c.arm();
    assert.equal(fs.readFileSync(foreign, 'utf8'), 'мой документ');
    assert.ok(st.skipped.some((x) => x.reason === 'foreign'));
    assert.equal(st.files.length, 3);
    const other = path.join(s.docs, 'Отчёт.docx');
    fs.writeFileSync(other, 'отчёт');
    // Подделанный список: чужой файл и файл вне папок приманок - disarm их не трогает.
    const mPath = path.join(s.dataDir, 'canary.json');
    const m = JSON.parse(fs.readFileSync(mPath, 'utf8'));
    const outside = path.join(s.root, NAMES[0]);
    fs.writeFileSync(outside, 'вне папок');
    m.files.push({ path: other, sha256: '0'.repeat(64), size: 1 }, { path: outside, sha256: '0'.repeat(64), size: 1 });
    fs.writeFileSync(mPath, JSON.stringify(m));
    const r = await s.c.disarm();
    assert.equal(r.removed.length, 3);
    assert.ok(fs.existsSync(foreign));
    assert.ok(fs.existsSync(other));
    assert.ok(fs.existsSync(outside));
    for (const dir of [s.docs, s.desk]) assert.deepEqual(fs.readdirSync(dir).filter((n) => n.startsWith(PREFIX) && !fs.readFileSync(path.join(dir, n), 'utf8').startsWith('мой')), []);
    assert.equal(fs.existsSync(mPath), false);
    assert.equal(s.c.status().armed, false);
    assert.deepEqual(s.c.check(), []);
  } finally {
    s.cleanup();
  }
});

test('нет папки или нет доступа - пропуск, остальные папки работают', async () => {
  const s = setup();
  try {
    const c = createCanary({ dataDir: s.dataDir, dirs: [path.join(s.root, 'нет-папки'), s.docs], hide: async () => {} });
    const st = await c.arm();
    assert.equal(st.files.length, 2);
    assert.ok(st.skipped.some((x) => x.reason === 'missing'));
    await c.disarm();
    // Запись запрещена (как при контролируемом доступе к папкам).
    const denyFs = { ...fs, writeFileSync: (p, d, o) => { if (String(p).startsWith(s.desk)) { const e = new Error('EPERM'); e.code = 'EPERM'; throw e; } return fs.writeFileSync(p, d, o); } };
    const c2 = createCanary({ dataDir: s.dataDir, dirs: [s.docs, s.desk], fs: denyFs, hide: async () => {} });
    const st2 = await c2.arm();
    assert.equal(st2.files.length, 2);
    assert.equal(st2.skipped.filter((x) => x.reason === 'denied').length, 2);
    await c2.disarm();
  } finally {
    s.cleanup();
  }
});

test('watch: изменение приманки - одно предупреждение на случай', async () => {
  const s = setup({ debounceMs: 30 });
  try {
    await s.c.arm();
    assert.equal(s.c.watch(), 2);
    assert.equal(s.c.status().watching, 2);
    // Посторонние файлы не вызывают тревогу.
    fs.writeFileSync(path.join(s.docs, 'Отчёт.docx'), 'x');
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(s.alerts.length, 0);
    const p = path.join(s.docs, NAMES[0]);
    fs.writeFileSync(p, 'зашифровано 1');
    assert.ok(await waitFor(() => s.alerts.length === 1), 'предупреждение пришло');
    assert.equal(s.alerts[0].files[0].path, p);
    assert.equal(s.alerts[0].files[0].change, 'modified');
    assert.ok(s.alerts[0].at);
    // Тот же файл меняется дальше - повторного предупреждения нет.
    fs.writeFileSync(p, 'зашифровано 2');
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(s.alerts.length, 1);
    // Новый файл пострадал - новый случай.
    fs.unlinkSync(path.join(s.desk, NAMES[1]));
    assert.ok(await waitFor(() => s.alerts.length === 2), 'второе предупреждение');
    assert.equal(s.alerts[1].files[0].change, 'deleted');
    assert.equal(s.c.status().alerts.length, 2);
    s.c.stop();
    assert.equal(s.c.status().watching, 0);
  } finally {
    s.cleanup();
  }
});

test('watch: уже испорченная приманка замечается сразу при запуске слежения', async () => {
  const s = setup();
  try {
    await s.c.arm();
    fs.writeFileSync(path.join(s.desk, NAMES[0]), 'x');
    s.c.watch();
    assert.equal(s.alerts.length, 1);
  } finally {
    s.cleanup();
  }
});

test('defaultDirs: «Документы» и «Рабочий стол» профиля, запасной вариант - OneDrive', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-home-'));
  try {
    const home = path.join(root, 'user');
    const one = path.join(root, 'OneDrive');
    fs.mkdirSync(path.join(home, 'Desktop'), { recursive: true });
    fs.mkdirSync(path.join(one, 'Документы'), { recursive: true });
    assert.deepEqual(defaultDirs({ env: { USERPROFILE: home, OneDrive: one } }), [path.join(one, 'Документы'), path.join(home, 'Desktop')]);
    assert.deepEqual(defaultDirs({ env: { USERPROFILE: home } }), [path.join(home, 'Documents'), path.join(home, 'Desktop')]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
