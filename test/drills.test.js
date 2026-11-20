'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createDrills, exposure, DRILLS, describe } = require('../server/drills');
const { createStore } = require('../server/store');
const { render } = require('../server/i18n');

const ROOT = path.join(__dirname, '..');
const DRILL_PS1 = path.join(ROOT, 'server/ps/drill.ps1');
const ADAPTERS = [
  { alias: 'Ethernet', address: '192.168.7.10', prefix: 24, gateway: '192.168.7.1', hardware: true, virtual: false, status: 'Up' },
  { alias: 'vEthernet (WSL)', address: '172.20.0.1', prefix: 20, gateway: null, hardware: false, virtual: true, status: 'Up' },
  { alias: 'Wi-Fi', address: '169.254.3.3', prefix: 16, gateway: null, hardware: true, virtual: false, status: 'Up' },
  { alias: 'VPN', address: '100.64.1.2', prefix: 32, gateway: null, hardware: false, virtual: true, status: 'Up' },
];
const facts = (tcp, fwOn = true) => ({
  ports: { tcp },
  firewall: { profiles: ['Domain', 'Private', 'Public'].map((name) => ({ name, enabled: fwOn ? 'True' : 'False' })) },
});

function tmpStore() {
  return createStore(fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-drills-')));
}

test('drill.ps1: BOM, нет учебных строк EICAR/AMSI в открытом виде, не меняет настройки', () => {
  const buf = fs.readFileSync(DRILL_PS1);
  assert.ok(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf, 'нет BOM - node tools/ps-bom.js');
  const src = buf.toString('utf8');
  // Сами учебные строки здесь не записаны: сверяются их отпечатки SHA-256.
  const EICAR_SHA = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
  const AMSI_SHA = '50a3a914f7ce11e2ec39815e1d3880e2d38a7917645c60b87224094d5267501c';
  const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
  const literal = (len, hash) => { for (let i = 0; i + len <= src.length; i++) if (sha(src.slice(i, i + len)) === hash) return true; return false; };
  assert.equal(literal(68, EICAR_SHA), false, 'строка EICAR в открытом виде');
  assert.equal(literal(54, AMSI_SHA), false, 'строка AMSI в открытом виде');
  assert.equal(/EICAR-STANDARD|AMSI Test Sample|7e72c3ce/i.test(src), false);
  // В сценарии нет ни кодов символов, ни кодирования и запуска «зашифрованных» команд:
  // учебные строки приходят от программы через стандартный ввод.
  assert.doesNotMatch(src, /EicarCodes|AmsiCodes|FromCodes|-EncodedCommand|ToBase64String|FromBase64String|\[char\]/i);
  assert.match(src, /ReadSample 68/);
  assert.match(src, /ReadSample 54/);
  assert.match(src, /-Command -'/);
  // Программа передаёт ровно стандартные строки, а в самом drills.js они только кодами.
  const { drillInput } = require('../server/drills');
  assert.equal(sha(JSON.parse(drillInput('eicar')).sample), EICAR_SHA);
  assert.equal(sha(JSON.parse(drillInput('amsi')).sample), AMSI_SHA);
  assert.equal(drillInput('cfa'), null);
  const js = fs.readFileSync(path.join(ROOT, 'server/drills.js'), 'utf8');
  assert.equal(/EICAR-STANDARD|AMSI Test Sample/i.test(js), false);
  const body = src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  const WRITE = /\b(Set-\w+|New-ItemProperty|New-Item\b|Remove-\w+|Disable-\w+|Enable-\w+|Stop-\w+|Start-Service|Restart-\w+|Add-MpPreference|Rename-\w+|Clear-\w+|Invoke-Expression|RunAs|reg(\.exe)?\s+(add|delete)|netsh\b|bcdedit\b)\b/i;
  const m = WRITE.exec(body);
  assert.equal(m, null, m && m[0]);
  assert.match(src, /ValidateSet\('eicar', 'amsi', 'cfa'\)/);
  assert.match(src, /Adamant-drill-/);
  assert.match(src, /Adamant-check-/);
});

test('DRILLS: четыре учения с понятным описанием', () => {
  assert.deepEqual(DRILLS.map((d) => d.id), ['eicar', 'amsi', 'cfa', 'exposure']);
  for (const d of DRILLS) for (const k of ['title', 'what', 'why']) assert.ok(typeof d[k] === 'string' && d[k].length > 5, `${d.id}.${k}`);
});

test('взгляд соседа: подключается только к своим частным адресам', async () => {
  const calls = [];
  const probe = async (ip, port) => { calls.push(`${ip}:${port}`); return port === 3389 || port === 8080 ? 'open' : 'closed'; };
  const r = await exposure({
    facts: facts([
      { addr: '0.0.0.0', port: 3389, proc: 'svchost' },
      { addr: '0.0.0.0', port: 8080, proc: 'python' },
      { addr: '127.0.0.1', port: 5177, proc: 'node' },
      { addr: '::1', port: 5178, proc: 'node' },
      { addr: '172.20.0.1', port: 6379, proc: 'redis-server' },
      { addr: '192.168.7.10', port: 5900, proc: 'vnc' },
      { addr: '10.9.9.9', port: 21, proc: 'ftp' },
      { addr: '8.8.8.8', port: 22, proc: 'evil' },
    ]),
    adapters: ADAPTERS,
    probe,
  });
  // Только физический частный адрес; петля, чужие адреса, link-local и CGNAT - никогда.
  for (const c of calls) assert.match(c, /^192\.168\.7\.10:/, c);
  assert.deepEqual(calls.map((c) => Number(c.split(':')[1])).sort((a, b) => a - b), [3389, 5900, 8080]);
  assert.equal(r.status, 'failed');
  assert.deepEqual(r.reachable.map((x) => [x.port, x.risky]), [[3389, true], [8080, false]]);
  assert.deepEqual(r.reachable[0].procs, ['svchost']);
  assert.equal(r.fix, 'rdp-off');
  assert.match(render('ru', r.detail), /3389 \(RDP\) - svchost/);
  assert.ok(render('ru', r.advice).length > 10);
});

test('взгляд соседа: SMB опасен только без брандмауэра; нет своей сети - пропуск', async () => {
  const tcp = [{ addr: '0.0.0.0', port: 445, proc: 'System' }, { addr: '::', port: 135, proc: 'svchost' }];
  const probe = async () => 'open';
  const on = await exposure({ facts: facts(tcp, true), adapters: ADAPTERS, probe });
  assert.equal(on.status, 'passed');
  assert.equal(on.reachable.length, 2);
  const off = await exposure({ facts: facts(tcp, false), adapters: ADAPTERS, probe });
  assert.equal(off.status, 'failed');
  assert.equal(off.fix, 'firewall-on');
  let probed = 0;
  const none = await exposure({ facts: facts(tcp), adapters: [{ alias: 'VPN', address: '100.64.1.2', status: 'Up' }], probe: async () => { probed++; return 'open'; } });
  assert.equal(none.status, 'skipped');
  assert.equal(probed, 0);
  assert.equal((await exposure({ facts: {}, adapters: ADAPTERS, probe })).status, 'skipped');
  // Сбой подключения - не сбой учения.
  const err = await exposure({ facts: facts(tcp, false), adapters: ADAPTERS, probe: async () => { throw new Error('x'); } });
  assert.equal(err.status, 'passed');
});

test('учения: по очереди, сбой одного не останавливает остальные, заголовок и сохранение', async () => {
  const store = tmpStore();
  const order = [];
  const runDrill = async (id) => {
    order.push(id);
    if (id === 'eicar') return { drill: 'eicar', status: 'passed', ms: 1234, detail: 'removed', threat: 'Virus:DOS/EICAR_Test_File' };
    if (id === 'amsi') throw new Error('powershell упал');
    if (id === 'cfa') return { drill: 'cfa', status: 'skipped', ms: 0, detail: 'off' };
    throw new Error('лишний вызов');
  };
  const drills = createDrills({ store, runDrill, exposure: async () => { order.push('exposure'); return { drill: 'exposure', status: 'passed', ms: 50, detail: 'ок' }; } });
  const r = await drills.run();
  assert.deepEqual(order, ['eicar', 'amsi', 'cfa', 'exposure']);
  assert.deepEqual(r.results.map((x) => x.status), ['passed', 'error', 'skipped', 'passed']);
  assert.equal(r.passed, 2);
  assert.equal(r.total, 2);
  assert.equal(render('ru', r.headline), 'Учения пройдены: отражено атак - 2 из 2');
  assert.match(render('ru', r.results[0].detail), /1\.2 с\. Название угрозы: Virus:DOS\/EICAR_Test_File/);
  assert.equal(r.results[0].ms, 1234);
  assert.match(render('ru', r.results[1].detail), /powershell упал/);
  assert.equal(r.results[2].fix, 'cfa-on');
  assert.ok(r.results[2].advice);
  for (const x of r.results) for (const k of ['id', 'status', 'title', 'detail', 'advice', 'ms']) assert.ok(k in x, `${x.id}.${k}`);
  assert.deepEqual(drills.last(), JSON.parse(JSON.stringify(r)));
  assert.deepEqual(store.read('drills.json', null).at, r.at);
});

test('учения: проваленные атаки - совет и кнопка исправления; выбор учений', async () => {
  const store = tmpStore();
  const runDrill = async (id) => ({ eicar: { status: 'failed', ms: 15000, detail: 'kept' }, amsi: { status: 'failed', ms: 300, detail: 'ran' }, cfa: { status: 'passed', ms: 5, detail: 'blocked' } }[id]);
  const drills = createDrills({ store, runDrill, exposure: async () => { throw new Error('не должен вызываться'); } });
  const r = await drills.run(['eicar', 'amsi', 'cfa', 'eicar', 'нет-такого']);
  assert.deepEqual(r.results.map((x) => x.id), ['eicar', 'amsi', 'cfa']);
  assert.equal(r.passed, 1);
  assert.equal(r.total, 3);
  assert.equal(render('ru', r.headline), 'Учения: отражено атак - 1 из 3, есть что исправить');
  assert.equal(r.results[0].fix, 'defender-realtime');
  assert.equal(r.results[1].fix, 'defender-realtime');
  assert.ok(r.results[0].advice && r.results[1].advice);
  assert.equal(r.results[2].advice, null);
  await assert.rejects(() => drills.run(['нет-такого']));
});

test('учения: зависшее учение останавливается по лимиту, остальные идут дальше', async () => {
  const store = tmpStore();
  let t = 0;
  const drills = createDrills({
    store, drillMs: 30, totalMs: 10_000,
    runDrill: (id) => (id === 'eicar' ? new Promise(() => {}) : Promise.resolve({ status: 'passed', ms: 1, detail: 'blocked' })),
    exposure: async () => ({ status: 'passed', ms: 1, detail: 'ок' }),
  });
  const r = await drills.run();
  assert.equal(r.results[0].status, 'error');
  assert.match(render('ru', r.results[0].detail), /не уложилась во время/);
  assert.equal(r.results[1].status, 'passed');
  // Общий лимит: время вышло - остальные помечены пропущенными, без запуска.
  let calls = 0;
  const late = createDrills({ store, totalMs: 100, now: () => (t += 1000), runDrill: async () => { calls++; return { status: 'passed', ms: 1, detail: 'blocked' }; }, exposure: async () => ({ status: 'passed' }) });
  const r2 = await late.run(['amsi', 'cfa']);
  assert.equal(calls, 0);
  assert.deepEqual(r2.results.map((x) => x.status), ['skipped', 'skipped']);
  assert.equal(render('ru', r2.headline), 'Учения не прошли: ни одна проверка не дала ответа');
});

test('describe: неизвестный ответ - ошибка, а не «пройдено»', () => {
  assert.equal(describe('eicar', null).status, 'error');
  assert.equal(describe('amsi', { status: 'ok' }).status, 'error');
  assert.match(render('ru', describe('cfa', { status: 'skipped', detail: 'audit' }).detail), /аудита/);
  assert.match(render('ru', describe('amsi', { status: 'error', detail: 'timeout' }).detail), /не уложилась/);
});
