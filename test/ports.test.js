'use strict';
/**
 * Порты: что это, можно ли закрыть, закрытие правилом брандмауэра с откатом, «Закрыть лишнее».
 * Без настоящего брандмауэра: fix.ps1 не запускается, runner поддельный.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const ports = require('../server/ports');
const fixes = require('../server/fixes');
const { render } = require('../server/i18n');
const { createApp } = require('../server/app');
const { createStore } = require('../server/store');
const licenseLib = require('../server/license');
const { good, NOW } = require('./fixtures/facts');

const ru = (m) => render('ru', m);
const FIX_PS = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'fix.ps1'), 'utf8');
const row = (over) => ({ proto: 'tcp', addr: '0.0.0.0', port: 80, pid: 900, proc: 'app', path: 'C:\\Program Files\\App\\app.exe', services: [], ...over });

function facts(extraTcp = [], extraUdp = []) {
  const f = good();
  f.ports = {
    tcp: [
      row({ port: 135, pid: 1000, proc: 'svchost', path: null, services: ['RpcSs'] }),
      row({ port: 445, pid: 4, proc: 'System', path: null }),
      row({ port: 445, addr: '::', pid: 4, proc: 'System', path: null }),
      row({ port: 5432, pid: 2000, proc: 'postgres', path: 'C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe' }),
      row({ port: 5500, pid: 2100, proc: 'python3.13', path: 'C:\\Users\\u\\AppData\\Local\\Programs\\Python\\python3.13.exe' }),
      row({ port: 8092, addr: '127.0.0.1', pid: 2100, proc: 'python3.13' }),
      row({ port: 49664, addr: '::', pid: 700, proc: 'lsass', path: 'C:\\Windows\\System32\\lsass.exe', services: ['SamSs'] }),
      row({ port: 51000, pid: 3000, proc: 'Telegram', path: 'C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe' }),
      row({ port: 52000, pid: 3100, proc: 'mystery', path: null }),
      row({ port: 4444, pid: 3200, proc: 'evil', path: 'C:\\Users\\u\\AppData\\Local\\Temp\\evil.exe' }),
      ...extraTcp,
    ],
    udp: [
      row({ proto: 'udp', port: 68, pid: 1100, proc: 'svchost', path: null, services: ['Dhcp'] }),
      row({ proto: 'udp', port: 53, addr: '172.25.240.1', pid: 1200, proc: 'svchost', path: null, services: ['SharedAccess'] }),
      row({ proto: 'udp', port: 5355, addr: '::', pid: 1300, proc: 'svchost', path: null, services: ['Dnscache'] }),
      row({ proto: 'udp', port: 1900, addr: 'fe80::1%22', pid: 1400, proc: 'svchost', path: null, services: ['SSDPSRV'] }),
      ...extraUdp,
    ],
  };
  return f;
}
const find = (a, proto, port) => a.items.find((i) => i.proto === proto && i.port === port);

test('порты: понятное описание, оценка и можно ли закрыть', () => {
  const a = ports.annotate(facts(), []);
  assert.deepEqual(a.firewallOff, []);
  const rpc = find(a, 'tcp', 135);
  assert.equal(rpc.info.verdict, 'system');
  assert.equal(rpc.close, null, 'RPC не закрываем');
  assert.ok(rpc.why);
  const smb = find(a, 'tcp', 445);
  assert.deepEqual(smb.addrs, ['0.0.0.0', '::'], 'одна строка на порт и процесс');
  assert.equal(smb.info.verdict, 'optional');
  assert.equal(smb.info.home, false, 'общие папки дома часто нужны - сами не отмечаем');
  assert.deepEqual(smb.close, { kind: 'port', proto: 'tcp', port: 445 });
  assert.match(ru(smb.info.breaks), /общие папки/);
  assert.equal(find(a, 'tcp', 5432).info.verdict, 'close');
  assert.equal(find(a, 'tcp', 5500).info.verdict, 'optional', 'Python - программа для разработки');
  const loc = find(a, 'tcp', 8092);
  assert.equal(loc.scope, 'local');
  assert.equal(loc.info.verdict, 'local');
  assert.equal(loc.close, null);
  assert.equal(find(a, 'tcp', 49664).info.verdict, 'system', 'служебный порт Windows с меняющимся номером');
  // Меняющийся номер у обычной программы - правило по программе; у программы без пути - нельзя.
  assert.deepEqual(find(a, 'tcp', 51000).close, { kind: 'program', path: 'C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe', name: 'Telegram' });
  assert.equal(find(a, 'tcp', 52000).close, null);
  const evil = find(a, 'tcp', 4444);
  assert.equal(evil.info.verdict, 'unknown');
  assert.match(ru(evil.info.what), /«evil»/);
  assert.equal(find(a, 'udp', 68).close, null, 'DHCP закрыть нельзя - пропадёт сеть');
  assert.equal(find(a, 'udp', 53).info.verdict, 'system', 'общий доступ к интернету');
  assert.equal(find(a, 'udp', 5355).info.home, true, 'LLMNR дома не нужен');
  assert.equal(find(a, 'udp', 1900).scope, 'addr');
  // У каждого порта есть имя и объяснение.
  for (const i of a.items) assert.ok(ru(i.info.name) && ru(i.info.what), `${i.proto}:${i.port}`);
});

test('порты: закрытые Адамантом видны по журналу, откаченные - нет', () => {
  const journal = [
    { record: 'r1', id: 'port-block', arg: { items: [{ kind: 'port', proto: 'tcp', port: 5432 }, { kind: 'program', path: 'c:\\users\\u\\appdata\\roaming\\telegram desktop\\telegram.exe' }] } },
    { record: 'r2', id: 'port-block', undoneAt: '2026-11-18T10:00:00Z', arg: { items: [{ kind: 'port', proto: 'tcp', port: 445 }] } },
    { record: 'r3', id: 'firewall-on', arg: null },
  ];
  const a = ports.annotate(facts(), journal);
  assert.equal(find(a, 'tcp', 5432).blocked, 'r1');
  assert.equal(find(a, 'tcp', 51000).blocked, 'r1', 'путь сравнивается без учёта регистра');
  assert.equal(find(a, 'tcp', 445).blocked, null);
});

test('port-block: закрыть можно только то, что есть в проверке и что разрешено', () => {
  const f = facts();
  const a = fixes.validate('port-block', f, { items: [{ kind: 'port', proto: 'tcp', port: 5432 }, { kind: 'port', proto: 'tcp', port: 5432 }, { kind: 'port', proto: 'udp', port: 5355, extra: 'x' }] });
  assert.equal(a.items.length, 2, 'повтор убран');
  assert.deepEqual(a.items.map((i) => [i.proto, i.port]), [['tcp', 5432], ['udp', 5355]]);
  // Путь программы берётся из проверки, а не из запроса.
  const p = fixes.validate('port-block', f, { items: [{ kind: 'program', path: 'C:\\USERS\\U\\APPDATA\\ROAMING\\TELEGRAM DESKTOP\\TELEGRAM.EXE' }] });
  assert.equal(p.items[0].path, 'C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe');
  for (const bad of [
    { items: [{ kind: 'port', proto: 'tcp', port: 135 }] },
    { items: [{ kind: 'port', proto: 'udp', port: 68 }] },
    { items: [{ kind: 'port', proto: 'tcp', port: 8092 }] },
    { items: [{ kind: 'port', proto: 'tcp', port: 9999 }] },
    { items: [{ kind: 'port', proto: 'tcp', port: '5432' }] },
    { items: [{ kind: 'port', proto: 'icmp', port: 5432 }] },
    { items: [{ kind: 'program', path: 'C:\\Windows\\System32\\lsass.exe' }] },
    { items: [{ kind: 'program', path: 'C:\\Windows\\System32\\cmd.exe' }] },
    { items: [] },
    { items: Array.from({ length: ports.MAX_ITEMS + 1 }, () => ({ kind: 'port', proto: 'tcp', port: 5432 })) },
    null,
  ]) assert.throws(() => fixes.validate('port-block', f, bad), JSON.stringify(bad));
  // Брандмауэр выключен - правило не сработает, закрывать не даём.
  const off = facts();
  off.firewall.profiles = off.firewall.profiles.map((x) => ({ ...x, enabled: 'False' }));
  assert.throws(() => fixes.validate('port-block', off, { items: [{ kind: 'port', proto: 'tcp', port: 5432 }] }), /Брандмауэр выключен/);
  assert.deepEqual(ports.annotate(off, []).firewallOff, ['Public']);
});

test('port-block: что изменится, что перестанет работать, и что уходит в fix.ps1', () => {
  const f = facts();
  const plan = fixes.plan('port-block', f, { items: [{ kind: 'port', proto: 'tcp', port: 445 }, { kind: 'program', path: 'C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe' }] });
  assert.equal(ru(plan.changes[0].what), 'Порт TCP 445 - Общие папки и принтеры (SMB)');
  assert.equal(ru(plan.changes[1].what), 'Программа «Telegram»');
  assert.equal(plan.changes[0].to, 'закрыт брандмауэром');
  assert.ok(plan.notes.map(ru).some((n) => n.startsWith('порт 445: Другие устройства не смогут открыть общие папки')));
  const args = fixes.scriptArgs('apply', { id: 'port-block', arg: plan.arg });
  const sent = JSON.parse(Buffer.from(args[5], 'base64').toString('utf8'));
  assert.deepEqual(sent, { items: [{ kind: 'port', proto: 'tcp', port: 445 }, { kind: 'program', path: 'C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe' }] }, 'в fix.ps1 - только порт или путь');
});

test('fix.ps1: port-block проверяет всё сам и откатывает только свои правила', () => {
  assert.ok(FIX_PS.includes("'port-block' = @{"));
  // Список портов, которые закрывать нельзя, одинаковый в JS и fix.ps1.
  const ps = FIX_PS.match(/\$NeverPorts = @\(([^)]*)\)/)[1].match(/'([a-z]+:\d+)'/g).map((x) => x.slice(1, -1)).sort();
  assert.deepEqual(ps, [...ports.NEVER].sort());
  const block = FIX_PS.slice(FIX_PS.indexOf('function PortBlock-Specs'), FIX_PS.indexOf("'firewall-on' = @{"));
  assert.match(block, /Брандмауэр выключен/);
  assert.match(block, /\$port -gt 49151/);
  assert.match(block, /SystemRoot/);
  assert.match(block, /Test-Path -LiteralPath \$full -PathType Leaf/);
  const fix = FIX_PS.slice(FIX_PS.indexOf("'port-block' = @{"), FIX_PS.indexOf('foreach ($k in $RegFixes.Keys)'));
  assert.match(fix, /Direction = 'Inbound'; Action = 'Block'/);
  assert.match(fix, /Remove-NetFirewallRule -Name \(\[string\]\$_\.name\)/, 'откат - по имени своего правила');
  assert.doesNotMatch(fix, /Remove-NetFirewallRule -(Group|DisplayName)/, 'чужие правила не трогаем');
});

// ---------------------------------------------------------------- Сервер: «Закрыть лишнее» - в полной версии

const KEY = 'ports-test-key-0123456789';
function req(port, method, route, body) {
  return new Promise((res, rej) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const r = http.request({ host: '127.0.0.1', port, method, path: route, headers: { Host: `127.0.0.1:${port}`, 'X-Adamant-Key': KEY, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}) } }, (s) => {
      const c = [];
      s.on('data', (x) => c.push(x));
      s.on('end', () => { const t = Buffer.concat(c).toString(); let j = null; try { j = JSON.parse(t); } catch { /* не JSON */ } res({ status: s.statusCode, json: j }); });
    });
    r.on('error', rej);
    if (data) r.write(data);
    r.end();
  });
}

test('сервер: порты в состоянии, по одному - всем, несколько сразу - в полной версии', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-ports-'));
  const lic = crypto.generateKeyPairSync('ed25519');
  const store = createStore(dir);
  const calls = [];
  const runner = { collect: async () => facts(), fix: async (args) => { calls.push(args); return { ok: true, record: '0f8fad5b-d9cb-469f-a165-70867728950e', changes: [] }; } };
  const app = createApp({ store, key: KEY, version: 'test', runner, now: () => NOW, autorun: { set: async () => {} }, openTarget: () => {}, licensePublicKey: lic.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const api = (m, r, b) => req(app.server.address().port, m, r, b);
  try {
    assert.equal((await api('GET', '/api/state')).json.ports, null, 'до проверки сведений нет');
    assert.equal((await api('POST', '/api/check', {})).status, 200);
    const st = (await api('GET', '/api/state')).json;
    assert.equal(find(st.ports, 'tcp', 5432).info.verdict, 'close');
    const two = { id: 'port-block', arg: { items: [{ kind: 'port', proto: 'tcp', port: 5432 }, { kind: 'port', proto: 'udp', port: 5355 }] } };
    assert.equal((await api('POST', '/api/fix/plan', two)).status, 402, 'бесплатно - не пачкой');
    assert.equal((await api('POST', '/api/fix/apply', two)).status, 402);
    assert.equal(calls.length, 0);
    const one = { id: 'port-block', arg: { items: [{ kind: 'port', proto: 'tcp', port: 5432 }] } };
    assert.equal((await api('POST', '/api/fix/plan', one)).status, 200);
    assert.equal((await api('POST', '/api/fix/apply', one)).status, 200);
    assert.deepEqual(calls[0].slice(0, 4), ['-Action', 'apply', '-Id', 'port-block']);
    assert.equal(find((await api('GET', '/api/state')).json.ports, 'tcp', 5432).blocked, '0f8fad5b-d9cb-469f-a165-70867728950e', 'закрытый порт виден по журналу');
    // С ключом полной версии - можно сразу несколько.
    store.write('license.json', { key: licenseLib.issue({ licensee: 'Проверка' }, lic.privateKey.export({ type: 'pkcs8', format: 'pem' })) });
    assert.equal((await api('GET', '/api/state')).json.license.features.ports, true);
    assert.equal((await api('POST', '/api/fix/apply', two)).status, 200);
    assert.equal(calls.length, 2);
  } finally {
    await new Promise((r) => app.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
