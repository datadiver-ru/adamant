'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const ns = require('../server/netscan');

const ADAPTERS = [
  { alias: 'Ethernet', address: '192.168.1.20', prefix: 24, gateway: '192.168.1.1', virtual: false, hardware: true, status: 'Up' },
  { alias: 'Office', address: '10.20.30.40', prefix: 16, gateway: null, virtual: false, hardware: true, status: 'Up' },
  { alias: 'vpnd-sb', address: '172.19.0.1', prefix: 30, virtual: true, hardware: false, status: 'Up', description: 'sing-tun Tunnel' },
  { alias: 'Public', address: '8.8.4.4', prefix: 24, virtual: false, hardware: true },
  { alias: 'APIPA', address: '169.254.10.1', prefix: 16, virtual: false, hardware: true },
];

test('частные адреса: только 10/8, 172.16/12, 192.168/16', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.0.1']) assert.ok(ns.isPrivate(ip), ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '172.15.255.255', '169.254.1.1', '127.0.0.1', '100.64.0.1', '192.169.0.1', '1.2.3', 'abc', '::1', '256.1.1.1']) {
    assert.ok(!ns.isPrivate(ip), ip);
  }
});

test('подсети: публичные и служебные адреса отбрасываются, широкая сеть сужается до /24, VPN не выбран', () => {
  const subs = ns.subnets(ADAPTERS);
  assert.deepEqual(subs.map((s) => s.id), ['192.168.1.0/24', '10.20.30.0/24', '172.19.0.0/30']);
  const office = subs.find((s) => s.alias === 'Office');
  assert.equal(office.count, 254);
  assert.equal(office.first, '10.20.30.1');
  assert.equal(office.last, '10.20.30.254');
  assert.equal(subs.find((s) => s.alias === 'Ethernet').recommended, true);
  assert.equal(subs.find((s) => s.alias === 'vpnd-sb').recommended, false);
  assert.ok(subs.every((s) => s.count <= 256));
});

test('isAllowedTarget: только адреса из своих подсетей', () => {
  const subs = ns.subnets(ADAPTERS);
  assert.ok(ns.isAllowedTarget('192.168.1.77', subs));
  assert.ok(!ns.isAllowedTarget('192.168.2.77', subs), 'соседняя частная сеть - не своя');
  assert.ok(!ns.isAllowedTarget('10.20.31.1', subs), 'за пределами суженной /24');
  assert.ok(!ns.isAllowedTarget('8.8.4.10', subs), 'публичный адрес адаптера');
  assert.ok(!ns.isAllowedTarget('1.1.1.1', subs));
  assert.ok(!ns.isAllowedTarget('192.168.1.77', []));
  // Подделанная «подсеть» с публичным адресом не делает публичные адреса разрешёнными.
  assert.ok(!ns.isAllowedTarget('8.8.8.8', [{ address: '8.8.8.1', first: '8.8.8.1', last: '8.8.8.254' }]));
});

test('проверка обращается только к своим адресам и находит службы', async () => {
  const subs = ns.subnets(ADAPTERS);
  const touched = new Set();
  const devices = { '192.168.1.1': [80, 53], '192.168.1.50': [23, 445], '192.168.1.60': [3306] };
  const probe = async (ip, port) => {
    touched.add(ip);
    if (devices[ip]) return devices[ip].includes(port) ? 'open' : 'closed';
    return 'filtered';
  };
  const res = await ns.scan({
    subnets: subs, selected: ['192.168.1.0/24'], probe, httpInfo: async () => ({ status: 200, server: 'httpd', title: 'Router' }),
    neighbors: async () => [{ ip: '192.168.1.99', mac: 'AA-BB-CC-DD-EE-FF' }, { ip: '8.8.8.8', mac: '11-22-33-44-55-66' }],
  });
  for (const ip of touched) assert.ok(ns.isAllowedTarget(ip, subs), `обращение к чужому адресу ${ip}`);
  assert.ok(!touched.has('192.168.1.20'), 'свой адрес не проверяется');
  assert.equal(touched.size, 253);
  const hosts = new Map(res.hosts.map((h) => [h.ip, h]));
  assert.deepEqual([...hosts.keys()], ['192.168.1.1', '192.168.1.50', '192.168.1.60', '192.168.1.99']);
  assert.equal(hosts.get('192.168.1.1').kind, 'router');
  assert.equal(hosts.get('192.168.1.1').gateway, true);
  assert.deepEqual(hosts.get('192.168.1.50').open, [23, 445]);
  assert.equal(hosts.get('192.168.1.99').mac, 'AA-BB-CC-DD-EE-FF');
  assert.ok(!hosts.has('8.8.8.8'), 'сосед из ARP вне своей сети отброшен');

  const f = new Map(ns.networkFindings(res).map((x) => [x.id, x]));
  assert.equal(f.get('lan-telnet').sev, 'critical');
  assert.equal(f.get('lan-db').sev, 'high');
  assert.equal(f.get('lan-router-http').sev, 'advice');
});

test('проверка отказывается от невыбранных и неправильных подсетей', async () => {
  const subs = ns.subnets(ADAPTERS);
  await assert.rejects(ns.scan({ subnets: subs, selected: [] }));
  await assert.rejects(ns.scan({ subnets: subs, selected: ['8.8.4.0/24'] }));
  const forged = [{ id: 'x', address: '8.8.8.1', first: '8.8.8.1', last: '8.8.8.254', count: 254 }];
  await assert.rejects(ns.scan({ subnets: forged, selected: ['x'], probe: async () => assert.fail('не должно быть обращений') }));
  const huge = [{ id: 'y', address: '10.0.0.1', first: '10.0.0.1', last: '10.0.3.254', count: 1022 }];
  await assert.rejects(ns.scan({ subnets: huge, selected: ['y'], probe: async () => assert.fail('не должно быть обращений') }));
});

test('настоящее TCP-подключение: открытый и закрытый порт на этом компьютере', async () => {
  const net = require('node:net');
  const srv = net.createServer((s) => s.end()).listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const port = srv.address().port;
  assert.equal(await ns.probe('127.0.0.1', port, 1000), 'open');
  srv.close();
  await new Promise((r) => srv.once('close', r));
  assert.equal(await ns.probe('127.0.0.1', port, 1000), 'closed');
});
