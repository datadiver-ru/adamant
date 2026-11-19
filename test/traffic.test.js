'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { analyse, ipScope, adapterKind } = require('../server/traffic');
const { render } = require('../server/i18n');

const ru = (m) => render('ru', m);
const ids = (r) => r.findings.map((f) => f.id).sort();

const WIFI_OPEN = `There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Cafe Free
    BSSID                  : 11:22:33:44:55:66
    Radio type             : 802.11ax
    Authentication         : Open
    Cipher                 : None
    Connection mode        : Auto Connect
    Band                   : 5 GHz
    Channel                : 44
    Signal                 : 81%
    Profile                : Cafe Free`;

function raw(over = {}) {
  return {
    format: 'adamant-traffic', version: 1, at: '2026-11-18T12:00:00.000Z', errors: {},
    adapters: [
      { alias: 'Wi-Fi', description: 'Intel(R) Wi-Fi 6 AX201', ifIndex: 12, status: 'Up', media: 'Native 802.11', virtual: false, hardware: true, speed: '1.2 Gbps', mac: 'AA-BB-CC-DD-EE-01',
        ipv4: ['192.168.1.36'], ipv6: ['fe80::1', '2a02:6b8::36'], gateway: '192.168.1.1', gateway6: 'fe80::1', dns: ['192.168.1.1', 'fec0:0:0:ffff::1'], category: 'Private', network: 'Home', rx: 1_000_000, tx: 500_000 },
      { alias: 'vEthernet (Default Switch)', description: 'Hyper-V Virtual Ethernet Adapter', ifIndex: 30, status: 'Up', media: 'Unspecified', virtual: true, hardware: false, ipv4: ['172.20.0.1'], ipv6: [], dns: [], rx: 0, tx: 0 },
    ],
    rate: { seconds: 2, adapters: [{ alias: 'Wi-Fi', rx: 20_000, tx: 4_000 }] },
    wifi: null,
    tcp: [
      { la: '192.168.1.36', lp: 50001, ra: '93.184.216.34', rp: 443, state: 'Established', pid: 100 },
      { la: '192.168.1.36', lp: 50002, ra: '93.184.216.35', rp: 443, state: 'Established', pid: 100 },
      { la: '127.0.0.1', lp: 50003, ra: '127.0.0.1', rp: 9229, state: 'Established', pid: 100 },
      { la: '0.0.0.0', lp: 445, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 4 },
      { la: '127.0.0.1', lp: 9229, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 300 },
    ],
    udp: [],
    procs: { 100: { name: 'firefox', path: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' }, 300: { name: 'node', path: 'C:\\Program Files\\nodejs\\node.exe' } },
    dns: [{ name: 'example.com', ip: '93.184.216.34' }],
    shares: [{ name: 'ADMIN$', path: 'C:\\Windows', type: 2147483648 }, { name: 'C$', path: 'C:\\', type: 2147483648 }, { name: 'IPC$', path: '', type: 2147483651 }],
    sharing: { files: [], discovery: ['Private'] },
    vpn: [],
    ...over,
  };
}

test('адреса: виды и границы', () => {
  assert.equal(ipScope('8.8.8.8'), 'public');
  assert.equal(ipScope('192.168.0.5'), 'private');
  assert.equal(ipScope('172.31.255.1'), 'private');
  assert.equal(ipScope('172.32.0.1'), 'public');
  assert.equal(ipScope('100.64.1.1'), 'cgnat');
  assert.equal(ipScope('169.254.3.3'), 'linklocal');
  assert.equal(ipScope('127.0.0.1'), 'loopback');
  assert.equal(ipScope('0.0.0.0'), 'unspecified');
  assert.equal(ipScope('239.255.255.250'), 'multicast');
  assert.equal(ipScope('::ffff:10.0.0.1'), 'private');
  assert.equal(ipScope('fe80::1'), 'linklocal');
  assert.equal(ipScope('fd00::1'), 'private');
  assert.equal(ipScope('2a02:6b8::1'), 'public');
  assert.equal(ipScope('::1'), 'loopback');
  assert.equal(ipScope('300.1.1.1'), 'invalid');
  assert.equal(adapterKind({ alias: 'vpnd-sb', description: 'sing-tun Tunnel' }), 'vpn');
  assert.equal(adapterKind({ alias: 'vEthernet (WSL)', description: 'Hyper-V Virtual Ethernet Adapter', virtual: true }), 'virtual');
  assert.equal(adapterKind({ alias: 'Ethernet', description: 'Realtek PCIe GbE', media: '802.3' }), 'ethernet');
});

test('спокойная сеть: скорость, программы, имена из кэша DNS, без находок', () => {
  const r = analyse(raw());
  assert.deepEqual(ids(r), ['net-ok']);
  assert.equal(r.speed.rx, 10_000, 'байты за 2 секунды → в секунду');
  assert.equal(r.speed.tx, 2_000);
  assert.equal(r.adapters.length, 1, 'виртуальный адаптер Hyper-V не показывается');
  assert.equal(r.outgoing.length, 1);
  assert.equal(r.outgoing[0].name, 'firefox');
  assert.equal(r.outgoing[0].count, 2, 'локальное соединение 127.0.0.1 не считается');
  assert.equal(r.outgoing[0].remotes[0].host, 'example.com');
  assert.equal(r.outgoing[0].remotes[1].host, null);
  assert.deepEqual(r.adapters[0].dns, ['192.168.1.1'], 'заглушки fec0::ffff не показываются');
  assert.deepEqual(r.listening.map((l) => [l.name, l.port, l.system]), [['System', 445, true]], 'порт только на 127.0.0.1 - не для сети');
  assert.equal(r.devices, null);
});

test('опасности: открытый Wi-Fi, порт бэкдора, Tor, программа из «Загрузок», удалённый доступ, вход из интернета', () => {
  const r = analyse(raw({
    wifi: WIFI_OPEN,
    tcp: [
      { la: '192.168.1.36', lp: 50010, ra: '45.9.20.1', rp: 4444, state: 'Established', pid: 200 },
      { la: '192.168.1.36', lp: 50011, ra: '51.15.1.1', rp: 9001, state: 'Established', pid: 201 },
      { la: '192.168.1.36', lp: 50012, ra: '188.1.1.1', rp: 443, state: 'Established', pid: 202 },
      { la: '192.168.1.36', lp: 50013, ra: '20.1.1.1', rp: 21, state: 'Established', pid: 100 },
      { la: '0.0.0.0', lp: 3389, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 203 },
      { la: '192.168.1.36', lp: 3389, ra: '203.0.113.50', rp: 51000, state: 'Established', pid: 203 },
    ],
    procs: {
      100: { name: 'filezilla', path: 'C:\\Program Files\\FileZilla\\filezilla.exe' },
      200: { name: 'update', path: 'C:\\Users\\u\\AppData\\Local\\Temp\\x\\update.exe' },
      201: { name: 'tor', path: 'C:\\Users\\u\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe' },
      202: { name: 'AnyDesk', path: 'C:\\Users\\u\\Downloads\\AnyDesk.exe' },
      203: { name: 'svchost', path: 'C:\\Windows\\System32\\svchost.exe' },
    },
    sharing: { files: ['Public', 'Private'], discovery: ['Any'] },
    shares: [{ name: 'Фото', path: 'D:\\Фото', type: 0 }, { name: 'IPC$', path: '', type: 2147483651 }],
  }));
  assert.deepEqual(ids(r), ['net-danger-port', 'net-discovery-public', 'net-incoming-internet', 'net-plain', 'net-remote-tool', 'net-shares', 'net-sharing-public', 'net-temp-proc', 'net-tor', 'net-wifi-open'].sort());
  const by = new Map(r.findings.map((f) => [f.id, f]));
  assert.equal(by.get('net-wifi-open').sev, 'high');
  assert.match(ru(by.get('net-wifi-open').evidence[0]), /Cafe Free/);
  assert.match(ru(by.get('net-danger-port').evidence[0]), /update → 45\.9\.20\.1:4444 \(Metasploit\)/);
  assert.equal(by.get('net-temp-proc').evidence.length, 2, 'Temp и «Загрузки»');
  assert.match(ru(by.get('net-incoming-internet').evidence[0]), /svchost: порт 3389 ← 203\.0\.113\.50/);
  assert.equal(by.get('net-sharing-public').open, 'sharing');
  assert.deepEqual(by.get('net-shares').evidence.map(ru), ['«Фото»: D:\\Фото'], 'служебные папки C$, IPC$ не считаются');
  assert.equal(r.incoming.length, 1);
  assert.equal(r.incoming[0].scope, 'internet');
  assert.ok(!r.outgoing.some((o) => o.name === 'svchost'), 'входящее соединение не попадает в исходящие');
  assert.equal(r.wifi.signal, 81);
  assert.equal(r.wifi.channel, 44);
});

test('VPN: утечка IPv6 мимо туннеля и программы в общественной сети', () => {
  const base = raw();
  const r = analyse(raw({
    adapters: [
      { ...base.adapters[0], category: 'Public' },
      { alias: 'WireGuard', description: 'WireGuard Tunnel', ifIndex: 40, status: 'Up', media: 'Unspecified', virtual: true, ipv4: ['10.8.0.2'], ipv6: [], dns: ['10.8.0.1'], category: 'Public' },
    ],
    tcp: [...base.tcp, { la: '0.0.0.0', lp: 5432, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 300 }],
    procs: { ...base.procs, 300: { name: 'postgres', path: 'C:\\Program Files\\PostgreSQL\\bin\\postgres.exe' } },
  }));
  assert.equal(r.vpn.on, true);
  assert.deepEqual(r.vpn.names, ['WireGuard']);
  assert.deepEqual(ids(r), ['net-listen-public', 'net-vpn-ipv6']);
  assert.match(ru(r.findings.find((f) => f.id === 'net-listen-public').evidence[0]), /postgres: порт 5432/);
  // Без своего IPv6 у обычного подключения - утечки нет.
  const r2 = analyse(raw({ adapters: [{ ...base.adapters[0], ipv6: ['fe80::1'] }, { alias: 'WireGuard', description: 'WireGuard Tunnel', ifIndex: 40, status: 'Up', virtual: true, ipv4: ['10.8.0.2'] }] }));
  assert.ok(!ids(r2).includes('net-vpn-ipv6'));
});

test('кто в сети: только частные адреса физических адаптеров, роутер, случайный MAC, новые устройства', () => {
  const neighbors = [
    { ip: '192.168.1.1', mac: '50-FF-20-A1-89-C8', state: 'Reachable', ifIndex: 12 },
    { ip: '192.168.1.37', mac: '92-C1-41-FB-42-0C', state: 'Stale', ifIndex: 12 },
    { ip: '192.168.1.40', mac: 'F8-B5-4D-53-75-AF', state: 'Stale', ifIndex: 12 },
    { ip: '172.20.0.5', mac: '00-15-5D-01-02-03', state: 'Stale', ifIndex: 30 },
    { ip: '8.8.8.8', mac: '00-11-22-33-44-55', state: 'Stale', ifIndex: 12 },
  ];
  const first = analyse(raw(), { neighbors, known: null });
  assert.deepEqual(first.devices.map((d) => d.ip), ['192.168.1.1', '192.168.1.37', '192.168.1.40'], 'сеть Hyper-V и публичный адрес не показываются');
  assert.equal(first.devices[0].gateway, true);
  assert.equal(first.devices[1].randomMac, true);
  assert.equal(first.devices[2].randomMac, false);
  assert.ok(first.devices.every((d) => !d.isNew), 'в первый раз «новых» нет');
  const second = analyse(raw(), { neighbors, known: new Set(['50-FF-20-A1-89-C8', '92-C1-41-FB-42-0C']) });
  assert.deepEqual(second.devices.filter((d) => d.isNew).map((d) => d.ip), ['192.168.1.40']);
});

test('чужой или испорченный ответ не принимается, странные поля не ломают', () => {
  assert.throws(() => analyse(null));
  assert.throws(() => analyse({ format: 'other' }));
  const r = analyse({ format: 'adamant-traffic', adapters: [null, 5, {}], tcp: [null, { state: 'Established', ra: 'x', pid: 1 }], dns: [null], procs: null, rate: null });
  assert.ok(Array.isArray(r.findings));
  assert.equal(r.speed.rx, 0);
});

test('traffic.ps1 только читает', () => {
  const WRITE = /\b(Set-\w+|New-ItemProperty|New-Item\b|Remove-\w+|Disable-\w+|Enable-\w+|Stop-\w+|Start-Service|Restart-\w+|Rename-\w+|Clear-\w+|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Resolve-DnsName|Test-Connection|Test-NetConnection|nslookup|ping\b|netsh\s+\S+\s+(set|add|delete)|Add-\w+)\b/i;
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'traffic.ps1'), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  const m = WRITE.exec(src);
  assert.equal(m, null, m && m[0]);
  assert.ok(!/key=clear/i.test(src), 'пароли Wi-Fi не читаются');
});
