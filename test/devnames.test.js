'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const devnames = require('../server/devnames');
const netscan = require('../server/netscan');
const traffic = require('../server/traffic');

const { ptrQuery, nbstatQuery, parsePtr, parseNbstat, cleanName, lookup } = devnames;

function encode(name) {
  return Buffer.concat([...name.split('.').map((l) => Buffer.concat([Buffer.from([Buffer.byteLength(l)]), Buffer.from(l)])), Buffer.from([0])]);
}

/** Ответ DNS на наш вопрос: вопрос + одна запись PTR (имя ответа - ссылка на вопрос). */
function ptrAnswer(query, host, { id, rcode = 0 } = {}) {
  const q = query.subarray(12);
  const hdr = Buffer.from(query.subarray(0, 12));
  if (id != null) hdr.writeUInt16BE(id, 0);
  hdr.writeUInt16BE(0x8400 | rcode, 2);
  hdr.writeUInt16BE(1, 6);
  const rdata = encode(host);
  const rr = Buffer.alloc(12);
  rr.writeUInt16BE(0xc00c, 0);
  rr.writeUInt16BE(12, 2);
  rr.writeUInt16BE(1, 4);
  rr.writeUInt32BE(120, 6);
  rr.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([hdr, q, rr, rdata]);
}

/** Ответ NetBIOS NBSTAT со списком имён [имя, код, группа]. */
function nbAnswer(id, names) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(id, 0);
  hdr.writeUInt16BE(0x8400, 2);
  hdr.writeUInt16BE(1, 6);
  const qname = nbstatQuery(id).subarray(12, 12 + 34);
  const list = Buffer.concat(names.map(([n, code, group]) => {
    const b = Buffer.alloc(18, 0x20);
    Buffer.from(n, 'latin1').copy(b, 0, 0, 15);
    b[15] = code;
    b.writeUInt16BE(group ? 0x8400 : 0x0400, 16);
    return b;
  }));
  const rr = Buffer.alloc(10);
  rr.writeUInt16BE(0x21, 0);
  rr.writeUInt16BE(1, 2);
  rr.writeUInt16BE(1 + list.length, 8);
  return Buffer.concat([hdr, qname, rr, Buffer.from([names.length]), list, Buffer.alloc(46)]);
}

test('имена: вопрос PTR и разбор ответа mDNS и роутера', () => {
  const q = ptrQuery('192.168.1.50', 0x1234);
  assert.equal(q.readUInt16BE(0), 0x1234);
  assert.ok(q.includes(Buffer.from('in-addr')));
  assert.equal(parsePtr(ptrAnswer(q, 'DESKTOP-228SSGE.local'), 0x1234), 'DESKTOP-228SSGE');
  assert.equal(parsePtr(ptrAnswer(q, 'android-1f2e.lan'), 0x1234), 'android-1f2e');
  // mDNS может ответить с номером 0 - принимаем только там, где это разрешено.
  assert.equal(parsePtr(ptrAnswer(q, 'iPhone.local', { id: 0 }), 0x1234, { allowZeroId: true }), 'iPhone');
  assert.equal(parsePtr(ptrAnswer(q, 'iPhone.local', { id: 0 }), 0x1234), null);
  assert.equal(parsePtr(ptrAnswer(q, 'x.local', { id: 0x9999 }), 0x1234), null, 'чужой номер запроса');
  assert.equal(parsePtr(ptrAnswer(q, 'x.local', { rcode: 3 }), 0x1234), null, 'ошибка - не имя');
  assert.equal(parsePtr(q, 0x1234), null, 'вопрос - не ответ');
  // Испорченные пакеты и петли сжатия не роняют разбор.
  const loop = ptrAnswer(q, 'a.local');
  loop.writeUInt16BE(0xc000 | (loop.length - 4), loop.length - 4);
  assert.doesNotThrow(() => parsePtr(loop, 0x1234));
  for (let n = 0; n < loop.length; n++) assert.doesNotThrow(() => parsePtr(loop.subarray(0, n), 0x1234));
  assert.equal(parsePtr(null, 1), null);
});

test('имена: NetBIOS - имя компьютера, а не рабочей группы', () => {
  const q = nbstatQuery(0x0101);
  assert.equal(q.length, 50);
  assert.equal(q.readUInt16BE(q.length - 4), 0x21);
  const a = nbAnswer(0x0101, [['WORKGROUP', 0x00, true], ['NAS-HOME', 0x00, false], ['NAS-HOME', 0x20, false]]);
  assert.equal(parseNbstat(a, 0x0101), 'NAS-HOME');
  assert.equal(parseNbstat(nbAnswer(0x0101, [['WORKGROUP', 0x00, true]]), 0x0101), null);
  assert.equal(parseNbstat(a, 0x0202), null, 'чужой номер запроса');
  for (let n = 0; n < a.length; n++) assert.doesNotThrow(() => parseNbstat(a.subarray(0, n), 0x0101));
});

test('имена: очистка - без «.local», управляющих символов и адресов вместо имени', () => {
  assert.equal(cleanName('MacBook-Air.local.'), 'MacBook-Air');
  assert.equal(cleanName('tv\u0007box.home'), 'tvbox');
  assert.equal(cleanName('192.168.1.5'), null);
  assert.equal(cleanName('5.1.168.192.in-addr.arpa'), null);
  assert.equal(cleanName(''), null);
  assert.equal(cleanName('x'.repeat(200)).length, 63);
});

test('имена: только свои адреса, сначала само устройство, роутер - пока отвечает', async () => {
  const asked = [];
  const ask = async (ip, port, packet) => {
    asked.push(`${ip}:${port}`);
    const id = packet.readUInt16BE(0);
    if (port === 5353 && ip === '192.168.1.50') return ptrAnswer(packet, 'DESKTOP-228SSGE.local');
    if (port === 137 && ip === '192.168.1.60') return nbAnswer(id, [['NAS', 0x20, false]]);
    if (port === 137 && ip === '192.168.1.50') return nbAnswer(id, [['OTHER', 0x20, false]]);
    if (port === 53 && ip === '192.168.1.1') {
      const s = packet.toString('latin1');
      return s.includes('\x0270') ? ptrAnswer(packet, 'galaxy-s24.lan') : null;
    }
    return null;
  };
  const allowed = (ip) => /^192\.168\.1\.\d+$/.test(ip);
  const r = await lookup(['192.168.1.50', '192.168.1.60', '192.168.1.70', '8.8.8.8', '192.168.1.50'], { allowed, gateway: '192.168.1.1', ask });
  assert.deepEqual(r.get('192.168.1.50'), { name: 'DESKTOP-228SSGE', source: 'mdns' });
  assert.deepEqual(r.get('192.168.1.60'), { name: 'NAS', source: 'netbios' });
  assert.deepEqual(r.get('192.168.1.70'), { name: 'galaxy-s24', source: 'router' });
  assert.ok(!asked.some((a) => a.startsWith('8.8.8.8')), 'чужие адреса не спрашиваем');
  assert.equal(asked.filter((a) => a === '192.168.1.50:5353').length, 1, 'повторы убраны');

  // Роутер вне своей сети - не спрашиваем; молчащего роутера после трёх тишин не спрашиваем.
  const asked2 = [];
  const silent = async (ip, port) => { asked2.push(`${ip}:${port}`); return null; };
  const ips = Array.from({ length: 10 }, (_, i) => `192.168.1.${100 + i}`);
  await lookup(ips, { allowed, gateway: '10.0.0.1', ask: silent });
  assert.ok(!asked2.some((a) => a.endsWith(':53')));
  asked2.length = 0;
  await lookup(ips, { allowed, gateway: '192.168.1.1', ask: silent });
  assert.equal(asked2.filter((a) => a === '192.168.1.1:53').length, 3, 'молчащий роутер - не больше трёх вопросов');
  await assert.rejects(lookup(ips, { ask: silent }));
});

test('имена: ответ принимается только с того адреса и порта, куда ушёл вопрос', async () => {
  const server = dgram.createSocket('udp4');
  const other = dgram.createSocket('udp4');
  await new Promise((r) => server.bind(0, '127.0.0.1', r));
  await new Promise((r) => other.bind(0, '127.0.0.1', r));
  const port = server.address().port;
  let mode = 'other';
  server.on('message', (msg, rinfo) => {
    const reply = ptrAnswer(msg, 'box.local');
    if (mode === 'other') other.send(reply, rinfo.port, rinfo.address);
    else server.send(reply, rinfo.port, rinfo.address);
  });
  try {
    const ask = (ip, p, packet, timeout) => {
      // тот же ask, что в модуле, но через его экспорт - проверяем поведение сокета
      return require('../server/devnames').__ask(ip, p, packet, timeout);
    };
    const q = ptrQuery('192.168.1.5', 7);
    assert.equal(await ask('127.0.0.1', port, q, 400), null, 'ответ с чужого порта отброшен');
    mode = 'self';
    const b = await ask('127.0.0.1', port, q, 1000);
    assert.equal(parsePtr(b, 7), 'box');
  } finally {
    server.close();
    other.close();
  }
});

test('поиск устройств: имена попадают в результат, вопросы - только своей подсети', async () => {
  const subs = [{ id: '192.168.1.0/24', alias: 'Wi-Fi', address: '192.168.1.36', prefix: 24, gateway: '192.168.1.1', count: 254, first: '192.168.1.1', last: '192.168.1.254', network: '192.168.1.0', broadcast: '192.168.1.255' }];
  const probe = async (ip, port) => (['192.168.1.1', '192.168.1.50'].includes(ip) && port === 80 ? 'open' : 'filtered');
  let seen = null;
  const names = async (ips, { allowed, gateway }) => {
    seen = { ips, gateway, outside: allowed('10.0.0.5') };
    return new Map([['192.168.1.50', { name: 'DESKTOP-228SSGE', source: 'mdns' }]]);
  };
  const r = await netscan.scan({ subnets: subs, selected: ['192.168.1.0/24'], probe, httpInfo: async () => null, names });
  assert.deepEqual(seen.ips.sort(), ['192.168.1.1', '192.168.1.50']);
  assert.equal(seen.gateway, '192.168.1.1');
  assert.equal(seen.outside, false);
  const h = r.hosts.find((x) => x.ip === '192.168.1.50');
  assert.equal(h.name, 'DESKTOP-228SSGE');
  assert.equal(h.nameSource, 'mdns');
  // Ошибка в поиске имён не ломает проверку сети.
  const r2 = await netscan.scan({ subnets: subs, selected: ['192.168.1.0/24'], probe, httpInfo: async () => null, names: async () => { throw new Error('x'); } });
  assert.equal(r2.hosts.length, 2);
});

test('кто в сети: имя из подписи, из кэша DNS (PTR) и запомненное', () => {
  const raw = {
    format: 'adamant-traffic', at: '2026-11-18T12:00:00.000Z',
    adapters: [{ alias: 'Ethernet', description: 'Realtek', ifIndex: 5, status: 'Up', media: '802.3', ipv4: ['192.168.1.36'], gateway: '192.168.1.1', category: 'Private' }],
    dns: [{ name: '40.1.168.192.in-addr.arpa', ip: 'printer.lan' }, { name: 'nas.local', ip: '192.168.1.41' }],
  };
  const neighbors = [
    { ip: '192.168.1.1', mac: '50-FF-20-A1-89-C8', ifIndex: 5 },
    { ip: '192.168.1.40', mac: 'f8:b5:4d:53:75:af', ifIndex: 5 },
    { ip: '192.168.1.41', mac: '30-C5-99-5F-2B-99', ifIndex: 5 },
    { ip: '192.168.1.50', mac: '74-56-3C-F6-57-CB', ifIndex: 5 },
    { ip: '192.168.1.60', mac: '7A-E4-09-79-9F-22', ifIndex: 5 },
  ];
  const saved = {
    '50-FF-20-A1-89-C8': { label: 'Роутер' },
    '74-56-3C-F6-57-CB': { name: 'DESKTOP-228SSGE.local', nameSource: 'mdns' },
  };
  const r = traffic.analyse(raw, { neighbors, known: new Set(Object.keys(saved)), saved });
  const by = Object.fromEntries(r.devices.map((d) => [d.ip, d]));
  assert.equal(by['192.168.1.1'].label, 'Роутер');
  assert.deepEqual([by['192.168.1.40'].name, by['192.168.1.40'].nameSource], ['printer', 'dns']);
  assert.deepEqual([by['192.168.1.41'].name, by['192.168.1.41'].nameSource], ['nas', 'dns']);
  assert.deepEqual([by['192.168.1.50'].name, by['192.168.1.50'].nameSource], ['DESKTOP-228SSGE', 'mdns']);
  assert.equal(by['192.168.1.60'].name, null);
  assert.equal(by['192.168.1.60'].label, null);
  assert.equal(by['192.168.1.60'].isNew, true);
});
