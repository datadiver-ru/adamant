'use strict';
/**
 * Имена устройств своей сети. Только при «Найти устройства» и только у адресов, которые уже прошли проверку
 * «своя частная сеть» (netscan.isAllowedTarget). Три вопроса, каждый - одним пакетом UDP:
 *  - mDNS (порт 5353 самого устройства): «как тебя зовут?» - отвечают компьютеры, Mac и iPhone, принтеры, ТВ-приставки;
 *  - NetBIOS (порт 137 самого устройства): имя компьютера Windows или сетевого хранилища;
 *  - роутер (порт 53 шлюза своей сети): имя, под которым устройство взяло адрес у роутера.
 * Ответ принимается только с того адреса и порта, куда ушёл вопрос, и с тем же номером запроса.
 * В интернет вопросы не уходят: других адресов здесь нет.
 */
const dgram = require('node:dgram');

const LOCAL_SUFFIX = /\.(local|lan|home|localdomain|home\.arpa|internal|router|domain)\.?$/i;

/** Имя для показа: без «.local», без управляющих символов, не длиннее 63 знаков. */
function cleanName(s) {
  let n = String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, '').trim().replace(/\.$/, '');
  n = n.replace(LOCAL_SUFFIX, '');
  if (!n || /\.in-addr\.arpa$/i.test(n) || /^\d+(\.\d+){3}$/.test(n)) return null;
  return n.slice(0, 63);
}

function reverseName(ip) {
  return String(ip).split('.').reverse().join('.') + '.in-addr.arpa';
}

function encodeName(name) {
  const parts = name.split('.').filter(Boolean).map((l) => {
    const b = Buffer.from(l, 'ascii');
    return Buffer.concat([Buffer.from([b.length]), b]);
  });
  return Buffer.concat([...parts, Buffer.from([0])]);
}

/** Вопрос DNS/mDNS: запись PTR для адреса (обратное имя). */
function ptrQuery(ip, id) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(id & 0xffff, 0);
  hdr.writeUInt16BE(0x0100, 2); // RD: для роутера - «поищи у себя»; mDNS этот флаг не смотрит
  hdr.writeUInt16BE(1, 4);
  return Buffer.concat([hdr, encodeName(reverseName(ip)), Buffer.from([0, 12, 0, 1])]);
}

/** Вопрос NetBIOS «покажи свои имена» (NBSTAT) - как nbtstat -A. */
function nbstatQuery(id) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(id & 0xffff, 0);
  hdr.writeUInt16BE(1, 4);
  const raw = Buffer.alloc(16);
  raw[0] = 0x2a; // «*»
  const enc = Buffer.alloc(32);
  for (let i = 0; i < 16; i++) {
    enc[i * 2] = 0x41 + (raw[i] >> 4);
    enc[i * 2 + 1] = 0x41 + (raw[i] & 0x0f);
  }
  return Buffer.concat([hdr, Buffer.from([0x20]), enc, Buffer.from([0, 0, 0x21, 0, 1])]);
}

/** Имя из пакета DNS (с поддержкой сжатия). → { name, off } или null при ошибке. */
function readName(buf, off) {
  const parts = [];
  let end = null;
  let jumps = 0;
  for (;;) {
    if (off >= buf.length) return null;
    const len = buf[off];
    if (len === 0) { off += 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length || ++jumps > 16) return null;
      if (end === null) end = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      continue;
    }
    if ((len & 0xc0) !== 0 || off + 1 + len > buf.length) return null;
    parts.push(buf.toString('utf8', off + 1, off + 1 + len));
    off += 1 + len;
    if (parts.length > 64) return null;
  }
  return { name: parts.join('.'), off: end === null ? off : end };
}

/** Ответ DNS/mDNS → первое имя из записи PTR (или null). id - номер нашего вопроса; mDNS может вернуть 0. */
function parsePtr(buf, id, { allowZeroId = false } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length < 12 || buf.length > 9000) return null;
  const rid = buf.readUInt16BE(0);
  if (rid !== (id & 0xffff) && !(allowZeroId && rid === 0)) return null;
  const flags = buf.readUInt16BE(2);
  if (!(flags & 0x8000) || (flags & 0x000f) !== 0) return null;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const n = readName(buf, off);
    if (!n) return null;
    off = n.off + 4;
  }
  for (let i = 0; i < an && i < 32; i++) {
    const n = readName(buf, off);
    if (!n || n.off + 10 > buf.length) return null;
    const type = buf.readUInt16BE(n.off);
    const rdl = buf.readUInt16BE(n.off + 8);
    off = n.off + 10;
    if (off + rdl > buf.length) return null;
    if (type === 12) {
      const v = readName(buf, off);
      const name = v && cleanName(v.name);
      if (name) return name;
    }
    off += rdl;
  }
  return null;
}

const OEM = (() => { try { return new TextDecoder('ibm866'); } catch { return null; } })();

/** Ответ NetBIOS NBSTAT → имя компьютера (уникальное имя с кодом 00 или 20) или null. */
function parseNbstat(buf, id) {
  if (!Buffer.isBuffer(buf) || buf.length < 57 || buf.length > 9000) return null;
  if (buf.readUInt16BE(0) !== (id & 0xffff)) return null;
  const flags = buf.readUInt16BE(2);
  if (!(flags & 0x8000) || (flags & 0x000f) !== 0) return null;
  if (buf.readUInt16BE(6) < 1) return null;
  const n = readName(buf, 12);
  if (!n || n.off + 11 > buf.length) return null;
  if (buf.readUInt16BE(n.off) !== 0x21) return null;
  let off = n.off + 10;
  const count = buf[off];
  off += 1;
  let best = null;
  for (let i = 0; i < count && off + 18 <= buf.length; i++, off += 18) {
    const raw = buf.subarray(off, off + 15);
    const suffix = buf[off + 15];
    const group = (buf.readUInt16BE(off + 16) & 0x8000) !== 0;
    if (group || (suffix !== 0x00 && suffix !== 0x20)) continue;
    const text = (raw.some((b) => b >= 0x80) && OEM ? OEM.decode(raw) : raw.toString('latin1')).replace(/[\u0000 ]+$/, '');
    const name = cleanName(text);
    if (!name) continue;
    if (suffix === 0x20) return name;
    if (!best) best = name;
  }
  return best;
}

/** Один вопрос по UDP: ответ принимается только с ip:port. → Buffer или null по таймауту. */
function ask(ip, port, packet, timeout) {
  return new Promise((resolve) => {
    let done = false;
    const sock = dgram.createSocket('udp4');
    const finish = (v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch { /* уже закрыт */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish(null), timeout);
    sock.on('error', () => finish(null));
    sock.on('message', (msg, rinfo) => {
      if (rinfo.address === ip && rinfo.port === port) finish(msg);
    });
    sock.send(packet, port, ip, (err) => { if (err) finish(null); });
  });
}

async function pool(items, limit, fn) {
  let i = 0;
  const work = async () => { while (i < items.length) { const x = items[i++]; await fn(x); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, work));
}

/**
 * Имена для списка адресов. allowed(ip) - проверка «своя сеть» (обязательна); gateway - роутер этой сети или null.
 * → Map ip → { name, source: 'mdns' | 'netbios' | 'router' }
 */
async function lookup(ips, { allowed, gateway = null, timeout = 1500, ask: askFn = ask } = {}) {
  if (typeof allowed !== 'function') throw new Error('allowed');
  const out = new Map();
  const list = [...new Set(ips)].filter((ip) => allowed(ip)).slice(0, 256);
  const router = gateway && allowed(gateway) ? gateway : null;
  let seq = Math.floor(Math.random() * 0xffff);
  await pool(list, 16, async (ip) => {
    const id1 = (seq = (seq + 1) & 0xffff);
    const id2 = (seq = (seq + 1) & 0xffff);
    const [m, nb] = await Promise.all([
      askFn(ip, 5353, ptrQuery(ip, id1), timeout).then((b) => parsePtr(b, id1, { allowZeroId: true })),
      askFn(ip, 137, nbstatQuery(id2), timeout).then((b) => parseNbstat(b, id2)),
    ]);
    if (m) out.set(ip, { name: m, source: 'mdns' });
    else if (nb) out.set(ip, { name: nb, source: 'netbios' });
  });
  // Роутер - по очереди и только про тех, кто не назвался сам. Трижды промолчал - больше не спрашиваем
  // (не отвечает на такие вопросы или их перехватывает VPN).
  if (router) {
    let silent = 0;
    for (const ip of list) {
      if (out.has(ip) || silent >= 3) continue;
      const id = (seq = (seq + 1) & 0xffff);
      const b = await askFn(router, 53, ptrQuery(ip, id), timeout);
      if (!b) { silent++; continue; }
      silent = 0;
      const r = parsePtr(b, id);
      if (r) out.set(ip, { name: r, source: 'router' });
    }
  }
  return out;
}

module.exports = { lookup, cleanName, ptrQuery, nbstatQuery, parsePtr, parseNbstat, reverseName, __ask: ask };
