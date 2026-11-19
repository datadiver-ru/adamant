'use strict';
/**
 * Роутер: какие порты он открыл в интернет по UPnP (IGD). Только чтение и только внутри своей сети:
 *  - поиск роутера - SSDP (M-SEARCH на 239.255.255.250:1900) с адресов своих адаптеров в частных сетях;
 *  - описание роутера и список пробросов портов (GetGenericPortMappingEntry) - обычные запросы UPnP
 *    к самому роутеру. Адрес описания должен быть частным и совпадать с адресом, с которого пришёл ответ.
 * Ничего не открывает и не закрывает: AddPortMapping/DeletePortMapping программа не вызывает.
 */
const dgram = require('node:dgram');
const http = require('node:http');
const os = require('node:os');
const { tx, t } = require('./i18n');
const { isPrivate, ipToInt } = require('./netscan');

const SSDP = { address: '239.255.255.250', port: 1900 };
const TARGETS = ['urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'urn:schemas-upnp-org:device:InternetGatewayDevice:2', 'urn:schemas-upnp-org:service:WANIPConnection:1'];
const SERVICES = ['urn:schemas-upnp-org:service:WANIPConnection:2', 'urn:schemas-upnp-org:service:WANIPConnection:1', 'urn:schemas-upnp-org:service:WANPPPConnection:1'];
const MAX_BYTES = 256 * 1024;
const MAX_MAPPINGS = 128;

/** Свои адреса IPv4 в частных сетях (физические адаптеры и VPN - роутер ответит только там, где он есть). */
function localAddresses(ifaces = os.networkInterfaces()) {
  const out = [];
  for (const list of Object.values(ifaces || {})) for (const a of list || []) if ((a.family === 'IPv4' || a.family === 4) && !a.internal && isPrivate(a.address)) out.push(a.address);
  return [...new Set(out)];
}

/** Заголовок LOCATION из ответа SSDP, если ответ про роутер и адрес описания - тот же частный адрес. */
function parseSsdp(text, from) {
  const head = {};
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^([A-Za-z-]+):\s*(.*)$/.exec(line.trim());
    if (m) head[m[1].toLowerCase()] = m[2].trim();
  }
  const st = head.st || head.nt || '';
  if (!/InternetGatewayDevice|WAN(IP|PPP)Connection/i.test(st)) return null;
  let u;
  try { u = new URL(head.location); } catch { return null; }
  if (u.protocol !== 'http:' || !isPrivate(u.hostname) || u.hostname !== from) return null;
  return { location: u.href, server: String(head.server || '').slice(0, 120) };
}

function discover({ timeout = 2500, addresses = localAddresses(), createSocket = dgram.createSocket } = {}) {
  return new Promise((resolve) => {
    const found = new Map();
    const sockets = [];
    const msg = (st) => Buffer.from(`M-SEARCH * HTTP/1.1\r\nHOST: ${SSDP.address}:${SSDP.port}\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ${st}\r\n\r\n`);
    for (const addr of addresses) {
      let s;
      try { s = createSocket({ type: 'udp4', reuseAddr: true }); } catch { continue; }
      sockets.push(s);
      s.on('error', () => { try { s.close(); } catch { /* ignore */ } });
      s.on('message', (buf, rinfo) => {
        if (buf.length > 4096) return;
        const r = parseSsdp(buf.toString('latin1'), rinfo.address);
        if (r && !found.has(r.location)) found.set(r.location, { ...r, via: addr });
      });
      s.bind({ address: addr, port: 0 }, () => {
        try { s.setMulticastTTL(2); s.setMulticastInterface(addr); } catch { /* ignore */ }
        for (const st of TARGETS) s.send(msg(st), SSDP.port, SSDP.address, () => {});
      });
    }
    setTimeout(() => {
      for (const s of sockets) { try { s.close(); } catch { /* ignore */ } }
      resolve([...found.values()]);
    }, timeout);
  });
}

function request(url, { method = 'GET', headers = {}, body = null, timeout = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error('bad url')); }
    if (u.protocol !== 'http:' || !isPrivate(u.hostname)) return reject(new Error('not private'));
    const req = http.request({ host: u.hostname, port: u.port || 80, path: u.pathname + u.search, method, headers: { ...headers, ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) }, timeout }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => { size += c.length; if (size > MAX_BYTES) req.destroy(new Error('too large')); else chunks.push(c); });
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const unxml = (s) => String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&').trim();
function tag(xml, name) {
  const m = new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${name}>`, 'i').exec(String(xml));
  return m ? unxml(m[1]) : null;
}

/** Описание роутера: имя, модель и адрес управления службой подключения к интернету. */
function parseDescription(xml, location) {
  const base = tag(xml, 'URLBase') || location;
  const services = [];
  const re = /<(?:\w+:)?service\b[^>]*>([\s\S]*?)<\/(?:\w+:)?service>/gi;
  let m;
  while ((m = re.exec(xml))) {
    const type = tag(m[1], 'serviceType');
    const ctl = tag(m[1], 'controlURL');
    if (type && ctl) services.push({ type, control: ctl });
  }
  const svc = SERVICES.map((s) => services.find((x) => x.type === s)).find(Boolean);
  let control = null;
  if (svc) {
    try {
      const u = new URL(svc.control, base);
      // Управление - только на том же роутере.
      if (u.protocol === 'http:' && u.hostname === new URL(location).hostname) control = u.href;
    } catch { control = null; }
  }
  return {
    name: tag(xml, 'friendlyName'), manufacturer: tag(xml, 'manufacturer'), model: [tag(xml, 'modelName'), tag(xml, 'modelNumber')].filter(Boolean).join(' ') || null,
    service: svc ? svc.type : null, control,
  };
}

async function soap(control, service, action, args = {}) {
  const inner = Object.entries(args).map(([k, v]) => `<${k}>${String(v)}</${k}>`).join('');
  const body = `<?xml version="1.0"?>\r\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:${action} xmlns:u="${service}">${inner}</u:${action}></s:Body></s:Envelope>`;
  const r = await request(control, { method: 'POST', body, headers: { 'Content-Type': 'text/xml; charset="utf-8"', SOAPAction: `"${service}#${action}"` } });
  if (r.status !== 200) {
    const e = new Error(`UPnP ${action}: ${tag(r.text, 'errorDescription') || r.status}`);
    e.upnp = Number(tag(r.text, 'errorCode')) || r.status;
    throw e;
  }
  return r.text;
}

/** Всё о роутере: найден ли UPnP, внешний адрес и пробросы портов. */
async function inspect({ discoverFn = discover, requestFn = request, soapFn = soap } = {}) {
  const found = await discoverFn();
  if (!found.length) return { found: false };
  let lastErr = null;
  for (const dev of found) {
    try {
      const d = await requestFn(dev.location);
      if (d.status !== 200) throw new Error(`HTTP ${d.status}`);
      const desc = parseDescription(d.text, dev.location);
      const out = { found: true, host: new URL(dev.location).hostname, via: dev.via, name: desc.name, manufacturer: desc.manufacturer, model: desc.model, service: desc.service, externalIp: null, mappings: [], readable: false };
      if (!desc.control) return out;
      try { out.externalIp = tag(await soapFn(desc.control, desc.service, 'GetExternalIPAddress'), 'NewExternalIPAddress'); } catch { /* не у всех роутеров */ }
      for (let i = 0; i < MAX_MAPPINGS; i += 1) {
        let x;
        try { x = await soapFn(desc.control, desc.service, 'GetGenericPortMappingEntry', { NewPortMappingIndex: i }); } catch (e) {
          if (i === 0 && e.upnp !== 713 && e.upnp !== 714) out.error = e.message;
          break;
        }
        out.readable = true;
        out.mappings.push({
          proto: String(tag(x, 'NewProtocol') || '').toUpperCase(), external: Number(tag(x, 'NewExternalPort')) || null,
          client: tag(x, 'NewInternalClient'), internal: Number(tag(x, 'NewInternalPort')) || null,
          enabled: tag(x, 'NewEnabled') !== '0', description: String(tag(x, 'NewPortMappingDescription') || '').slice(0, 80),
          remote: tag(x, 'NewRemoteHost') || null, lease: Number(tag(x, 'NewLeaseDuration')) || 0,
        });
      }
      if (out.error == null && out.mappings.length === 0) out.readable = true;
      return out;
    } catch (e) { lastErr = e; }
  }
  return { found: true, error: lastErr ? lastErr.message : 'error', mappings: [] };
}

/** Порты, которые опасно открывать в интернет. */
const DANGER = {
  3389: { name: 'RDP', sev: 'critical' }, 445: { name: 'SMB', sev: 'critical' }, 139: { name: 'NetBIOS', sev: 'critical' }, 5900: { name: 'VNC', sev: 'critical' }, 23: { name: 'Telnet', sev: 'critical' },
  22: { name: 'SSH', sev: 'high' }, 21: { name: 'FTP', sev: 'high' }, 3306: { name: 'MySQL', sev: 'high' }, 1433: { name: 'SQL Server', sev: 'high' }, 5432: { name: 'PostgreSQL', sev: 'high' },
  6379: { name: 'Redis', sev: 'high' }, 27017: { name: 'MongoDB', sev: 'high' }, 5985: { name: 'WinRM', sev: 'high' }, 5986: { name: 'WinRM', sev: 'high' }, 8080: { name: 'HTTP', sev: 'advice' },
};

function grayAddress(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(String(ip || ''))) return false;
  const n = ipToInt(ip);
  const cgnat = (n >>> 22) === (ipToInt('100.64.0.0') >>> 22);
  return cgnat || isPrivate(ip);
}

/**
 * Находки по роутеру. own - адреса этого компьютера, listen - слушающие порты из проверки ({ port, proto, proc }).
 */
function findings(res, { own = [], listen = [] } = {}) {
  if (!res) return [];
  if (!res.found) {
    return [{ id: 'router-upnp-off', cat: 'network', sev: 'ok', title: t('UPnP на роутере выключен или не отвечает'), text: t('Программы в вашей сети не могут сами открыть порт в интернет через роутер.'), evidence: [] }];
  }
  const who = [res.manufacturer, res.model || res.name].filter(Boolean).join(' ') || res.host || t('роутер');
  const ev0 = [tx('Роутер: {0}{1}', who, res.host ? ` (${res.host})` : '')];
  if (res.externalIp) ev0.push(grayAddress(res.externalIp) ? tx('Внешний адрес {0} - «серый»: из интернета к роутеру, скорее всего, не подключиться', res.externalIp) : tx('Внешний адрес: {0}', res.externalIp));
  if (!res.readable) {
    return [{ id: 'router-upnp-on', cat: 'network', sev: 'advice', title: t('UPnP на роутере включён'), text: t('Любая программа в вашей сети может сама открыть порт в интернет - так делают и вирусы. Список открытых портов роутер не показал. Если не нужны игры по сети, торренты и удалённый доступ, выключите UPnP в настройках роутера.'), evidence: [...ev0, ...(res.error ? [tx('Ответ роутера: {0}', res.error)] : [])], guide: 'router-upnp' }];
  }
  const maps = (res.mappings || []).filter((m) => m.enabled !== false);
  if (!maps.length) {
    return [{ id: 'router-upnp-on', cat: 'network', sev: 'advice', title: t('UPnP на роутере включён, открытых портов нет'), text: t('Сейчас наружу ничего не открыто, но любая программа в вашей сети может сама открыть порт в интернет - так делают и вирусы. Если не нужны игры по сети, торренты и удалённый доступ, выключите UPnP в настройках роутера.'), evidence: ev0, guide: 'router-upnp' }];
  }
  const ownSet = new Set(own);
  let sev = 'advice';
  const order = ['advice', 'high', 'critical'];
  const ev = maps.map((m) => {
    const d = DANGER[m.internal] || DANGER[m.external];
    if (d && order.indexOf(d.sev) > order.indexOf(sev)) sev = d.sev;
    const mine = ownSet.has(m.client);
    const l = mine ? listen.find((x) => Number(x.port) === m.internal && String(x.proto || '').toUpperCase() === m.proto) : null;
    const where = mine ? (l && l.proc ? tx('этот компьютер, {0}', l.proc) : t('этот компьютер')) : m.client || '?';
    return tx('{0} {1} → {2}:{3} ({4}){5}{6}', m.proto, m.external, m.client || '?', m.internal, where, m.description ? ` - ${m.description}` : '', d ? tx(' - {0} нельзя открывать в интернет', d.name) : '');
  });
  return [{
    id: 'router-upnp-ports', cat: 'network', sev,
    title: tx('Роутер открыл порты в интернет: {0}', maps.length),
    text: sev === 'critical'
      ? t('Через открытый порт к устройству в вашей сети может подключиться любой в интернете. Удалённый рабочий стол, общие папки и VNC - главные цели взлома. Закройте этот проброс и выключите программу, которая его открыла.')
      : t('Эти порты программы открыли сами через UPnP: обычно это игры, торренты и программы удалённого доступа. Если программа вам незнакома или порт больше не нужен, закройте её и выключите UPnP в настройках роутера.'),
    evidence: [...ev0, ...ev], guide: 'router-upnp',
  }];
}

module.exports = { discover, inspect, findings, parseSsdp, parseDescription, localAddresses, grayAddress, tag, DANGER };
