'use strict';
/**
 * «Своя сеть»: поиск устройств и открытых служб ТОЛЬКО в частных подсетях этого компьютера.
 *  - Адреса: только 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 и только подсети своих адаптеров.
 *    Любой другой адрес отклоняется (isAllowedTarget) - это проверяют тесты.
 *  - Не больше 256 адресов на подсеть: широкая подсеть сужается до /24 вокруг своего адреса.
 *  - Только обычное TCP-подключение к короткому списку портов и заголовок веб-страницы на порту 80.
 *    Никаких атак, подбора паролей и эксплойтов.
 *  - Имена не ищутся через DNS: запрос к внешнему DNS-серверу раскрыл бы адреса вашей сети.
 */
const net = require('node:net');
const os = require('node:os');
const http = require('node:http');
const { tx, t } = require('./i18n');

const ipToInt = (ip) => ip.split('.').reduce((a, o) => (a * 256 + Number(o)) >>> 0, 0) >>> 0;
const intToIp = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function isPrivate(ip) {
  if (!IPV4.test(ip)) return false;
  const n = ipToInt(ip);
  const inNet = (base, bits) => (n >>> (32 - bits)) === (ipToInt(base) >>> (32 - bits));
  return inNet('10.0.0.0', 8) || inNet('172.16.0.0', 12) || inNet('192.168.0.0', 16);
}

function maskToPrefix(mask) {
  return ipToInt(mask).toString(2).replace(/0+$/, '').length;
}

const VIRTUAL_RE = /vpn|tap|tun|wireguard|wintun|virtualbox|vmware|hyper-v|vethernet|docker|wsl|tailscale|zerotier|amnezia|sing-tun|outline|openvpn|loopback|bluetooth/i;

/**
 * Подсети для проверки. adapters - из network.ps1 (alias, address, prefix, gateway, virtual, hardware, description),
 * без них - из os.networkInterfaces(). recommended: физический адаптер (не VPN и не виртуальная машина).
 */
function subnets(adapters) {
  let list = adapters;
  if (!Array.isArray(list) || !list.length) {
    list = [];
    for (const [alias, addrs] of Object.entries(os.networkInterfaces())) {
      for (const a of addrs || []) {
        if (a.family !== 'IPv4' && a.family !== 4) continue;
        if (a.internal) continue;
        list.push({ alias, address: a.address, prefix: maskToPrefix(a.netmask), description: '', virtual: VIRTUAL_RE.test(alias), hardware: !VIRTUAL_RE.test(alias) });
      }
    }
  }
  const out = [];
  for (const a of list) {
    if (!isPrivate(a.address)) continue;
    const prefix = Math.max(Number(a.prefix) || 24, 24);
    const base = prefix >= 32 ? ipToInt(a.address) : (ipToInt(a.address) & (~0 << (32 - prefix))) >>> 0;
    const size = 2 ** (32 - prefix);
    const first = size > 2 ? base + 1 : base;
    const last = size > 2 ? base + size - 2 : base + size - 1;
    const virtual = !!a.virtual || VIRTUAL_RE.test(`${a.alias} ${a.description || ''}`);
    out.push({
      id: `${intToIp(base)}/${prefix}`,
      alias: a.alias, description: a.description || '', address: a.address, gateway: a.gateway || null,
      prefix, realPrefix: Number(a.prefix) || prefix, first: intToIp(first), last: intToIp(last), count: last - first + 1,
      virtual, recommended: !virtual && (a.hardware !== false) && (a.status == null || a.status === 'Up'),
    });
  }
  // Одна подсеть может встретиться на двух адаптерах - оставляем первую.
  return out.filter((s, i) => out.findIndex((x) => x.id === s.id) === i);
}

function inSubnet(ip, s) {
  const n = ipToInt(ip);
  return n >= ipToInt(s.first) && n <= ipToInt(s.last);
}

/** Главная защита: адрес частный и лежит в одной из своих подсетей. */
function isAllowedTarget(ip, subs) {
  return isPrivate(ip) && Array.isArray(subs) && subs.some((s) => isPrivate(s.address) && inSubnet(ip, s));
}

function hostsOf(s) {
  const out = [];
  for (let n = ipToInt(s.first); n <= ipToInt(s.last) && out.length < 256; n++) {
    const ip = intToIp(n);
    if (ip !== s.address) out.push(ip);
  }
  return out;
}

/** TCP-подключение: open - порт принимает, closed - устройство ответило отказом, filtered - тишина. */
function probe(ip, port, timeout = 800) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: ip, port });
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(timeout, () => finish('filtered'));
    sock.once('connect', () => finish('open'));
    sock.once('error', (e) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
  });
}

/** Заголовок веб-страницы устройства (порт 80) - чтобы понять, что это за устройство. */
function httpInfo(ip, port = 80, timeout = 1500) {
  return new Promise((resolve) => {
    const req = http.get({ host: ip, port, path: '/', timeout, headers: { 'User-Agent': 'Adamant-LAN-check', Connection: 'close' } }, (res) => {
      let body = '';
      res.setEncoding('latin1');
      res.on('data', (c) => {
        body += c;
        if (body.length > 16384) res.destroy();
      });
      const end = () => {
        const m = /<title[^>]*>([^<]{1,120})<\/title>/i.exec(body);
        resolve({ status: res.statusCode, server: String(res.headers.server || '').slice(0, 80), title: m ? m[1].trim() : '' });
      };
      res.on('end', end);
      res.on('close', end);
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

const QUICK_PORTS = [80, 443, 445, 22, 139, 135, 53, 8080, 62078];
const PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB',
  554: 'RTSP', 631: 'IPP', 1433: 'SQL Server', 1883: 'MQTT', 3306: 'MySQL', 3389: 'RDP', 5000: 'HTTP 5000', 5001: 'HTTPS 5001',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8000: 'HTTP 8000', 8080: 'HTTP 8080', 8443: 'HTTPS 8443', 9100: 'JetDirect',
  27017: 'MongoDB', 62078: 'iPhone/iPad',
};
const FULL_PORTS = Object.keys(PORTS).map(Number);

async function pool(items, limit, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      await fn(items[k], k);
    }
  });
  await Promise.all(workers);
}

function guessKind(h, s) {
  const p = new Set(h.open);
  if (s && h.ip === s.gateway) return 'router';
  if (p.has(9100) || p.has(631)) return 'printer';
  if (p.has(554)) return 'camera';
  if (p.has(62078)) return 'phone';
  if ((p.has(5000) || p.has(5001)) && p.has(445)) return 'nas';
  if (p.has(3389) || p.has(135) || p.has(445)) return 'computer';
  return 'device';
}

/**
 * Проверка подсетей. options:
 *   subnets - все подсети (subnets()), selected - id выбранных;
 *   probe, httpInfo, neighbors - для тестов; onProgress(done, total).
 */
async function scan({ subnets: subs, selected, probe: pr = probe, httpInfo: hi = httpInfo, neighbors = async () => [], names = null, onProgress = () => {}, concurrency = 96 } = {}) {
  const chosen = (subs || []).filter((s) => (selected || []).includes(s.id));
  if (!chosen.length) throw new Error(t('Не выбрана ни одна подсеть'));
  for (const s of chosen) if (!isPrivate(s.address) || s.count > 256) throw new Error(tx('Подсеть {0} нельзя проверять', s.id));
  const started = new Date().toISOString();
  const hosts = new Map();
  const targets = chosen.flatMap((s) => hostsOf(s).map((ip) => ({ ip, s })));
  for (const x of targets) if (!isAllowedTarget(x.ip, chosen)) throw new Error(tx('Адрес {0} вне своей сети', x.ip));
  const host = (ip, s) => {
    if (!hosts.has(ip)) hosts.set(ip, { ip, subnet: s.id, open: [], alive: false, mac: '', via: [] });
    return hosts.get(ip);
  };
  // 1. Быстрый проход: кто вообще отвечает.
  const quick = targets.flatMap((x) => QUICK_PORTS.map((port) => ({ ...x, port })));
  const fullCount = () => [...hosts.values()].filter((h) => h.alive).length * (FULL_PORTS.length - QUICK_PORTS.length);
  let done = 0;
  await pool(quick, concurrency, async ({ ip, s, port }) => {
    const r = await pr(ip, port, 700);
    if (r !== 'filtered') {
      const h = host(ip, s);
      h.alive = true;
      if (r === 'open' && !h.open.includes(port)) h.open.push(port);
    }
    onProgress(++done, quick.length + fullCount());
  });
  // 2. Соседи из таблицы ARP (их нашёл первый проход) - устройства, которые не отвечают по TCP.
  let arp = [];
  try { arp = await neighbors(); } catch { arp = []; }
  for (const n of arp || []) {
    const s = chosen.find((x) => isAllowedTarget(n.ip, [x]));
    if (!s || n.ip === s.address) continue;
    const h = host(n.ip, s);
    h.alive = true;
    h.mac = n.mac || h.mac;
  }
  // 3. Полный список портов - только у найденных устройств.
  const rest = FULL_PORTS.filter((p) => !QUICK_PORTS.includes(p));
  const alive = [...hosts.values()].filter((h) => h.alive);
  const full = alive.flatMap((h) => rest.map((port) => ({ h, port })));
  const total = quick.length + full.length;
  await pool(full, concurrency, async ({ h, port }) => {
    if (!isAllowedTarget(h.ip, chosen)) return;
    if ((await pr(h.ip, port, 900)) === 'open' && !h.open.includes(port)) h.open.push(port);
    onProgress(++done, total);
  });
  // 4. Что за устройство: заголовок веб-страницы.
  await pool(alive.filter((h) => h.open.includes(80)), 8, async (h) => {
    h.http = await hi(h.ip, 80);
  });
  // 5. Имя устройства: спрашиваем у самого устройства (mDNS, NetBIOS) и у роутера этой сети - только свои адреса.
  if (typeof names === 'function') {
    for (const s of chosen) {
      const mine = alive.filter((h) => h.subnet === s.id).map((h) => h.ip);
      let got = null;
      try { got = await names(mine, { allowed: (ip) => isAllowedTarget(ip, [s]), gateway: s.gateway || null }); } catch { got = null; }
      if (!(got instanceof Map)) continue;
      for (const h of alive) {
        const n = got.get(h.ip);
        if (h.subnet === s.id && n && typeof n.name === 'string') { h.name = n.name.slice(0, 63); h.nameSource = String(n.source || '').slice(0, 10); }
      }
    }
  }
  const list = alive.map((h) => {
    const s = chosen.find((x) => x.id === h.subnet);
    h.open.sort((a, b) => a - b);
    return { ...h, gateway: !!(s && s.gateway === h.ip), kind: guessKind(h, s) };
  }).sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));
  return { started, finished: new Date().toISOString(), subnets: chosen.map((s) => s.id), hosts: list };
}

// ---------------------------------------------------------------- Находки по сети

const NET_ISSUES = [
  { ports: [23], id: 'lan-telnet', sev: 'critical', title: t('В сети открыт Telnet'), text: t('Telnet передаёт пароли открытым текстом. Через него чаще всего заражают роутеры и камеры.'), guide: 'device' },
  { ports: [21], id: 'lan-ftp', sev: 'high', title: t('В сети открыт FTP'), text: t('FTP передаёт пароли и файлы без шифрования.'), guide: 'device' },
  { ports: [5900], id: 'lan-vnc', sev: 'high', title: t('В сети открыт VNC (управление экраном)'), text: t('VNC даёт управление экраном. Часто его защищает только короткий пароль.'), guide: 'device' },
  { ports: [3306, 5432, 1433, 6379, 27017], id: 'lan-db', sev: 'high', title: t('В сети доступна база данных'), text: t('Базы данных не стоит открывать для всей сети: Redis и MongoDB по умолчанию работают без пароля.'), guide: 'device' },
  { ports: [3389], id: 'lan-rdp', sev: 'advice', title: t('В сети открыт удалённый рабочий стол'), text: t('К этим компьютерам можно подключиться по RDP. Если это не нужно, выключите его на них.'), guide: 'device' },
  { ports: [1883], id: 'lan-mqtt', sev: 'advice', title: t('В сети открыт MQTT (умный дом)'), text: t('MQTT часто работает без пароля: любой в сети может читать и отправлять команды умному дому.'), guide: 'device' },
  { ports: [554], id: 'lan-rtsp', sev: 'advice', title: t('В сети есть камера с видеопотоком RTSP'), text: t('Проверьте, что у камеры стоит свой пароль, а не заводской.'), guide: 'device' },
];

function networkFindings(result) {
  if (!result || !Array.isArray(result.hosts)) return [];
  const out = [];
  for (const issue of NET_ISSUES) {
    const hit = result.hosts.filter((h) => h.open.some((p) => issue.ports.includes(p)));
    if (!hit.length) continue;
    out.push({
      id: issue.id, cat: 'network', sev: issue.sev, title: issue.title, text: issue.text, guide: issue.guide,
      evidence: hit.map((h) => tx('{0}: порт {1}', h.ip, h.open.filter((p) => issue.ports.includes(p)).join(', '))),
    });
  }
  const gw = result.hosts.find((h) => h.gateway);
  if (gw && gw.open.includes(80) && !gw.open.includes(443)) {
    out.push({
      id: 'lan-router-http', cat: 'network', sev: 'advice', guide: 'router',
      title: t('Настройки роутера открываются без шифрования'),
      text: t('Страница настроек роутера работает по HTTP: пароль администратора передаётся по сети открытым текстом. Включите HTTPS, если роутер это умеет, и смените стандартный пароль.'),
      evidence: [tx('Роутер {0}: порт 80 открыт, 443 закрыт', gw.ip), gw.http && gw.http.title ? tx('Страница: «{0}»', gw.http.title) : null].filter(Boolean),
    });
  }
  if (!out.length) {
    out.push({ id: 'lan-ok', cat: 'network', sev: 'ok', title: t('Опасных служб в сети не найдено'), text: tx('Найдено устройств: {0}.', result.hosts.length), evidence: [] });
  }
  return out;
}

module.exports = { scan, subnets, isAllowedTarget, isPrivate, hostsOf, probe, networkFindings, ipToInt, intToIp, PORTS, FULL_PORTS, QUICK_PORTS };
