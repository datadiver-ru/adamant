'use strict';
const { cleanName } = require('./devnames');
/**
 * «Сеть и трафик»: разбор ответа server/ps/traffic.ps1 (только чтение, без запросов в сеть).
 *  - подключение: адаптеры, Wi-Fi (защита, сигнал), VPN, DNS, тип сети, скорость сейчас и сколько с включения;
 *  - куда уходит трафик: программы и адреса, с которыми они соединены (имя сайта - из кэша DNS этого компьютера);
 *  - кто подключается к вам: входящие соединения и порты, открытые для сети;
 *  - кто в сети: соседи из таблицы ARP; новые устройства отмечаются (список знакомых - в папке данных);
 *  - утечки и опасности: находки в обычном формате (id, sev, title, text, evidence).
 * Имена устройств и сайтов через DNS не ищутся: запрос раскрыл бы адреса вашей сети внешнему серверу.
 */
const { t, tx } = require('./i18n');
const { parseNetshInterfaces } = require('./rules-ready');

const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const str = (x, n = 300) => String(x == null ? '' : x).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, n);

// ---------------------------------------------------------------- адреса

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Вид адреса: loopback | unspecified | private | cgnat | linklocal | multicast | public | invalid. */
function ipScope(ip) {
  let s = String(ip || '').trim().toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) s = mapped[1];
  const m = V4.exec(s);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if ([a, b, Number(m[3]), Number(m[4])].some((x) => x > 255)) return 'invalid';
    if (a === 0) return 'unspecified';
    if (a === 127) return 'loopback';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a === 169 && b === 254) return 'linklocal';
    if (a >= 224) return 'multicast';
    return 'public';
  }
  if (!s.includes(':')) return 'invalid';
  if (s === '::' || s === '0:0:0:0:0:0:0:0') return 'unspecified';
  if (s === '::1') return 'loopback';
  if (/^fe[89ab]/.test(s)) return 'linklocal';
  if (/^f[cd]/.test(s) || /^fec0:/.test(s)) return 'private';
  if (/^ff/.test(s)) return 'multicast';
  return 'public';
}
const isLocalScope = (s) => s === 'private' || s === 'linklocal' || s === 'cgnat';

// ---------------------------------------------------------------- справочники

/** VPN по имени или описанию адаптера (виртуальные машины и Bluetooth сюда не попадают). */
const VPN_RE = /vpn|wireguard|wintun|\btap\b|tap-windows|\btun\b|tailscale|zerotier|amnezia|sing-?box|sing-tun|outline|openvpn|nordlynx|proton|surfshark|expressvpn|cloudflare warp|\bwarp\b|v2ray|xray|hiddify|clash|vpnd/i;
const VM_RE = /hyper-v|vethernet|virtualbox|vmware|docker|wsl|loopback|bluetooth|kernel debug|teredo|isatap|6to4/i;

/** Порты, на которые обычные программы не ходят: «бэкдоры», IRC-боты, Android Debug Bridge. */
const DANGER_PORTS = new Map([[4444, 'Metasploit'], [1337, ''], [31337, 'Back Orifice'], [12345, 'NetBus'], [54321, ''], [6666, 'IRC'], [6667, 'IRC'], [6697, 'IRC'], [5555, 'ADB'], [2323, 'Telnet']]);
const TOR_PORTS = new Set([9001, 9030, 9050, 9051, 9150]);
const PLAIN_PORTS = new Map([[21, 'FTP'], [23, 'Telnet']]);

/** Программы удалённого доступа: если они на связи, кто-то может видеть экран. */
const REMOTE_TOOLS = /^(anydesk|teamviewer(_service)?|tv_w32|tv_x64|rustdesk|ammyy_admin|aa_v3|aeroadmin|ultraviewer(_service)?|ultraviewer_desktop|supremo(service)?|radmin|rserver3|rutserv|rfusclient|litemanager|romserver|romviewer|winvnc|tvnserver|vncserver|uvnc_service|screenconnect\.windowsclient|screenconnect\.clientservice|connectwisecontrol\.client|remoting_host|splashtop\w*|srservice|dwrcs|getscreen|meshagent|parsec(d)?|chrome remote desktop host)$/i;

/** Системные процессы Windows (не «чужие программы»). */
const SYSTEM_PROC = /^(system|idle|svchost|lsass|services|wininit|smss|csrss|spoolsv|searchindexer|msmpeng|nissrv|mpdefendercoreservice|system idle process)$/i;

/** Подозрительное место, откуда программа ходит в интернет. */
const RISKY_PATH = /\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\downloads\\|\\\$recycle\.bin\\|\\programdata\\[^\\]+\.exe$/i;

// ---------------------------------------------------------------- Wi-Fi

/** netsh: дополнительные поля текущего подключения (сигнал, канал, стандарт). */
function wifiExtra(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\s*(\S.*?)\s+:\s?(.*)$/.exec(line);
    if (!m) continue;
    const k = m[1].trim().toLowerCase().replace(/\s+/g, ' ');
    const v = m[2].trim();
    if ((k === 'signal' || k === 'сигнал') && out.signal == null) out.signal = Number.parseInt(v, 10);
    else if ((k === 'channel' || k === 'канал') && out.channel == null) out.channel = Number.parseInt(v, 10);
    else if ((k === 'radio type' || k === 'тип радио' || k === 'тип радиомодуля') && out.radio == null) out.radio = v;
    else if ((k === 'band' || k === 'диапазон') && out.band == null) out.band = v;
  }
  return out;
}

function wifiNow(text) {
  if (!text) return null;
  const list = parseNetshInterfaces(text);
  const c = list.find((i) => i.connected);
  if (!c) return list.length ? { connected: false } : null;
  const x = wifiExtra(text);
  return {
    connected: true, ssid: str(c.ssid || c.profile, 64), security: c.security, auth: str(c.auth, 64), cipher: str(c.cipher, 64),
    signal: Number.isFinite(x.signal) ? x.signal : null, channel: Number.isFinite(x.channel) ? x.channel : null, radio: x.radio ? str(x.radio, 40) : null, band: x.band ? str(x.band, 40) : null,
  };
}

// ---------------------------------------------------------------- разбор

function adapterKind(a) {
  const s = `${a.alias || ''} ${a.description || ''}`;
  if (VPN_RE.test(s)) return 'vpn';
  if (VM_RE.test(s)) return 'virtual';
  if (/802\.11|wireless|wi-?fi|wlan/i.test(`${a.media || ''} ${s}`)) return 'wifi';
  if (/802\.3|ethernet/i.test(`${a.media || ''} ${s}`) && !a.virtual) return 'ethernet';
  return a.virtual ? 'virtual' : 'other';
}

/** Разбор ответа traffic.ps1. neighbors - из network.ps1 -Mode neighbors; known - Set знакомых MAC (null - первый раз). */
function analyse(raw, { neighbors = null, known = null, saved = null } = {}) {
  if (!raw || raw.format !== 'adamant-traffic') throw new Error(t('Сценарий сети вернул неожиданный ответ'));
  const errors = raw.errors && typeof raw.errors === 'object' ? raw.errors : {};
  const rate = new Map(arr(raw.rate && raw.rate.adapters).map((x) => [x.alias, x]));
  const sec = Math.max(0.5, Number(raw.rate && raw.rate.seconds) || 2);

  const adapters = arr(raw.adapters).filter((a) => a && typeof a === 'object').map((a) => {
    const kind = adapterKind(a);
    const r = rate.get(a.alias);
    return {
      alias: str(a.alias, 120), description: str(a.description, 160), kind, up: a.status === 'Up', status: str(a.status, 30),
      ipv4: arr(a.ipv4).map((x) => str(x, 45)).filter((x) => ipScope(x) !== 'linklocal'),
      ipv6Global: arr(a.ipv6).some((x) => ipScope(x) === 'public'),
      gateway: a.gateway ? str(a.gateway, 45) : null, gateway6: a.gateway6 && a.gateway6 !== '::' ? str(a.gateway6, 45) : null,
      dns: arr(a.dns).map((x) => str(x, 45)).filter((x) => !/^fec0:0:0:ffff::[123]$/i.test(x)),
      category: a.category ? str(a.category, 30) : null, network: a.network ? str(a.network, 120) : null, speed: a.speed ? str(a.speed, 30) : null,
      rxTotal: Number.isFinite(Number(a.rx)) ? Number(a.rx) : null, txTotal: Number.isFinite(Number(a.tx)) ? Number(a.tx) : null,
      rxRate: r ? Math.max(0, Math.round(Number(r.rx) / sec)) : null, txRate: r ? Math.max(0, Math.round(Number(r.tx) / sec)) : null,
    };
  });
  const physical = adapters.filter((a) => a.up && (a.kind === 'wifi' || a.kind === 'ethernet' || a.kind === 'other') && (a.ipv4.length || a.gateway));
  const vpnAdapters = adapters.filter((a) => a.up && a.kind === 'vpn');
  const vpnConns = arr(raw.vpn).filter((v) => v && /connected/i.test(v.status || ''));
  const vpn = { on: !!(vpnAdapters.length || vpnConns.length), names: [...vpnAdapters.map((a) => a.alias), ...vpnConns.map((v) => str(v.name, 80))] };
  const wifi = wifiNow(raw.wifi);
  const sum = (list, k) => list.reduce((s, a) => s + (a[k] || 0), 0);
  const speed = { rx: sum(physical, 'rxRate'), tx: sum(physical, 'txRate'), rxTotal: sum(physical, 'rxTotal'), txTotal: sum(physical, 'txTotal'), seconds: sec };

  // Имена сайтов из кэша DNS.
  const names = new Map();
  for (const d of arr(raw.dns)) {
    if (!d || !d.ip || !d.name) continue;
    // Запись PTR (обратное имя): name - «5.1.168.192.in-addr.arpa», ip - имя устройства.
    const ptr = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa\.?$/i.exec(String(d.name));
    const ip = ptr ? [ptr[4], ptr[3], ptr[2], ptr[1]].join('.') : String(d.ip).toLowerCase();
    const name = ptr ? String(d.ip) : String(d.name);
    if (!names.has(ip)) names.set(ip, str(name.replace(/\.$/, ''), 120));
  }
  const procs = raw.procs && typeof raw.procs === 'object' ? raw.procs : {};
  const proc = (pid) => {
    if (pid === 0) return { name: 'System Idle Process', path: null };
    if (pid === 4) return { name: 'System', path: null };
    const p = procs[String(pid)];
    return p ? { name: str(p.name, 80) || `PID ${pid}`, path: p.path ? str(p.path, 260) : null } : { name: `PID ${pid}`, path: null };
  };

  const tcp = arr(raw.tcp).filter((c) => c && typeof c === 'object');
  const listen = tcp.filter((c) => c.state === 'Listen');
  const listenPorts = new Set(listen.filter((c) => ipScope(c.la) !== 'loopback').map((c) => c.lp));
  const est = tcp.filter((c) => c.state !== 'Listen' && !['loopback', 'unspecified'].includes(ipScope(c.ra)));

  // Входящие: удалённая сторона подключилась к нашему открытому порту.
  const incomingRaw = est.filter((c) => listenPorts.has(c.lp) && c.lp < 49152);
  const incomingKeys = new Set(incomingRaw.map((c) => `${c.lp}|${c.ra}|${c.rp}`));
  const outRaw = est.filter((c) => !incomingKeys.has(`${c.lp}|${c.ra}|${c.rp}`));

  const byProc = new Map();
  for (const c of outRaw) {
    const p = proc(c.pid);
    const key = p.name.toLowerCase();
    let g = byProc.get(key);
    if (!g) byProc.set(key, (g = { name: p.name, path: p.path, count: 0, internet: 0, remotes: new Map(), ports: new Set() }));
    g.count += 1;
    const scope = ipScope(c.ra);
    if (scope === 'public') g.internet += 1;
    g.ports.add(c.rp);
    const host = names.get(String(c.ra).toLowerCase()) || null;
    const rk = host || c.ra;
    if (!g.remotes.has(rk)) g.remotes.set(rk, { ip: str(c.ra, 45), port: c.rp, host, scope: scope === 'public' ? 'internet' : 'local' });
  }
  const outgoing = [...byProc.values()].map((g) => ({
    name: g.name, path: g.path, count: g.count, internet: g.internet,
    remotes: [...g.remotes.values()].sort((a, b) => (a.scope === b.scope ? 0 : a.scope === 'internet' ? -1 : 1)).slice(0, 12), more: Math.max(0, g.remotes.size - 12),
  })).sort((a, b) => b.internet - a.internet || b.count - a.count).slice(0, 60);

  const incoming = incomingRaw.map((c) => {
    const p = proc(c.pid);
    const scope = ipScope(c.ra);
    return { name: p.name, path: p.path, port: c.lp, ip: str(c.ra, 45), host: names.get(String(c.ra).toLowerCase()) || null, scope: scope === 'public' ? 'internet' : 'local' };
  }).slice(0, 100);

  const seenListen = new Set();
  const listening = [];
  for (const c of listen) {
    if (ipScope(c.la) === 'loopback') continue;
    const p = proc(c.pid);
    const k = `${p.name}|${c.lp}`;
    if (seenListen.has(k)) continue;
    seenListen.add(k);
    listening.push({ name: p.name, path: p.path, port: c.lp, addr: str(c.la, 45), all: ipScope(c.la) === 'unspecified', system: SYSTEM_PROC.test(p.name) || /^c:\\windows\\/i.test(p.path || '') });
  }
  listening.sort((a, b) => a.port - b.port);

  // Кто в сети.
  const physIdx = new Set(arr(raw.adapters).filter((a) => a && a.status === 'Up' && ['wifi', 'ethernet', 'other'].includes(adapterKind(a))).map((a) => Number(a.ifIndex)));
  const gateways = new Set(physical.map((a) => a.gateway).filter(Boolean));
  const devices = Array.isArray(neighbors) ? neighbors.filter((n) => n && ipScope(n.ip) === 'private' && (physIdx.size === 0 || physIdx.has(Number(n.ifIndex)))).map((n) => {
    const mac = str(n.mac, 17).toUpperCase().replace(/:/g, '-');
    const first = Number.parseInt(mac.slice(0, 2), 16);
    const ip = str(n.ip, 45);
    const s = saved && mac && saved[mac] && typeof saved[mac] === 'object' ? saved[mac] : {};
    const dnsName = cleanName(names.get(ip));
    const remembered = typeof s.name === 'string' ? cleanName(s.name) : null;
    return {
      ip, mac, gateway: gateways.has(n.ip), randomMac: Number.isFinite(first) && (first & 2) === 2,
      isNew: !!(known && mac && !known.has(mac)), state: str(n.state, 20),
      label: typeof s.label === 'string' && s.label ? str(s.label, 40) : null,
      name: dnsName || remembered || null,
      nameSource: dnsName ? 'dns' : remembered ? str(s.nameSource || '', 10) || null : null,
    };
  }).sort((a, b) => (b.gateway - a.gateway) || ipNum(a.ip) - ipNum(b.ip)) : null;

  const res = {
    at: typeof raw.at === 'string' ? raw.at : new Date().toISOString(),
    adapters: adapters.filter((a) => a.up && a.kind !== 'virtual'),
    wifi, vpn, speed, outgoing, incoming, listening, devices,
    counts: {
      connections: outRaw.length, internet: outRaw.filter((c) => ipScope(c.ra) === 'public').length, programs: outgoing.length,
      incoming: incoming.length, listening: listening.length, dnsNames: names.size,
    },
    errors: Object.keys(errors).slice(0, 10),
  };
  res.findings = findings(raw, res, { est, incomingRaw, proc });
  return res;
}

function ipNum(ip) {
  const m = V4.exec(ip);
  return m ? ((Number(m[1]) * 256 + Number(m[2])) * 256 + Number(m[3])) * 256 + Number(m[4]) : 0;
}

// ---------------------------------------------------------------- утечки и опасности

const F = (id, sev, title, text, evidence = [], extra = {}) => ({ id, cat: 'network', sev, title, text, evidence: evidence.slice(0, 30), ...extra });

function findings(raw, r, { est, incomingRaw, proc }) {
  const out = [];
  const w = r.wifi;
  if (w && w.connected && w.security === 'open') {
    out.push(F('net-wifi-open', 'high', t('Wi-Fi без пароля: трафик в эфире не зашифрован'),
      t('Люди рядом могут видеть, какие сайты вы открываете, и перехватить всё, что идёт без HTTPS. Для банка, почты и работы включите VPN или раздайте интернет с телефона.'),
      [tx('Сеть «{0}»', w.ssid || '?')], { guide: 'wifi-forget' }));
  } else if (w && w.connected && (w.security === 'wep' || w.security === 'tkip')) {
    out.push(F('net-wifi-weak', 'high', t('Wi-Fi со слабым шифрованием'),
      t('Защиту WEP и WPA-TKIP взламывают за минуты. Если это ваша сеть, выберите в роутере WPA2-AES или WPA3.'),
      [tx('Сеть «{0}»: {1}', w.ssid || '?', w.security === 'wep' ? 'WEP' : 'WPA-TKIP')], { guide: 'wifi-forget' }));
  }

  const sh = raw.sharing && typeof raw.sharing === 'object' ? raw.sharing : {};
  const pub = (list) => arr(list).some((p) => /public|any/i.test(String(p)));
  if (pub(sh.files)) {
    out.push(F('net-sharing-public', 'high', t('Общий доступ к файлам открыт и в общественных сетях'),
      t('В кафе, гостинице или аэропорту другие устройства сети могут видеть ваши общие папки и принтеры. Оставьте общий доступ только для частной (домашней) сети.'),
      [tx('Правила брандмауэра «Общий доступ к файлам и принтерам» включены для профилей: {0}', arr(sh.files).join(', '))], { open: 'sharing' }));
  }
  if (pub(sh.discovery)) {
    out.push(F('net-discovery-public', 'advice', t('Компьютер виден другим в общественных сетях'),
      t('Включено «Обнаружение сети» для общественных сетей: в чужой сети компьютер отвечает на поиск устройств и показывает своё имя. Дома это удобно, в кафе и гостинице не нужно. Выключите обнаружение для общедоступных сетей.'),
      [tx('Правила брандмауэра «Обнаружение сети» включены для профилей: {0}', arr(sh.discovery).join(', '))], { open: 'sharing' }));
  }
  const shares = arr(raw.shares).filter((s) => s && s.name && !(Number(s.type) & 0x80000000) && !/^(ipc\$|print\$|admin\$|[a-z]\$)$/i.test(s.name));
  if (shares.length) {
    out.push(F('net-shares', 'advice', tx('Папки открыты для сети: {0}', shares.length),
      t('Эти папки видят другие компьютеры сети, если им разрешён доступ. Проверьте, что среди них нет документов, и что доступ дан не «Всем».'),
      shares.map((s) => tx('«{0}»: {1}', str(s.name, 80), str(s.path, 200) || '-')), { open: 'sharing' }));
  }

  const internet = est.filter((c) => ipScope(c.ra) === 'public');
  const danger = internet.filter((c) => DANGER_PORTS.has(c.rp));
  if (danger.length) {
    out.push(F('net-danger-port', 'high', t('Соединение на порт, которым пользуются вредоносные программы'),
      t('Обычные программы на эти порты не ходят: так часто связываются со своим хозяином программы удалённого управления и боты. Если программа вам незнакома, отключите интернет и проверьте компьютер антивирусом.'),
      danger.map((c) => tx('{0} → {1}:{2}', proc(c.pid).name, c.ra, c.rp + (DANGER_PORTS.get(c.rp) ? ` (${DANGER_PORTS.get(c.rp)})` : '')))));
  }
  const tor = internet.filter((c) => TOR_PORTS.has(c.rp) || /^tor$/i.test(proc(c.pid).name));
  if (tor.length) {
    out.push(F('net-tor', 'advice', t('Трафик идёт через сеть Tor'),
      t('Если это Tor Browser, всё в порядке. Если вы Tor не запускали, его может использовать вредоносная программа, чтобы скрыть, куда она передаёт данные.'),
      [...new Set(tor.map((c) => tx('{0} → {1}:{2}', proc(c.pid).name, c.ra, c.rp)))]));
  }
  const risky = new Map();
  for (const c of internet) {
    const p = proc(c.pid);
    if (p.path && RISKY_PATH.test(p.path) && !risky.has(p.path)) risky.set(p.path, tx('{0} ({1}) → {2}:{3}', p.name, p.path, c.ra, c.rp));
  }
  if (risky.size) {
    out.push(F('net-temp-proc', 'high', t('В интернет ходит программа из временной папки или «Загрузок»'),
      t('Установленные программы так не работают: из временных папок и «Загрузок» обычно запускаются только что скачанные файлы. Если вы не запускали эту программу сами, закройте её и проверьте компьютер антивирусом.'),
      [...risky.values()]));
  }
  const remote = new Map();
  for (const c of internet) {
    const p = proc(c.pid);
    if (REMOTE_TOOLS.test(p.name) && !remote.has(p.name)) remote.set(p.name, tx('{0} → {1}', p.name, c.ra));
  }
  if (remote.size) {
    out.push(F('net-remote-tool', 'advice', t('Программа удалённого доступа на связи'),
      t('Через такие программы можно видеть ваш экран и управлять компьютером. Если сейчас к вам никто не подключён по вашей просьбе, закройте её; мошенники часто просят установить именно их.'),
      [...remote.values()]));
  }
  const inNet = incomingRaw.filter((c) => ipScope(c.ra) === 'public');
  if (inNet.length) {
    out.push(F('net-incoming-internet', 'high', t('К компьютеру подключены из интернета'),
      t('Кто-то из интернета сейчас соединён с открытым портом этого компьютера. Если вы не включали удалённый доступ или сервер сами, отключите интернет и посмотрите, что это за программа.'),
      inNet.map((c) => tx('{0}: порт {1} ← {2}', proc(c.pid).name, c.lp, c.ra))));
  }
  const plain = internet.filter((c) => PLAIN_PORTS.has(c.rp));
  if (plain.length) {
    out.push(F('net-plain', 'advice', t('Соединение без шифрования (FTP или Telnet)'),
      t('Логин и пароль по таким протоколам идут открытым текстом: их видит любой на пути. Используйте SFTP или SSH.'),
      plain.map((c) => tx('{0} → {1}:{2} ({3})', proc(c.pid).name, c.ra, c.rp, PLAIN_PORTS.get(c.rp)))));
  }
  if (r.vpn.on) {
    const v6 = r.adapters.filter((a) => a.kind !== 'vpn' && a.ipv6Global && a.gateway6);
    if (v6.length && !r.adapters.some((a) => a.kind === 'vpn' && a.gateway6)) {
      out.push(F('net-vpn-ipv6', 'advice', t('IPv6 может идти мимо VPN'),
        t('VPN включён, но у обычного подключения есть свой адрес IPv6 и выход в интернет по нему. Сайты, которые работают по IPv6, могут видеть ваш настоящий адрес. Включите в VPN защиту от утечек IPv6 или выключите IPv6 у этого подключения.'),
        v6.map((a) => tx('{0}: есть адрес IPv6 и шлюз {1}', a.alias, a.gateway6))));
    }
  }
  const pubNet = r.adapters.filter((a) => a.kind !== 'vpn' && a.category === 'Public');
  const exposed = r.listening.filter((l) => l.all && !l.system && l.port < 49152);
  if (pubNet.length && exposed.length) {
    out.push(F('net-listen-public', 'advice', t('Программы ждут подключений в общественной сети'),
      t('Эти программы открыли порт для всей сети. Брандмауэр обычно закрывает такие порты в общественных сетях, но если вы разрешали программе доступ, к ней смогут подключиться соседи по сети. Закройте программы, которые вам сейчас не нужны.'),
      exposed.map((l) => tx('{0}: порт {1}', l.name, l.port))));
  }
  if (!out.length) out.push(F('net-ok', 'ok', t('Утечек и опасных соединений не видно'), tx('Соединений с интернетом: {0}, программ в сети: {1}.', r.counts.internet, r.counts.programs)));
  return out;
}

module.exports = { analyse, ipScope, adapterKind, wifiNow, REMOTE_TOOLS, DANGER_PORTS };
