'use strict';
/**
 * Bluetooth: разбор ответа server/ps/bluetooth.ps1 (только чтение и прослушивание эфира).
 *  - сопряжённые устройства: что это (клавиатура и мышь, наушники, телефон), нет ли среди них устройств для атак;
 *  - кто рядом: производитель, что за устройство, метки для поиска вещей (AirTag, SmartTag, Tile), устройства для атак,
 *    рассылка поддельных объявлений (так «Flipper Zero» и подобные засыпают телефоны окнами «подключить наушники»);
 *  - находки: что с этим делать.
 * Адреса устройств рядом - чужие и случайные: программа держит их только в памяти.
 */
const { t, tx } = require('./i18n');

const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const str = (x, n = 200) => (typeof x === 'string' ? x.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, n) : x == null ? '' : String(x).slice(0, n));

// Коды производителей Bluetooth SIG (только те, в которых уверены).
const VENDORS = {
  '004C': 'Apple', '0006': 'Microsoft', '0075': 'Samsung', '00E0': 'Google', '0087': 'Garmin', '0157': 'Huami (Amazfit)',
  '038F': 'Xiaomi', '027D': 'Huawei', '009E': 'Bose', '0057': 'Harman (JBL)', '012D': 'Sony', '02E5': 'Espressif (ESP32)',
  '0059': 'Nordic Semiconductor', '000F': 'Broadcom', '0171': 'Amazon', '068E': 'Razer',
};
// Службы (16-битные номера): метки для поиска вещей и прочее заметное.
const TRACKER_SVC = { FD5A: 'Samsung SmartTag', FEED: 'Tile', FEEC: 'Tile', FD84: 'Tile', FE33: 'Chipolo' };
const SVC_VENDOR = { FE2C: 'Google', FEAA: 'Google', FEBE: 'Bose', FE0F: 'Philips Hue', FD6F: null };
// Имена устройств для атак и тестов на проникновение.
const ATTACK_NAME = /flipper|bad ?usb|bad ?kb|bad ?ble|ducky|marauder|evil ?(crow|twin)?|pwn|ble ?spam|pineapple|hak5|deauth/i;

const KIND = {
  tracker: t('метка для поиска вещей'), attack: t('устройство для Bluetooth-атак'), apple: t('iPhone, iPad, Mac или часы'),
  airpods: t('наушники AirPods или Beats'), airplay: t('Apple TV или колонка AirPlay'), windows: t('компьютер или Xbox с Windows'),
  hid: t('клавиатура, мышь или пульт'), tv: t('телевизор'), audio: t('наушники или колонка'), phone: t('телефон'), other: t('устройство'),
};

function nearbyKind(d) {
  const mf = d.mf.map((m) => m.split(':'));
  const apple = mf.find(([c]) => c === '004C');
  const appleType = apple && apple[1] ? apple[1].slice(0, 2) : null;
  if (ATTACK_NAME.test(d.name)) return 'attack';
  if (appleType === '12' || d.svc.some((s) => TRACKER_SVC[s])) return 'tracker';
  if (d.svc.includes('1812')) return 'hid';
  if (appleType === '07') return 'airpods';
  if (appleType === '09') return 'airplay';
  if (appleType === '10' || appleType === '0C' || appleType === '0F' || appleType === '05') return 'apple';
  if (mf.some(([c, b]) => c === '0006' && b && b.startsWith('01'))) return 'windows';
  if (/\btv\b|\[tv\]|television|bravia/i.test(d.name)) return 'tv';
  if (/buds|airpods|headphone|earbud|speaker|jbl|bose|sony wh|wf-|lev\d|soundbar|наушник|колонк/i.test(d.name)) return 'audio';
  if (/phone|galaxy|redmi|pixel|iphone/i.test(d.name)) return 'phone';
  return 'other';
}

function vendorOf(d) {
  for (const m of d.mf) {
    const v = VENDORS[m.split(':')[0]];
    if (v) return v;
  }
  for (const s of d.svc) {
    if (TRACKER_SVC[s]) return TRACKER_SVC[s].split(' ')[0];
    if (SVC_VENDOR[s]) return SVC_VENDOR[s];
  }
  return null;
}

function trackerName(d) {
  const s = d.svc.find((x) => TRACKER_SVC[x]);
  if (s) return TRACKER_SVC[s];
  return 'Apple AirTag / Find My';
}

/** Разбор ответа bluetooth.ps1. */
function analyse(raw) {
  if (!raw || raw.format !== 'adamant-bluetooth') throw new Error(t('Сценарий Bluetooth вернул неожиданный ответ'));
  const errors = raw.errors && typeof raw.errors === 'object' ? raw.errors : {};
  const radio = raw.radio && typeof raw.radio === 'object'
    ? { present: !!raw.radio.present, on: !!raw.radio.on, name: str(raw.radio.name, 80) || null }
    : { present: !!raw.adapter, on: null, name: null };
  const adapter = raw.adapter && typeof raw.adapter === 'object' ? { name: str(raw.adapter.name, 120), status: str(raw.adapter.status, 30) } : null;
  if (adapter && !radio.present) radio.present = true;

  const paired = arr(raw.paired).filter((p) => p && typeof p === 'object').map((p) => {
    const name = str(p.name, 80);
    const attack = ATTACK_NAME.test(name);
    const kind = attack ? 'attack' : p.hid ? 'hid' : p.audio ? 'audio' : p.phone ? 'phone' : 'other';
    return { name, mac: str(p.mac, 12).toUpperCase().replace(/(..)(?!$)/g, '$1:'), le: !!p.le, kind, kindLabel: KIND[kind], hid: !!p.hid, attack, ok: str(p.status, 20) === 'OK' };
  }).slice(0, 100);

  const nearby = arr(raw.nearby).filter((d) => d && typeof d === 'object' && /^[0-9A-F]{12}$/i.test(String(d.addr))).map((d) => {
    const x = {
      addr: String(d.addr).toUpperCase().replace(/(..)(?!$)/g, '$1:'), rssi: Number.isFinite(Number(d.rssi)) ? Math.max(-127, Math.min(20, Number(d.rssi))) : null,
      seen: Math.max(0, Math.min(100000, Number(d.n) || 0)), name: str(d.name, 60),
      mf: arr(d.mf).map((m) => str(m, 20).toUpperCase()).filter((m) => /^[0-9A-F]{4}:[0-9A-F]*$/.test(m)).slice(0, 4),
      svc: arr(d.svc).map((s) => str(s, 36).toUpperCase()).slice(0, 6),
      random: d.random === true, connectable: d.connectable === true,
    };
    x.kind = nearbyKind(x);
    x.kindLabel = KIND[x.kind];
    x.vendor = vendorOf(x);
    if (x.kind === 'tracker') x.tracker = trackerName(x);
    // Совпадает ли с сопряжённым устройством (тот же адрес).
    x.paired = paired.some((p) => p.mac === x.addr);
    return x;
  }).sort((a, b) => (b.rssi ?? -200) - (a.rssi ?? -200)).slice(0, 200);

  const appleAction = nearby.filter((d) => d.mf.some((m) => m.startsWith('004C:0F'))).length;
  const res = {
    at: typeof raw.at === 'string' ? raw.at : new Date().toISOString(),
    seconds: Number(raw.seconds) || 0,
    radio, adapter, paired, nearby,
    counts: {
      paired: paired.length, nearby: nearby.length, named: nearby.filter((d) => d.name).length,
      trackers: nearby.filter((d) => d.kind === 'tracker').length, close: nearby.filter((d) => d.rssi != null && d.rssi >= -60).length,
    },
    errors: Object.keys(errors),
  };
  res.findings = findings(res, { appleAction });
  return res;
}

function findings(r, { appleAction }) {
  const out = [];
  const open = 'bluetooth';
  if (!r.radio.present) {
    out.push({ id: 'bt-none', cat: 'network', sev: 'ok', title: t('Bluetooth на этом компьютере нет'), text: t('Атаки через Bluetooth этому компьютеру не грозят.'), evidence: [] });
    return out;
  }
  const attackPaired = r.paired.filter((p) => p.attack);
  if (attackPaired.length) {
    out.push({
      id: 'bt-attack-paired', cat: 'network', sev: 'critical',
      title: tx('Сопряжено устройство для Bluetooth-атак: {0}', attackPaired.map((p) => '«' + p.name + '»').join(', ')),
      text: t('По имени это устройство для взлома (Flipper Zero, BadUSB, «резиновая уточка» и подобные). Оно притворяется клавиатурой и за секунды может само набрать команды: скачать вирус, отправить ваши файлы. Если это ваше устройство для тестов - удалите сопряжение, когда закончите. Если вы его не узнаёте - удалите сразу: «Параметры» → «Bluetooth и устройства» → устройство → «Удалить», и смените пароли.'),
      evidence: attackPaired.map((p) => `${p.name} (${p.mac})`), open,
    });
  }
  const hid = r.paired.filter((p) => p.hid && !p.attack);
  if (hid.length) {
    out.push({
      id: 'bt-hid-paired', cat: 'network', sev: 'ok',
      title: tx('Bluetooth-клавиатуры и мыши: {0}', hid.length),
      text: t('Клавиатура может набирать команды на компьютере. Проверьте, что все устройства в списке ваши, а незнакомые удалите.'),
      evidence: hid.map((p) => `${p.name} (${p.mac})`), open,
    });
  }
  const attackNear = r.nearby.filter((d) => d.kind === 'attack' && !d.paired);
  if (attackNear.length) {
    out.push({
      id: 'bt-attack-nearby', cat: 'network', sev: 'high',
      title: t('Рядом устройство для Bluetooth-атак'),
      text: t('Поблизости работает устройство, которое по имени похоже на инструмент для взлома. Не принимайте запросы на сопряжение и не нажимайте «Подключить» во всплывающих окнах. Если вы в людном месте - выключите Bluetooth.'),
      evidence: attackNear.map((d) => `${d.name || d.addr} · ${d.rssi} dBm`), open,
    });
  }
  if (appleAction >= 5) {
    out.push({
      id: 'bt-spam', cat: 'network', sev: 'high',
      title: t('Похоже, рядом рассылают поддельные Bluetooth-объявления'),
      text: tx('За {0} с появилось {1} устройств с одинаковым «предложением подключиться». Так Flipper Zero и подобные устройства засыпают телефоны окнами «подключить наушники» и пытаются выманить сопряжение. Не нажимайте «Подключить» в таких окнах; при необходимости выключите Bluetooth на время.', r.seconds, appleAction),
      evidence: [], open,
    });
  }
  const closeTrackers = r.nearby.filter((d) => d.kind === 'tracker' && d.rssi != null && d.rssi >= -65);
  if (closeTrackers.length) {
    out.push({
      id: 'bt-tracker-close', cat: 'network', sev: 'advice',
      title: t('Совсем рядом метка для поиска вещей'),
      text: t('Метки AirTag, SmartTag и Tile помогают найти ключи, но ими же следят за людьми. Сигнал очень сильный - метка в паре метров. Если это не ваша метка (и не ваши AirPods или другое устройство Apple в режиме «Локатора»), проверьте сумку, куртку и машину. iPhone и Android сами предупреждают о чужой метке, которая едет с вами.'),
      evidence: closeTrackers.map((d) => `${d.tracker} · ${d.rssi} dBm`), open,
    });
  }
  if (r.radio.on && !r.paired.length) {
    out.push({
      id: 'bt-on-unused', cat: 'network', sev: 'advice',
      title: t('Bluetooth включён, но ничего не сопряжено'),
      text: t('Если вы не пользуетесь Bluetooth, выключите его: меньше способов подобраться к компьютеру, особенно в людных местах.'),
      evidence: [], open,
    });
  }
  if (r.radio.on === false) {
    out.push({ id: 'bt-off', cat: 'network', sev: 'ok', title: t('Bluetooth выключен'), text: t('Пока Bluetooth выключен, через него к компьютеру не подобраться.'), evidence: [] });
  } else if (!out.some((f) => f.sev !== 'ok')) {
    out.push({ id: 'bt-ok', cat: 'network', sev: 'ok', title: t('С Bluetooth всё спокойно'), text: t('Среди сопряжённых устройств нет подозрительных, рядом не видно устройств для атак.'), evidence: [] });
  }
  return out;
}

module.exports = { analyse, VENDORS, ATTACK_NAME, nearbyKind };
