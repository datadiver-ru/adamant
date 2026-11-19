'use strict';
/**
 * Программы с известными дырами, Wi-Fi, готовность к беде (копии, восстановление), приватность (камера, микрофон).
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Если нужного раздела в facts нет
 * (старый отчёт), - ничего, а если раздел не собрался из-за ошибки, - одна находка «Не видно».
 *
 * Разделы сведений (server/ps/sections):
 *   software   (software.ps1)  - { count, truncated, items[] { name, version, publisher, installDate, scope }, flashFiles[] }
 *   wifi       (readiness.ps1) - { service, interfaces (текст netsh), profiles[] { name, text (текст netsh) }, profilesText? }
 *   readiness  (readiness.ps1) - { restore, fileHistory, oneDrive, knownFolders }
 *   privacy    (privacy.ps1)   - { webcam, microphone, location }: { value, machineValue, count, apps[] }
 * Ответы netsh разбираются здесь (parseNetshProfile, parseNetshInterfaces): подписи по-русски и по-английски.
 */
const { tx, t } = require('./i18n');
const { ok, unknown, arr, DAY } = require('./rules');

// ================================================================ Программы

/**
 * Таблица известных дыр и заброшенных программ - встроенная, без интернета.
 * ЕЁ НУЖНО ОБНОВЛЯТЬ С КАЖДЫМ ВЫПУСКОМ «Адаманта»: новые версии, новые дыры, пороги для браузеров.
 * Сюда попадают только версии, в которых мы уверены (бюллетени производителей и CVE).
 */
const TABLE_DATE = '2026-11-17';

/** Программы, которые больше не получают исправлений: их нужно удалить. */
const ABANDONED = [
  { id: 'flash', label: 'Adobe Flash Player', re: /^Adobe Flash Player\b/i, since: '2020-12-31',
    text: t('Adobe прекратила поддержку Flash Player в конце 2020 года. Исправлений больше не будет, а через дыры во Flash годами заражали компьютеры. Сайтам он больше не нужен.') },
  { id: 'shockwave', label: 'Adobe Shockwave Player', re: /^Adobe Shockwave Player\b/i, since: '2019-04-09',
    text: t('Adobe прекратила выпуск Shockwave Player в 2019 году. Дыры в нём больше не закрываются.') },
  { id: 'silverlight', label: 'Microsoft Silverlight', re: /^Microsoft Silverlight\b/i, since: '2021-10-12',
    text: t('Microsoft прекратила поддержку Silverlight в октябре 2021 года. Сайты им больше не пользуются, а дыры в нём уже не исправят.') },
  { id: 'quicktime', label: 'QuickTime', re: /^QuickTime\b/i, since: '2016',
    text: t('Apple прекратила выпускать QuickTime для Windows в 2016 году и оставила в нём известные дыры. Видеофайл может заразить компьютер через QuickTime, а современные плееры открывают те же файлы.') },
  { id: 'python2', label: 'Python 2', re: /^Python 2\.\d/i, since: '2020-01-01',
    text: t('Python 2 не поддерживается с 2020 года: найденные в нём дыры не закрывают. Если он нужен для работы, перейдите на Python 3.') },
];

/** Офис: дата окончания поддержки по году версии (Microsoft Lifecycle). */
const OFFICE_EOL = { 2007: '2017-10-10', 2010: '2020-10-13', 2013: '2023-04-11', 2016: '2025-10-14', 2019: '2025-10-14', 2021: '2026-10-13' };

/** Программы с известными серьёзными дырами ниже указанной версии. tiers - от самой опасной. */
const VULNERABLE = [
  { id: '7zip', label: '7-Zip', re: /^7-Zip(?! ZS)\b/i, tiers: [
    { below: '24.09', sev: 'high', why: t('В старых версиях 7-Zip архив может обойти защиту Windows для файлов из интернета. Эту дыру уже использовали в атаках.') },
    { below: '25.01', sev: 'advice', why: t('В версиях 7-Zip до 25.01 архив со ссылками может записать файлы за пределами выбранной папки.') },
  ] },
  { id: 'winrar', label: 'WinRAR', re: /^WinRAR\b/i, tiers: [
    { below: '7.13', sev: 'high', why: t('Через дыры в старых версиях WinRAR (исправлены в 6.23 и 7.13) рассылали архивы, которые незаметно запускали вирус. Эти дыры использовались в настоящих атаках.') },
  ] },
  { id: 'winscp', label: 'WinSCP', re: /^WinSCP\b/i, tiers: [
    { below: '5.17.10', sev: 'high', why: t('В старых версиях WinSCP ссылка на сайте может запустить на компьютере чужую команду.') },
  ] },
  { id: 'anydesk', label: 'AnyDesk', re: /^AnyDesk\b/i, tiers: [
    { below: '8.0.8', sev: 'high', why: t('В 2024 году у AnyDesk украли сертификат, которым подписаны старые версии, и производитель попросил всех обновиться. Через программу удалённого доступа управляют компьютером, поэтому она должна быть свежей.') },
  ] },
  { id: 'teamviewer', label: 'TeamViewer', re: /^TeamViewer\b/i, tiers: [
    { below: '15.8.3', sev: 'high', why: t('Через дыру в старых версиях TeamViewer сайт мог получить данные для входа в Windows.') },
    { below: '15.58.4', sev: 'advice', why: t('В версиях TeamViewer до 15.58.4 обычная программа на компьютере может получить права администратора.') },
  ] },
  { id: 'zoom', label: 'Zoom', re: /^Zoom(\s*Workplace|\s*\(\d+\s*bit\)|\s+\(|$)/i, pub: /zoom/i, tiers: [
    { below: '5.16.5', sev: 'high', why: t('В старых версиях Zoom есть серьёзные дыры, через которые можно получить права на компьютере.') },
    { below: '6.3.10', sev: 'advice', why: t('В версиях Zoom до 6.3.10 есть дыра, через которую можно получить права администратора.') },
  ] },
  { id: 'putty', label: 'PuTTY', re: /^PuTTY\b/i, tiers: [
    { below: '0.81', sev: 'advice', why: t('В версиях PuTTY до 0.81 по подписям можно вычислить ключ входа типа NIST P-521. Если вы пользуетесь таким ключом, после обновления замените его.') },
  ] },
  { id: 'vlc', label: 'VLC media player', re: /^VLC media player\b/i, tiers: [
    { below: '3.0.21', sev: 'advice', why: t('В старых версиях VLC есть дыры, через которые может сработать специально испорченный видеофайл или поток.') },
  ] },
  { id: 'notepadpp', label: 'Notepad++', re: /^Notepad\+\+/i, tiers: [
    { below: '8.5.7', sev: 'advice', why: t('В старых версиях Notepad++ есть дыры, через которые может сработать специально испорченный файл.') },
  ] },
  { id: 'keepass', label: 'KeePass', re: /^KeePass\b/i, tiers: [
    { below: '2.54', sev: 'advice', why: t('В версиях KeePass до 2.54 главный пароль можно восстановить из памяти компьютера или файла подкачки.') },
  ] },
];

/**
 * Браузеры обновляются сами. Отмечаем только явно старые: по состоянию на TABLE_DATE - старше примерно 6-9 месяцев.
 * min - первая «нестарая» версия. Яндекс Браузер нумеруется «год.месяц».
 */
const BROWSERS = [
  { id: 'chrome', label: 'Google Chrome', re: /^Google Chrome$/i, min: '147' },
  { id: 'edge', label: 'Microsoft Edge', re: /^Microsoft Edge$/i, min: '147' },
  { id: 'firefox', label: 'Mozilla Firefox', re: /^Mozilla Firefox\b(?!.*\bESR\b)/i, min: '148' },
  { id: 'firefox-esr', label: 'Mozilla Firefox ESR', re: /^Mozilla Firefox\b.*\bESR\b/i, min: '128' },
  { id: 'opera', label: 'Opera', re: /^Opera(\s+(Stable|GX Stable|GX))?(\s+[\d.]+)?$/i, min: '122' },
  { id: 'yandex', label: 'Яндекс Браузер', re: /^(Yandex|Яндекс)(\s+(Browser|Браузер))?$/i, min: '26.1' },
];

/** Программы резервного копирования и облака - для «готовности к беде». */
const BACKUP_APPS = /acronis|veeam agent|macrium|aomei backupper|easeus todo backup|paragon (backup|hard disk manager)|cobian|duplicati|backblaze|carbonite|\bidrive\b|^arq\b|iperius|handy backup|urbackup|active backup for business|r-drive image/i;
const CLOUD_APPS = /yandex\.?\s?disk|яндекс[ .]?диск|^google drive|^dropbox|^megasync|^mega desktop|^pcloud|облако mail|mail\.ru cloud|^icloud|^box drive|^sync\b|^nextcloud|^owncloud|^seafile|^tresorit/i;

/** Версия → числа: «ad 8.0.8» → [8,0,8], «7.1.9 (48550)» → [7,1,9]. */
function verParts(s) {
  const m = String(s == null ? '' : s).match(/\d+(?:\.\d+)*/);
  return m ? m[0].split('.').map(Number) : null;
}
function cmpVer(a, b) {
  const x = verParts(a) || [], y = verParts(b) || [];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
/** Версия программы: из DisplayVersion, а если её нет - из имени. */
const versionOf = (it) => (verParts(it.version) ? String(it.version).trim() : (String(it.name).match(/\d+(?:\.\d+)+/) || [''])[0]);
const SEV_RANK = { critical: 0, high: 1, advice: 2, unknown: 3, ok: 4 };
const UPDATE = t('Обновите её с официального сайта или удалите, если она не нужна.');
const REMOVE = t('Удалите её через «Параметры» → «Приложения».');

function softwareRules(f, out, now) {
  const s = f.software;
  if (!s) {
    if (f.errors && f.errors.software) out.push(unknown('app', 'updates', t('Установленные программы'), f.errors.software));
    return;
  }
  const items = arr(s.items).filter((x) => x && x.name);
  const found = new Map(); // id → находка; одна находка на правило, в доказательствах - все установки
  const add = (id, mk, sev, ev) => {
    let x = found.get(id);
    if (!x) found.set(id, (x = { id: `app-${id}`, cat: 'updates', sev, ...mk(), evidence: [], guide: 'app-update' }));
    else if (SEV_RANK[sev] < SEV_RANK[x.sev]) Object.assign(x, mk(), { sev });
    if (!x.evidence.some((e) => JSON.stringify(e) === JSON.stringify(ev))) x.evidence.push(ev);
  };
  const shown = (it) => [it.name, it.version].filter(Boolean).join(' ');

  for (const it of items) {
    const name = String(it.name).trim();
    const ver = versionOf(it);
    // Заброшенные программы.
    for (const a of ABANDONED) {
      if (!a.re.test(name)) continue;
      add(a.id, () => ({ title: tx('Установлена заброшенная программа: {0}', a.label), text: tx('{0} {1}', a.text, REMOVE) }), 'high',
        tx('{0} - поддержка прекращена ({1})', shown(it), a.since));
    }
    // Java: 5, 6, 7 - заброшены; 8 очень старой сборки - обновить.
    const j = /^(?:Java(?:\(TM\))?(?:\s+SE)?(?:\s+(?:Development Kit|Runtime Environment))?|J2SE Runtime Environment)\s+(\d+)(?:\.0)?(?:\s+Update\s+(\d+))?/i.exec(name);
    if (j) {
      const major = Number(j[1]), upd = j[2] ? Number(j[2]) : null;
      if (major >= 5 && major <= 7) {
        add('java-old', () => ({ title: tx('Установлена заброшенная программа: {0}', 'Java 5/6/7'), text: tx('{0} {1}', t('Java 5, 6 и 7 давно не получают исправлений. Через старую Java заражали компьютеры с помощью файлов и сайтов.'), t('Удалите её; если Java нужна какой-то программе, поставьте свежую версию с сайта java.com или от производителя этой программы.')) }), 'high',
          tx('{0} - поддержка прекращена ({1})', shown(it), major === 7 ? '2015' : major === 6 ? '2013' : '2009'));
      } else if (major === 8 && upd != null && upd < 401) {
        add('java8', () => ({ title: tx('{0}: старая версия с известными дырами', 'Java 8'), text: tx('{0} {1}', t('В старых сборках Java 8 много дыр, закрытых позже: через них может сработать вредный файл или программа на Java.'), UPDATE) }), 'advice',
          tx('{0}: установлена {1}, нужна не ниже {2}', name, `8 Update ${upd}`, '8 Update 401'));
      }
    }
    // Adobe Reader / Acrobat: XI и старше - заброшены; DC до 2023 года - давно не обновлялся.
    if (/^Adobe (Acrobat( Reader)?|Reader)\b/i.test(name) && verParts(ver)) {
      const major = verParts(ver)[0];
      if (major <= 11) {
        add('reader-old', () => ({ title: tx('Установлена заброшенная программа: {0}', 'Adobe Reader'), text: tx('{0} {1}', t('Эта версия Adobe Reader или Acrobat давно не получает исправлений. PDF-файл из письма может заразить компьютер через дыру в старой программе.'), t('Удалите её и поставьте свежий Adobe Acrobat Reader или другую программу для PDF.')) }), 'high',
          tx('{0} - поддержка прекращена ({1})', shown(it), major <= 10 ? '2015' : '2017'));
      } else if (major >= 15 && major < 23) {
        add('reader', () => ({ title: tx('{0}: старая версия с известными дырами', 'Adobe Acrobat Reader'), text: tx('{0} {1}', t('Adobe Acrobat Reader обычно обновляется сам. Эта версия вышла до 2023 года - с тех пор в программе закрыли много дыр, через которые срабатывают вредные PDF-файлы.'), UPDATE) }), 'advice',
          tx('{0}: установлена {1}, нужна не ниже {2}', name, ver, '23'));
      }
    }
    // Microsoft Office без поддержки.
    const o = /^Microsoft Office\b.*?\b(2007|2010|2013|2016|2019|2021)\b/i.exec(name);
    if (o && !/interop|runtime|viewer/i.test(name)) {
      const eol = OFFICE_EOL[o[1]];
      if (eol && now >= Date.parse(eol)) {
        add('office-old', () => ({ title: tx('Microsoft Office {0} больше не получает исправлений', o[1]), text: tx('{0} {1}', t('Microsoft больше не выпускает исправления для этой версии Office. Документ из письма может заразить компьютер через дыру, которую уже не закроют.'), t('Перейдите на поддерживаемую версию: Microsoft 365 или Office 2024.')) }), 'high',
          tx('{0}: поддержка закончилась {1}', name, eol));
      }
    }
    // Известные дыры ниже версии.
    for (const v of VULNERABLE) {
      if (!v.re.test(name) || (v.pub && !v.pub.test(it.publisher || '')) || !verParts(ver)) continue;
      const tier = v.tiers.find((x) => cmpVer(ver, x.below) < 0);
      if (!tier) continue;
      add(v.id, () => ({ title: tx('{0}: старая версия с известными дырами', v.label), text: tx('{0} {1}', tier.why, UPDATE) }), tier.sev,
        tx('{0}: установлена {1}, нужна не ниже {2}', name, ver, v.tiers[v.tiers.length - 1].below));
    }
    // Браузеры: только явно старые.
    for (const b of BROWSERS) {
      if (!b.re.test(name) || !verParts(ver) || cmpVer(ver, b.min) >= 0) continue;
      add(`browser-${b.id}`, () => ({ title: tx('Браузер {0} давно не обновлялся', b.label), text: tx('{0} {1}', t('Браузер обычно обновляется сам. Такая старая версия значит, что обновление сломалось или выключено, а через браузер на компьютер попадает больше всего угроз.'), t('Откройте в браузере «Справка» → «О браузере»: он сам проверит и поставит обновление. Если не получается, скачайте браузер заново с официального сайта.')) }), 'advice',
        tx('{0}: установлена {1}, нужна не ниже {2}', name, ver, b.min));
    }
  }
  // Встроенный в Windows Flash Player (System32\Macromed\Flash).
  const flashFiles = arr(s.flashFiles);
  if (flashFiles.length) {
    add('flash', () => ({ title: tx('Установлена заброшенная программа: {0}', 'Adobe Flash Player'), text: tx('{0} {1}', ABANDONED[0].text, t('Встроенный в Windows Flash удаляет обновление KB4577586 из Центра обновления Windows.')) }), 'high',
      tx('Файлы Flash Player: {0}', flashFiles.slice(0, 3).join(', ')));
  }
  if (found.size) out.push(...found.values());
  else out.push(ok('app-ok', 'updates', t('Программ с известными дырами не найдено'), tx('Проверено программ: {0}. Список известных дыр - на {1}.', s.count != null ? s.count : items.length, TABLE_DATE)));
}

// ================================================================ Wi-Fi

/** Подписи netsh на английском и русском (в нижнем регистре). */
const LABELS = {
  name: ['name', 'имя'],
  ssid: ['ssid'],
  ssidName: ['ssid name', 'имя ssid'],
  state: ['state', 'состояние'],
  profile: ['profile', 'профиль'],
  auth: ['authentication', 'проверка подлинности', 'аутентификация', 'тип проверки подлинности'],
  cipher: ['cipher', 'шифр', 'шифрование'],
  mode: ['connection mode', 'режим подключения'],
};

/** Строки «Подпись : значение» из ответа netsh. */
function netshPairs(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\s*(\S.*?)\s+:(?:\s(.*))?$/.exec(line);
    if (m) out.push([m[1].trim().toLowerCase().replace(/\s+/g, ' '), (m[2] || '').trim()]);
  }
  return out;
}

/** Уровень защиты сети по «Проверка подлинности» и «Шифр»: open | wep | tkip | ok | unknown. */
function wifiSecurity(auth, cipher) {
  const A = arr(auth).map((s) => String(s || '').toLowerCase()).filter(Boolean);
  const C = arr(cipher).map((s) => String(s || '').toLowerCase()).filter(Boolean);
  if (!A.length) return 'unknown';
  if (C.some((c) => /wep/.test(c)) || A.some((a) => /^(shared|общ)/.test(a))) return 'wep';
  if (A.every((a) => /^(open|открыт)/.test(a))) return 'open';
  if (C.length && C.every((c) => /tkip/.test(c))) return 'tkip';
  return 'ok';
}
const isAuto = (mode) => (mode == null ? null : /auto|автомат/i.test(mode));

/** Ответ «netsh wlan show profile name=…» → { name, ssids, mode, auto, auth[], cipher[], security }. */
function parseNetshProfile(text) {
  const p = { name: null, ssids: [], mode: null, auth: [], cipher: [] };
  for (const [k, v] of netshPairs(text)) {
    if (LABELS.name.includes(k)) { if (p.name == null) p.name = v; }
    else if (LABELS.ssidName.includes(k)) p.ssids.push(v.replace(/^"|"$/g, ''));
    else if (LABELS.mode.includes(k)) p.mode = v;
    else if (LABELS.auth.includes(k)) p.auth.push(v);
    else if (LABELS.cipher.includes(k)) p.cipher.push(v);
  }
  return { ...p, auto: isAuto(p.mode), security: wifiSecurity(p.auth, p.cipher) };
}

/** Ответ «netsh wlan show interfaces» → [{ name, state, connected, ssid, profile, auth, cipher, mode, security }]. */
function parseNetshInterfaces(text) {
  const list = [];
  let cur = null;
  for (const [k, v] of netshPairs(text)) {
    if (LABELS.name.includes(k)) { list.push((cur = { name: v, state: null, ssid: null, profile: null, auth: null, cipher: null, mode: null })); continue; }
    if (!cur) continue;
    if (LABELS.state.includes(k)) cur.state = v;
    else if (LABELS.ssid.includes(k)) cur.ssid = v;
    else if (LABELS.profile.includes(k)) cur.profile = v;
    else if (LABELS.auth.includes(k)) cur.auth = v;
    else if (LABELS.cipher.includes(k)) cur.cipher = v;
    else if (LABELS.mode.includes(k)) cur.mode = v;
  }
  return list.map((i) => ({ ...i, connected: /^(connected|подключено|подключен)$/i.test(i.state || ''), security: i.auth ? wifiSecurity([i.auth], [i.cipher]) : 'unknown' }));
}

const SEC_LABEL = { wep: 'WEP', tkip: 'WPA-TKIP' };

function wifiRules(f, out) {
  const w = f.wifi;
  if (!w) {
    if (f.errors && f.errors.wifi) out.push(unknown('wifi', 'hardening', t('Сети Wi-Fi'), f.errors.wifi));
    return;
  }
  if (w.service !== 'Running') return; // нет Wi-Fi или служба выключена
  const ifs = parseNetshInterfaces(w.interfaces);
  const profiles = arr(w.profiles).map((p) => { const x = parseNetshProfile(p && p.text); return { ...x, name: (p && p.name) || x.name }; });
  if (!ifs.length && !profiles.length) return; // беспроводного адаптера нет

  const now = ifs.filter((i) => i.connected);
  const openNow = now.filter((i) => i.security === 'open');
  if (openNow.length) {
    out.push({
      id: 'wifi-open-now', cat: 'hardening', sev: 'high',
      title: t('Компьютер подключён к Wi-Fi без пароля'),
      text: t('В открытой сети данные идут по воздуху без шифрования Wi-Fi. Люди рядом могут видеть, какие сайты вы открываете, и перехватить то, что передаётся без HTTPS. Для банка, почты и работы включите VPN или раздайте интернет с телефона.'),
      evidence: openNow.map((i) => tx('Сейчас подключено: «{0}»', i.ssid || i.profile || i.name)),
      guide: 'wifi-forget',
    });
  }
  const weak = new Map();
  for (const p of profiles) if (SEC_LABEL[p.security]) weak.set(p.name, p.security);
  for (const i of now) if (SEC_LABEL[i.security] && !weak.has(i.profile || i.ssid)) weak.set(i.profile || i.ssid, i.security);
  if (weak.size) {
    out.push({
      id: 'wifi-weak', cat: 'hardening', sev: 'high',
      title: t('Сохранена сеть Wi-Fi со слабым шифрованием'),
      text: t('Защиту WEP и WPA с шифром TKIP взламывают за минуты: посторонний может подключиться к сети и видеть ваш трафик. Если это ваша сеть, в настройках роутера выберите WPA2-AES (WPA2-Personal) или WPA3. Чужую такую сеть лучше забыть.'),
      evidence: [...weak].map(([n, s]) => tx('«{0}»: {1}', n, SEC_LABEL[s])),
      guide: 'wifi-forget',
    });
  }
  const openAuto = profiles.filter((p) => p.security === 'open' && p.auto === true);
  if (openAuto.length) {
    out.push({
      id: 'wifi-open-auto', cat: 'hardening', sev: 'advice',
      title: tx('Открытые сети Wi-Fi с автоподключением: {0}', openAuto.length),
      text: t('Компьютер сам подключается к этим сетям без пароля. Любой может назвать свою точку доступа так же - и компьютер молча подключится к ней. Забудьте эти сети или выключите для них «Подключаться автоматически».'),
      evidence: openAuto.slice(0, 10).map((p) => tx('«{0}»: без пароля, подключаться автоматически', p.name)),
      guide: 'wifi-forget',
    });
  }
  const parsed = profiles.filter((p) => p.security !== 'unknown');
  if (profiles.length && !parsed.length && !openNow.length && !weak.size) {
    out.push({ id: 'wifi-unknown', cat: 'hardening', sev: 'unknown', title: t('Сети Wi-Fi'), text: t('Не удалось разобрать ответ Windows о сохранённых сетях Wi-Fi.'), evidence: [tx('Сохранённых сетей: {0}', profiles.length)] });
  } else if (!openNow.length && !weak.size && !openAuto.length && (parsed.length || now.length)) {
    out.push(ok('wifi-ok', 'hardening', t('Сети Wi-Fi защищены'), tx('Сохранённых сетей: {0}. Открытых сетей с автоподключением и слабого шифрования нет.', profiles.length)));
  }
}

// ================================================================ Готовность к беде

const pad = (n) => String(n).padStart(2, '0');
/** Дата и время по местному времени: «2026-11-16 14:44». */
function fmtTime(v) {
  const d = new Date(v);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
const fmtDay = (v) => fmtTime(v).slice(0, 10);
const toMs = (iso) => { const v = iso ? Date.parse(iso) : NaN; return Number.isFinite(v) ? v : null; };
const normDir = (p) => String(p || '').toLowerCase().replace(/[\\/]+$/, '');
const under = (p, root) => !!root && !!p && (normDir(p) + '\\').startsWith(normDir(root) + '\\');

const FOLDER_NAMES = { desktop: t('Рабочий стол'), documents: t('Документы'), pictures: t('Изображения') };

function backupRules(f, r, out, now) {
  const od = r.oneDrive || {};
  const roots = [...arr(od.roots), ...arr(od.accounts).map((a) => a && a.folder)].filter(Boolean);
  const kf = r.knownFolders || {};
  const kfm = ['desktop', 'documents', 'pictures'].filter((k) => kf[k] && roots.some((root) => under(kf[k], root)));
  const fh = r.fileHistory || {};
  const fhLast = toMs(fh.lastBackup);
  const fhOn = !!fh.configured && Number(fh.policyDisabled) !== 1;
  const fhAge = fhLast != null ? Math.floor((now - fhLast) / DAY) : null;
  const fhRecent = fhOn && (fhAge == null || fhAge <= 30);
  const apps = arr(f.software && f.software.items).filter((x) => x && x.name);
  const backupApps = apps.filter((x) => BACKUP_APPS.test(x.name));
  const cloudApps = apps.filter((x) => CLOUD_APPS.test(x.name));

  const ev = [];
  for (const k of kfm) ev.push(tx('Папка «{0}» копируется в OneDrive', FOLDER_NAMES[k]));
  if (fhRecent) ev.push(fhLast != null ? tx('История файлов: последняя копия {0}', fmtDay(fhLast)) : t('История файлов включена'));
  for (const a of backupApps.slice(0, 4)) ev.push(tx('Программа резервного копирования: {0}', a.name));
  const strong = ev.length > 0;
  if (strong) {
    out.push({ ...ok('ready-backup-ok', 'readiness', t('Личные файлы защищены копией'), t('Если диск сломается или файлы зашифрует вирус-вымогатель, их можно будет вернуть из копии. Время от времени проверяйте, что копия правда обновляется.')), evidence: ev });
  }
  const fhOld = fhOn && fhAge != null && fhAge > 30;
  if (fhOld) {
    out.push({
      id: 'ready-filehistory-old', cat: 'readiness', sev: 'advice',
      title: t('История файлов давно не сохраняла копию'),
      text: t('Скорее всего, диск для копий давно не подключали. Подключите его - Windows сама допишет новые версии файлов.'),
      evidence: [tx('Последняя копия: {0} ({1} дн. назад)', fmtDay(fhLast), fhAge)],
      guide: 'backup',
    });
  }
  if (strong || fhOld) return;
  const cloud = cloudApps.map((x) => x.name);
  if (arr(od.accounts).length) cloud.unshift('OneDrive');
  if (cloud.length) {
    out.push({
      id: 'ready-backup-check', cat: 'readiness', sev: 'advice',
      title: t('Неясно, есть ли копия ваших файлов'),
      text: t('Облако установлено, но рабочий стол и документы в него не копируются: туда попадает только то, что лежит в папке облака. Включите в OneDrive копирование папок или храните важные файлы в папке облака.'),
      evidence: cloud.slice(0, 5).map((n) => tx('Установлено: {0}', n)),
      guide: 'backup',
    });
    return;
  }
  out.push({
    id: 'ready-no-backup', cat: 'readiness', sev: 'high',
    title: t('Нет резервной копии личных файлов'),
    text: t('Если диск сломается, компьютер украдут или файлы зашифрует вирус-вымогатель, документы и фотографии пропадут навсегда. Чтобы этого не случилось, хватит одного внешнего диска или облака.'),
    evidence: [t('OneDrive не копирует рабочий стол и документы'), fh.configured ? t('История файлов выключена политикой') : t('История файлов не настроена'), t('Программ резервного копирования и облаков не найдено')],
    guide: 'backup',
  });
}

function restoreRules(f, r, out, now) {
  const rs = r.restore;
  if (!rs) return;
  const sys = String(rs.systemDrive || 'C:').toUpperCase();
  const why = [];
  if (Number(rs.policyDisableSR) === 1) why.push(t('Точки восстановления запрещены политикой'));
  if (Number(rs.disableSR) === 1) why.push(t('Восстановление системы выключено в реестре'));
  if (rs.rpSessionInterval != null && Number(rs.rpSessionInterval) === 0) why.push(t('Защита системы выключена на всех дисках'));
  if (Array.isArray(rs.protectedDrives) && !rs.protectedDrives.map((d) => String(d).toUpperCase()).includes(sys)) why.push(tx('Защита системы выключена на диске {0}', sys));
  if (why.length) {
    out.push({
      id: 'ready-restore-off', cat: 'readiness', sev: 'advice',
      title: t('Точки восстановления выключены'),
      text: t('Точка восстановления - снимок системных файлов и настроек. Если после обновления, драйвера или программы Windows начнёт сбоить, к ней можно вернуться за несколько минут. Личные файлы она не сохраняет - для них нужна резервная копия.'),
      evidence: why,
      guide: 'restore-points',
    });
    return;
  }
  if (rs.rpSessionInterval == null && !Array.isArray(rs.protectedDrives)) {
    out.push({ id: 'ready-restore-unknown', cat: 'readiness', sev: 'unknown', title: t('Точки восстановления'), text: t('Видно после полной проверки (кнопка «Проверить полностью»)'), evidence: [], guide: 'restore-points' });
    return;
  }
  // Последняя точка: по списку точек (с правами администратора) или по журналу событий
  // (8216 - «точку не создали, потому что за последние сутки она уже есть»).
  const skipped = toMs(rs.lastSkipped);
  const cands = [toMs(rs.lastPoint), toMs(rs.lastCreated), skipped != null ? skipped - DAY : null].filter((x) => x != null);
  const last = cands.length ? Math.max(...cands) : null;
  const age = last != null ? Math.floor((now - last) / DAY) : null;
  if (rs.points === 0) {
    out.push({ id: 'ready-restore-none', cat: 'readiness', sev: 'advice', title: t('Защита системы включена, но точек восстановления нет'), text: t('Windows создаёт точки сама перед обновлениями, но сейчас нет ни одной. Создайте точку вручную - это займёт минуту.'), evidence: [t('Точек сохранено: 0')], guide: 'restore-points' });
  } else if (age != null && age > 45) {
    out.push({ id: 'ready-restore-old', cat: 'readiness', sev: 'advice', title: t('Последняя точка восстановления старая'), text: t('Если сейчас что-то сломается, придётся вернуться на много недель назад. Создайте новую точку вручную.'), evidence: [tx('Последняя точка: {0} ({1} дн. назад)', fmtDay(last), age)], guide: 'restore-points' });
  } else {
    const ev = [last != null ? tx('Последняя точка: {0}', fmtDay(last)) : t('Дата последней точки видна после полной проверки')];
    if (rs.points != null) ev.push(tx('Точек сохранено: {0}', rs.points));
    out.push({ ...ok('ready-restore-ok', 'readiness', t('Точки восстановления включены'), t('Если Windows начнёт сбоить после обновления или установки программы, можно вернуться к прежнему состоянию.')), evidence: ev });
  }
}

function readinessRules(f, out, now) {
  const r = f.readiness;
  if (!r) {
    if (f.errors && f.errors.readiness) out.push(unknown('ready', 'readiness', t('Резервные копии и восстановление'), f.errors.readiness));
    return;
  }
  backupRules(f, r, out, now);
  restoreRules(f, r, out, now);
}

// ================================================================ Приватность

const CAPS = { webcam: t('камера'), microphone: t('микрофон'), location: t('местоположение') };
/** Папки, откуда нормальные программы камеру не включают. */
const SUSPICIOUS_DIR = /\\(temp|tmp)\\|\\downloads\\|\\загрузки\\|^[a-z]:\\users\\public\\|\\\$recycle\.bin\\|^[a-z]:\\programdata\\[^\\]+$|^[a-z]:\\perflogs\\/i;
const BAD_SIGNATURE = /^(NotSigned|HashMismatch|NotTrusted)$/i;
const RECENT_DAYS = 14;

const appLabel = (a) => (a.packaged ? a.name : a.path || a.name);

function privacyRules(f, out, now) {
  const p = f.privacy;
  if (!p) {
    if (f.errors && f.errors.privacy) out.push(unknown('priv', 'privacy', t('Камера и микрофон'), f.errors.privacy));
    return;
  }
  const since = now - RECENT_DAYS * DAY;
  const byCap = {};
  for (const cap of Object.keys(CAPS)) {
    byCap[cap] = arr(p[cap] && p[cap].apps).filter((a) => a && (a.name || a.path)).map((a) => ({ ...a, startMs: toMs(a.start) }));
  }
  // Незнакомая программа: временная папка, «Загрузки», общая папка или нет подписи (подпись проверяется вне Program Files и Windows).
  const sus = [];
  for (const cap of Object.keys(CAPS)) {
    for (const a of byCap[cap]) {
      if (a.packaged || !a.path || a.startMs == null || a.startMs < since) continue;
      const reason = SUSPICIOUS_DIR.test(a.path) ? t('временная или общая папка') : BAD_SIGNATURE.test(a.signature || '') ? t('нет подписи издателя') : null;
      if (reason) sus.push({ cap, a, reason });
    }
  }
  if (sus.length) {
    const caps = new Set(sus.map((x) => x.cap));
    out.push({
      id: 'priv-suspicious', cat: 'privacy', sev: 'high',
      title: caps.has('webcam') ? t('Незнакомая программа включала камеру') : caps.has('microphone') ? t('Незнакомая программа включала микрофон') : t('Незнакомая программа узнавала местоположение'),
      text: t('Программа запускалась из временной папки, из «Загрузок» или без подписи издателя - так часто ведут себя шпионские программы. Если вы её не узнаёте: запретите ей доступ в параметрах конфиденциальности, проверьте компьютер антивирусом (полная проверка) и удалите программу.'),
      evidence: sus.slice(0, 8).map(({ cap, a, reason }) => tx('{0} - {1}, {2} ({3})', a.path, CAPS[cap], fmtTime(a.startMs), reason)),
      guide: 'privacy-camera',
    });
  }
  // Сейчас включены. Запись «без конца» старше суток считаем оборванной (программа упала), а не работающей.
  const inUse = (cap) => byCap[cap].filter((a) => a.inUse && a.startMs != null && a.startMs >= now - DAY);
  const cam = inUse('webcam');
  if (cam.length) {
    out.push({ id: 'priv-camera-inuse', cat: 'privacy', sev: 'advice', title: t('Камера сейчас включена'), text: t('Сейчас камерой пользуется программа из списка. Если вы не на видеозвонке и ничего не снимаете, закройте её и проверьте, кому разрешён доступ к камере.'), evidence: cam.slice(0, 8).map((a) => tx('{0} - с {1}', appLabel(a), fmtTime(a.startMs))), guide: 'privacy-camera' });
  }
  const mic = inUse('microphone');
  if (mic.length) {
    out.push({ id: 'priv-mic-inuse', cat: 'privacy', sev: 'advice', title: t('Микрофон сейчас включён'), text: t('Сейчас микрофоном пользуется программа из списка. Если вы не разговариваете и ничего не записываете, закройте её и проверьте, кому разрешён доступ к микрофону.'), evidence: mic.slice(0, 8).map((a) => tx('{0} - с {1}', appLabel(a), fmtTime(a.startMs))), guide: 'privacy-camera' });
  }
  // Кто пользовался за 14 дней.
  const recent = (cap) => byCap[cap].filter((a) => a.startMs != null && a.startMs >= since).sort((x, y) => y.startMs - x.startMs);
  const rc = recent('webcam'), rm = recent('microphone');
  if (rc.length) out.push({ ...ok('priv-camera-recent', 'privacy', tx('Камеру включали за {0} дней: {1}', RECENT_DAYS, rc.length), t('Если в списке есть незнакомая программа, запретите ей доступ к камере в параметрах.')), evidence: rc.slice(0, 8).map((a) => tx('{0} - {1}', appLabel(a), fmtTime(a.startMs))), guide: 'privacy-camera' });
  if (rm.length) out.push({ ...ok('priv-mic-recent', 'privacy', tx('Микрофон включали за {0} дней: {1}', RECENT_DAYS, rm.length), t('Если в списке есть незнакомая программа, запретите ей доступ к микрофону в параметрах.')), evidence: rm.slice(0, 8).map((a) => tx('{0} - {1}', appLabel(a), fmtTime(a.startMs))), guide: 'privacy-camera' });
  if (!rc.length && !rm.length) {
    const ev = [];
    if (p.webcam && p.webcam.value === 'Deny') ev.push(t('Доступ к камере выключен'));
    if (p.microphone && p.microphone.value === 'Deny') ev.push(t('Доступ к микрофону выключен'));
    out.push({ ...ok('priv-ok', 'privacy', tx('Камерой и микрофоном за {0} дней не пользовались', RECENT_DAYS), t('Windows не записала ни одного включения камеры или микрофона.')), evidence: ev });
  }
}

// ================================================================

function evaluate(facts, { now = Date.now() } = {}) {
  const f = facts || {};
  const out = [];
  softwareRules(f, out, now);
  wifiRules(f, out);
  readinessRules(f, out, now);
  privacyRules(f, out, now);
  return out;
}

module.exports = { evaluate, TABLE_DATE, ABANDONED, VULNERABLE, BROWSERS, OFFICE_EOL, cmpVer, verParts, parseNetshProfile, parseNetshInterfaces, wifiSecurity };
