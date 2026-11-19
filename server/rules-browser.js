'use strict';
/**
 * Браузеры: расширения и политики браузеров (раздел 'browsers', server/ps/sections/browsers.ps1).
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Нет раздела (старый отчёт) - ничего.
 *
 * Что считается опасным:
 *  - расширение в обход магазина: загружено из папки (режим разработчика), обновляется с чужого сервера,
 *    поставлено другой программой или (Firefox) без подписи Mozilla - так ставят шпионские расширения;
 *  - расширение, поставленное политикой (его нельзя удалить в браузере), и политики, которые меняют домашнюю
 *    страницу, поиск или прокси. На компьютере в домене организации это обычное дело - там это только «Совет»;
 *  - включённые расширения, которые видят все сайты и могут читать cookies, перехватывать запросы и т. п. -
 *    «Совет»: блокировщики рекламы и менеджеры паролей так и работают, но лишние лучше удалить.
 */
const { tx, t } = require('./i18n');
const { unknown, arr, DAY } = require('./rules');

/** Откуда магазины браузеров раздают обновления расширений. */
const STORE_HOSTS = new Set(['clients2.google.com', 'edge.microsoft.com', 'extension-updates.opera.com', 'addons.opera.com', 'addons.mozilla.org', 'versioncheck.addons.mozilla.org', 'browser-extensions.s3.yandex.net', 'addons-ext.yandex.net']);
const ALL_SITES = new Set(['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*', '*://*/', 'http://*/', 'https://*/']);

/** Опасные возможности расширения (с доступом ко всем сайтам) - и как их назвать по-человечески. */
const SENSITIVE = {
  cookies: t('cookies (вход на сайты)'),
  webRequest: t('перехват запросов'),
  webRequestBlocking: t('перехват запросов'),
  declarativeNetRequestWithHostAccess: t('перехват запросов'),
  debugger: t('отладчик браузера'),
  nativeMessaging: t('связь с программами на компьютере'),
  proxy: t('прокси'),
  clipboardRead: t('чтение буфера обмена'),
  history: t('история посещений'),
  management: t('управление другими расширениями'),
  privacy: t('настройки приватности'),
  scripting: t('свой код на страницах'),
  downloads: t('загрузки'),
};

const POLICY_LABEL = {
  HomepageLocation: t('домашняя страница'), NewTabPageLocation: t('новая вкладка'), RestoreOnStartupURLs: t('страницы при запуске'),
  DefaultSearchProviderSearchURL: t('поиск'), DefaultSearchProviderName: t('поиск'), ProxyServer: t('прокси'), ProxyPacUrl: t('прокси'), ProxyMode: t('прокси'),
};

function host(u) {
  try { return new URL(String(u)).host || String(u).slice(0, 60); } catch { return String(u).slice(0, 60); }
}

function evaluate(f, { now = Date.now() } = {}) {
  const out = [];
  const b = f.browsers;
  if (!b) {
    if (f.errors && f.errors.browsers) out.push(unknown('browser-ext', 'browser', t('Расширения браузеров'), f.errors.browsers));
    return out;
  }
  const domain = b.domain === true;
  const names = Object.fromEntries(arr(b.list).map((x) => [x.id, x.name]));
  const all = [];
  for (const br of arr(b.list)) for (const p of arr(br.profiles)) for (const e of arr(p.extensions)) all.push({ ...e, browser: br.name, browserId: br.id, profile: p.profile });
  const label = (e) => tx('{0} ({1}): {2}', e.browser, e.profile || '-', [e.name || e.id, e.version].filter(Boolean).join(' '));
  const forcedIds = new Set(arr(b.policies).flatMap((p) => arr(p.forced).map((x) => String(x.id || '').toLowerCase())).filter(Boolean));

  // ---- В обход магазина
  const side = [];
  for (const e of all) {
    if (e.default || e.policy || forcedIds.has(String(e.id).toLowerCase())) continue;
    let why = null;
    if (e.unpacked) why = t('загружено из папки (режим разработчика)');
    else if (e.browserId === 'firefox' && e.signed != null && e.signed <= 0) why = t('без подписи Mozilla');
    else if (e.browserId === 'firefox' && e.foreign) why = t('поставлено другой программой');
    else if (e.updateHost && !STORE_HOSTS.has(String(e.updateHost).toLowerCase())) why = tx('обновляется с сервера {0}', e.updateHost);
    else if (e.browserId !== 'firefox' && !e.store && !e.updateHost && [2, 3, 6].includes(Number(e.location))) why = t('поставлено другой программой');
    if (why) side.push(e.enabled ? tx('{0} - {1}', label(e), why) : tx('{0} - {1} (выключено)', label(e), why));
  }
  if (side.length) {
    out.push({
      id: 'browser-ext-sideloaded', cat: 'browser', sev: 'high',
      title: t('Расширение браузера установлено в обход магазина'),
      text: t('Такие расширения никто не проверял. Так часто ставят шпионские расширения: они видят пароли и переписку и подменяют страницы. Если вы его не ставили сами - удалите.'),
      evidence: side, guide: 'browser-extensions',
    });
  }

  // ---- Политики браузеров
  const forced = [];
  const hijack = [];
  for (const p of arr(b.policies)) {
    const bn = names[p.browser] || p.browser;
    for (const x of arr(p.forced)) {
      const known = all.find((e) => String(e.id).toLowerCase() === String(x.id).toLowerCase());
      forced.push(tx('{0}: {1}{2}', bn, known ? known.name || x.id : x.id, x.host && !STORE_HOSTS.has(String(x.host).toLowerCase()) ? tx(' - с сервера {0}', x.host) : ''));
    }
    const vals = p.values || {};
    for (const [k, v] of Object.entries(vals)) {
      if (!POLICY_LABEL[k]) continue;
      if (k === 'ProxyMode' && /^(direct|system)$/i.test(String(v))) continue;
      hijack.push(tx('{0}: {1} - {2}', bn, POLICY_LABEL[k], v === true ? t('задано') : /^https?:/i.test(String(v)) ? host(v) : String(v).slice(0, 60)));
    }
  }
  if (forced.length) {
    out.push({
      id: 'browser-ext-forced', cat: 'browser', sev: domain ? 'advice' : 'high',
      title: t('Расширение браузера поставлено принудительно'),
      text: domain
        ? t('Расширение поставлено политикой организации: удалить его в браузере нельзя. На рабочем компьютере это обычно делает администратор. Если расширение вам незнакомо, спросите у него.')
        : t('Такое расширение нельзя удалить в браузере: рядом с ним написано «Установлено администратором» или «Управляется организацией». На домашнем компьютере так обычно делают вредоносные программы. Если вы этого не настраивали, удалите политику по инструкции.'),
      evidence: forced, guide: 'browser-policy',
    });
  }
  if (hijack.length) {
    out.push({
      id: 'browser-policy-hijack', cat: 'browser', sev: domain ? 'advice' : 'high',
      title: t('Политика браузера задаёт домашнюю страницу, поиск или прокси'),
      text: domain
        ? t('Эти настройки браузера задала организация. Если адреса вам незнакомы, спросите администратора.')
        : t('Так вредоносные программы подменяют поиск и домашнюю страницу и пропускают трафик через свой сервер. Поменять это в настройках браузера нельзя. Если вы этого не настраивали, удалите политику по инструкции.'),
      evidence: hijack, guide: 'browser-policy',
    });
  }

  // ---- Доступ ко всем сайтам с опасными возможностями
  const broad = [];
  for (const e of all) {
    if (!e.enabled || e.default) continue;
    const perms = arr(e.perms).map(String);
    if (!perms.some((x) => ALL_SITES.has(x))) continue;
    const caps = [...new Set(perms.filter((x) => SENSITIVE[x]).map((x) => SENSITIVE[x]))];
    if (!caps.length) continue;
    const days = e.installed ? Math.floor((now - Date.parse(e.installed)) / DAY) : null;
    const fresh = days != null && days >= 0 && days <= 14 ? tx(' · поставлено {0} дн. назад', days) : '';
    broad.push(tx('{0} - все сайты, {1}{2}', label(e), caps.length > 3 ? tx('{0} и ещё {1}', caps.slice(0, 3).join(', '), caps.length - 3) : caps.join(', '), fresh));
  }
  if (broad.length) {
    out.push({
      id: 'browser-ext-broad', cat: 'browser', sev: 'advice',
      title: tx('Расширения с доступом ко всем сайтам: {0}', broad.length),
      text: t('Они видят всё, что вы открываете, в том числе почту и банк, и могут менять страницы. Блокировщики рекламы и менеджеры паролей так и работают. Оставьте только те, что ставили сами и которыми пользуетесь.'),
      evidence: broad, guide: 'browser-extensions',
    });
  }

  if (!out.length && arr(b.list).length) {
    const n = all.filter((e) => e.enabled).length;
    out.push({ id: 'browser-ext-ok', cat: 'browser', sev: 'ok', title: t('Расширения браузеров в порядке'), text: tx('Включённых расширений: {0}. Все из магазинов браузеров, без лишнего доступа ко всем сайтам.', n), evidence: arr(b.list).map((x) => x.name) });
  }
  return out;
}

module.exports = { evaluate, STORE_HOSTS, SENSITIVE };
