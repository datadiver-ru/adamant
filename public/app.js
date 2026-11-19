'use strict';
/*
 * Окно «Адаманта». Без библиотек. Все строки - по-русски через T('…') и F('… {0}', x);
 * английский словарь - /i18n-en.js (window.ADAMANT_EN), ключ - исходная русская строка.
 * Данные с сервера (имена процессов, команды автозагрузки) вставляются только как текст (textContent).
 */
(() => {
  // ------------------------------------------------------------ Перевод
  let DICT = null;
  const fill = (s, a) => String(s).replace(/\{(\d+)\}/g, (m, i) => (a[i] === undefined ? m : String(a[i])));
  const T = (s) => (DICT && DICT.has(s) ? DICT.get(s) : s);
  const F = (s, ...a) => fill(T(s), a);
  const L = (m) => {
    if (m == null) return '';
    if (typeof m === 'string') return T(m);
    if (typeof m === 'number') return String(m);
    if (typeof m === 'object' && typeof m.k === 'string') return fill(T(m.k), (m.a || []).map((x) => (x && (typeof x === 'object' || typeof x === 'string') ? L(x) : x)));
    return String(m);
  };
  function setLang(lang) {
    DICT = lang === 'en' && window.ADAMANT_EN ? new Map(Object.entries(window.ADAMANT_EN)) : null;
    document.documentElement.lang = lang === 'en' ? 'en' : 'ru';
    document.title = T('Адамант');
  }

  // ------------------------------------------------------------ Ключ и запросы
  let KEY = '';
  const hm = /[#&]key=([^&]+)/.exec(location.hash);
  if (hm) {
    KEY = decodeURIComponent(hm[1]);
    try { sessionStorage.setItem('adamant-key', KEY); } catch { /* без хранилища - ключ живёт до перезагрузки окна */ }
    history.replaceState(null, '', location.pathname);
  } else {
    try { KEY = sessionStorage.getItem('adamant-key') || ''; } catch { KEY = ''; }
  }

  async function api(route, body) {
    const opt = { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Adamant-Key': KEY } };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    const r = await fetch(route, opt);
    const data = await r.json().catch(() => null);
    if (!r.ok) {
      const e = new Error(data && data.error ? data.error : 'HTTP ' + r.status);
      e.code = data && data.code;
      e.status = r.status;
      throw e;
    }
    return data;
  }

  // ------------------------------------------------------------ Элементы
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : String(c));
    }
    return el;
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  const ICONS = {
    gem: 'M6 3h12l4 6-10 12L2 9z M2 9h20 M9 3 8 9l4 12 4-12-1-6',
    pc: 'M3 4h18v12H3z M8 20h8 M12 16v4',
    ports: 'M9 2v6 M15 2v6 M6 8h12v3a6 6 0 0 1-12 0z M12 17v5',
    autostart: 'M12 2v9 M5.6 6.6a8 8 0 1 0 12.8 0',
    network: 'M2 9a14.5 14.5 0 0 1 20 0 M5 12.5a10 10 0 0 1 14 0 M8.5 16a5 5 0 0 1 7 0 M12 19.5h.01',
    history: 'M3 12a9 9 0 1 0 3-6.7 M3 4v5h5 M12 7v5l3 2',
    report: 'M6 2h9l5 5v15H6z M14 2v6h6 M9 13h8 M9 17h6',
    settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z',
    refresh: 'M21 12a9 9 0 1 1-2.6-6.4 M21 3v6h-6',
    shield: 'M12 2l8 3v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V5z M9 12l2 2 4-4',
    lock: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4',
    info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 16v-4 M12 8h.01',
    warn: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z M12 9v4 M12 17h.01',
    print: 'M6 9V2h12v7 M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2 M6 14h12v8H6z',
    download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 M7 10l5 5 5-5 M12 15V3',
    search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z M21 21l-4.3-4.3',
    edit: 'M12 20h9 M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
    eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12z M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
    camera: 'M3 7h4l2-3h6l2 3h4v13H3z M12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
    mic: 'M9 5a3 3 0 0 1 6 0v6a3 3 0 0 1-6 0z M5 11a7 7 0 0 0 14 0 M12 18v4',
    usb: 'M9 2h6v6H9z M7 8h10v8a5 5 0 0 1-10 0z M12 21v1',
    clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 6v6l4 2',
    check: 'M20 6 9 17l-5-5',
    bluetooth: 'M7 7l10 10-5 5V2l5 5L7 17',
    list: 'M9 6h11 M9 12h11 M9 18h11 M4 5.5l1 1 2-2 M4 11.5l1 1 2-2 M4 17.5l1 1 2-2',
    cross: 'M18 6 6 18 M6 6l12 12',
    trash: 'M3 6h18 M8 6V4h8v2 M6 6l1 15h10l1-15 M10 11v6 M14 11v6',
    folder: 'M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z',
    router: 'M3 14h18v6H3z M7 17h.01 M11 17h.01 M8 10a5 5 0 0 1 8 0 M5 7a9 9 0 0 1 14 0',
    alarm: 'M12 3a6 6 0 0 1 6 6v4l2 3H4l2-3V9a6 6 0 0 1 6-6z M10 19a2 2 0 0 0 4 0',
    send: 'M22 2 11 13 M22 2l-7 20-4-9-9-4z',
    box: 'M21 8 12 3 3 8v8l9 5 9-5z M3 8l9 5 9-5 M12 13v8',
    menu: 'M4 6h16 M4 12h16 M4 18h16',
  };
  function icon(name) {
    const s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('fill', 'none');
    s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '1.7');
    s.setAttribute('stroke-linecap', 'round');
    s.setAttribute('stroke-linejoin', 'round');
    s.setAttribute('aria-hidden', 'true');
    for (const d of ICONS[name].split(' M').map((x, i) => (i ? 'M' + x : x))) {
      const p = document.createElementNS(SVGNS, 'path');
      p.setAttribute('d', d);
      s.append(p);
    }
    return s;
  }
  /**
   * Камень-алмаз для сводки и ожидания: лучи, «охранный круг» с греческой надписью ΑΔΑΜΑΣ («несокрушимый»),
   * сам камень и искры. Цвет (по важности находок) задаёт класс вокруг (styles.css). Разметка постоянная, данных в ней нет.
   */
  let wardSeq = 0;
  function gem() {
    const id = 'ward-path-' + ++wardSeq;
    const src = `<svg xmlns="${SVGNS}" viewBox="0 0 200 200" class="ward" aria-hidden="true"><defs><path id="${id}" d="M16 100a84 84 0 1 1 168 0a84 84 0 1 1-168 0"/></defs>
<circle cx="100" cy="100" r="97" class="w-line"/><circle cx="100" cy="100" r="92" class="w-ticks"/><circle cx="100" cy="100" r="75" class="w-line faint"/>
<text class="w-text"><textPath href="#${id}" textLength="520" lengthAdjust="spacing">ΑΔΑΜΑΣ ✦ ΑΔΑΜΑΣ ✦ ΑΔΑΜΑΣ ✦ ΑΔΑΜΑΣ ✦</textPath></text>
<path class="w-gem" d="M100 0l4 5-4 5-4-5zM100 190l4 5-4 5-4-5zM0 100l5-4 5 4-5 4zM190 100l5-4 5 4-5 4z"/></svg>`;
    const ward = document.importNode(new DOMParser().parseFromString(src, 'image/svg+xml').documentElement, true);
    return [
      h('i', { class: 'rays', 'aria-hidden': 'true' }),
      ward,
      h('img', { class: 'stone', src: '/img/diamond.png', alt: '', draggable: 'false' }),
      [1, 2, 3].map((n) => h('i', { class: 'spark s' + n, 'aria-hidden': 'true' })),
    ];
  }
  const LEGEND = () => T('Адамант по-гречески - «несокрушимый». В мифах из адаманта выкованы вещи, которые никто не мог сломать: цепи Прометея и врата Тартара.');
  const btn = (label, cls, onclick, ic) => h('button', { class: 'btn ' + (cls || ''), type: 'button', onclick }, ic ? icon(ic) : null, label);

  function toast(text, kind = '') {
    const el = h('div', { class: 'toast ' + kind, text });
    document.getElementById('toasts').append(el);
    setTimeout(() => el.remove(), 6000);
  }

  function modal(build) {
    const close = () => back.remove();
    const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });
    const back = h('div', { class: 'backdrop', onclick: (e) => { if (e.target === back && !box.dataset.locked) close(); } }, box);
    const onKey = (e) => { if (e.key === 'Escape' && !box.dataset.locked) { close(); document.removeEventListener('keydown', onKey); } };
    document.addEventListener('keydown', onKey);
    build(box, close);
    document.body.append(back);
    const f = box.querySelector('button.primary, button');
    if (f) f.focus();
    return { box, close };
  }

  // ------------------------------------------------------------ Справочники
  const SEV = ['critical', 'high', 'advice', 'unknown', 'ok'];
  const SEV_LABEL = { critical: () => T('Критично'), high: () => T('Важно'), advice: () => T('Совет'), unknown: () => T('Не видно'), ok: () => T('В порядке') };
  const CAT_LABEL = {
    windows: () => T('Защита Windows'), ports: () => T('Порты и службы'), accounts: () => T('Учётные записи'),
    autostart: () => T('Автозагрузка'), updates: () => T('Обновления'), boot: () => T('Шифрование и загрузка'), network: () => T('Своя сеть'),
    hardening: () => T('Защита от взлома'), physical: () => T('Физический доступ'), readiness: () => T('Готовность к беде'), privacy: () => T('Приватность'), guard: () => T('Страж'),
    browser: () => T('Браузеры'), downloads: () => T('Скачанные файлы'),
  };
  const CAT_ORDER = ['windows', 'hardening', 'physical', 'ports', 'accounts', 'autostart', 'browser', 'downloads', 'updates', 'boot', 'readiness', 'privacy'];
  const GUARD_KIND = {
    autostart: () => T('Автозагрузка'), services: () => T('Службы'), tasks: () => T('Задачи планировщика'), wmi: () => T('Скрытые подписки WMI'),
    rootCerts: () => T('Корневые сертификаты'), hosts: () => T('Файл hosts'), dns: () => T('DNS-серверы'), proxy: () => T('Прокси'),
    exclusions: () => T('Исключения антивируса'), admins: () => T('Администраторы'), ports: () => T('Открытые порты'), usb: () => T('Флешки и диски'),
    bootOrder: () => T('Порядок загрузки'), secureBoot: () => T('Безопасная загрузка'), firewall: () => T('Брандмауэр'),
  };
  const GUARD_CHANGE = { added: () => T('появилось'), removed: () => T('исчезло'), changed: () => T('изменилось') };
  const PRESENCE = {
    boot: () => T('включение'), shutdown: () => T('выключение'), sleep: () => T('сон'), wake: () => T('пробуждение'), unexpected: () => T('аварийное выключение'),
    logon: () => T('вход'), unlock: () => T('разблокировка'), lock: () => T('блокировка'), 'failed-local': () => T('неверный пароль'),
  };
  // Что важнее показать в клетке часа: неверный пароль, затем аварийное выключение, вход, разблокировка, пробуждение, включение.
  const PRESENCE_ORDER = ['failed-local', 'unexpected', 'logon', 'unlock', 'wake', 'boot'];
  const LOC_LABEL = {
    'HKLM-Run': () => T('Реестр, для всех пользователей'), 'HKLM-Run32': () => T('Реестр, для всех (32-битные программы)'),
    'HKCU-Run': () => T('Реестр, ваша учётная запись'), 'HKLM-RunOnce': () => T('Однократный запуск, для всех'),
    'HKCU-RunOnce': () => T('Однократный запуск, ваша учётная запись'), 'Startup-User': () => T('Папка «Автозагрузка»'),
    'Startup-Common': () => T('Папка «Автозагрузка» для всех'),
  };
  const DISABLE_LOCS = ['HKLM-Run', 'HKLM-Run32', 'HKCU-Run', 'Startup-User', 'Startup-Common'];
  const KIND_LABEL = {
    router: () => T('Роутер'), printer: () => T('Принтер'), camera: () => T('Камера'), phone: () => T('Телефон или планшет'),
    nas: () => T('Сетевое хранилище'), computer: () => T('Компьютер'), device: () => T('Устройство'),
  };
  const PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB',
    554: 'RTSP', 631: 'IPP', 1433: 'SQL Server', 1883: 'MQTT', 1900: 'SSDP', 3306: 'MySQL', 3389: 'RDP', 3702: 'WS-Discovery', 5000: 'HTTP 5000',
    5001: 'HTTPS 5001', 5040: 'CDP', 5353: 'mDNS', 5355: 'LLMNR', 5357: 'WSD', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis',
    7680: 'Delivery Optimization', 8000: 'HTTP 8000', 8080: 'HTTP 8080', 8443: 'HTTPS 8443', 9100: 'JetDirect', 27017: 'MongoDB', 62078: 'iPhone/iPad',
  };
  const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(document.documentElement.lang === 'en' ? 'en-GB' : 'ru-RU', { dateStyle: 'medium', timeStyle: 'short' }) : '-');
  const worst = (list) => SEV.find((s) => list.some((f) => f.sev === s)) || 'ok';

  // ------------------------------------------------------------ Состояние
  const S = { data: null, view: 'summary', filter: 'all', portsNet: true, busy: null, subnets: null, selected: null, progress: null, error: null };
  const report = () => S.data && S.data.report;
  const scan = () => S.data && S.data.scan;
  const pcFindings = () => (report() ? report().findings : []);
  const routerInfo = () => S.data && S.data.router;
  const netFindings = () => [...(scan() ? scan().findings : []), ...(routerInfo() ? routerInfo().findings || [] : [])];
  const netChecked = () => !!(scan() || routerInfo());
  const allFindings = () => [...pcFindings(), ...netFindings()];

  async function load() {
    S.data = await api('/api/state');
    setLang(S.data.settings.lang);
  }

  async function runCheck(full) {
    if (S.busy) return;
    S.busy = full ? 'full' : 'check';
    render();
    try {
      await api('/api/check', { full });
      await load();
      if (full) toast(T('Полная проверка закончена.'), 'ok');
    } catch (e) {
      if (e.code === 'CANCELLED') toast(T('Вы отклонили запрос прав администратора. Проверка не проводилась.'));
      else toast(F('Проверка не удалась: {0}', T(e.message)), 'error');
    } finally {
      S.busy = null;
      render();
    }
  }

  // ------------------------------------------------------------ Исправления и инструкции
  async function openFix(fix) {
    let plan;
    try {
      plan = await api('/api/fix/plan', { id: fix.id, arg: fix.arg || null });
    } catch (e) {
      return toast(T(e.message), 'error');
    }
    modal((box, close) => {
      const body = h('div');
      const foot = h('div', { class: 'foot' });
      const apply = btn(T('Применить'), 'primary', async () => {
        box.dataset.locked = '1';
        apply.disabled = true;
        cancel.disabled = true;
        apply.textContent = T('Ждём разрешения Windows…');
        try {
          const res = await api('/api/fix/apply', { id: plan.id, arg: plan.arg });
          delete box.dataset.locked;
          body.replaceChildren(resultView(res, false));
          foot.replaceChildren(btn(T('Закрыть'), 'primary', close));
          if (res.ok) {
            toast(T('Исправление применено.'), 'ok');
            runCheck(false);
          }
        } catch (e) {
          delete box.dataset.locked;
          apply.disabled = false;
          cancel.disabled = false;
          apply.textContent = T('Применить');
          if (e.code === 'CANCELLED') toast(T('Вы отклонили запрос прав администратора. Ничего не изменилось.'));
          else toast(T(e.message), 'error');
        }
      });
      const cancel = btn(T('Отмена'), '', close);
      body.append(
        h('p', { class: 'intro', text: T('Вот что изменится. Ничего не применяется, пока вы не нажмёте «Применить».') }),
        diffTable(plan.changes),
        plan.notes && plan.notes.length ? h('ul', null, plan.notes.map((n) => h('li', { text: L(n) }))) : null,
        h('div', { class: 'note' }, icon('shield'), h('div', { text: T('Windows попросит разрешение администратора. Прежние значения сохранятся: исправление можно откатить в разделе «Исправления».') })),
        h('details', null, h('summary', { text: T('Команды, которые выполнит программа') }), h('pre', { text: plan.commands.join('\n') })),
      );
      foot.append(cancel, apply);
      box.append(h('h2', { text: L(plan.title) }), body, foot);
    });
  }

  function diffTable(changes) {
    if (!changes || !changes.length) return h('p', { class: 'muted', text: T('Менять нечего: всё уже в нужном состоянии.') });
    return h('div', { class: 'table-wrap card' }, h('table', { class: 'diff' },
      h('thead', null, h('tr', null, h('th', { text: T('Что') }), h('th', { text: T('Сейчас') }), h('th', { text: T('Станет') }))),
      h('tbody', null, changes.map((c) => h('tr', null, h('td', { text: L(c.what) }), h('td', { text: L(c.from) }), h('td', { text: L(c.to) })))),
    ));
  }

  function resultView(res, undo) {
    if (!res.ok) {
      return h('div', null, h('div', { class: 'note warn' }, icon('warn'), h('div', { text: F('Не получилось: {0}', L(res.error || T('неизвестная ошибка'))) })));
    }
    return h('div', null,
      h('p', { class: 'intro', text: undo ? T('Прежние значения возвращены.') : T('Готово. Вот что изменилось:') }),
      diffTable(res.changes),
      res.reboot ? h('div', { class: 'note warn' }, icon('warn'), h('div', { text: T('Чтобы изменения вступили в силу, перезагрузите компьютер.') })) : null,
    );
  }

  async function openGuide(id) {
    let g;
    try {
      g = await api('/api/guide', { id });
    } catch (e) {
      return toast(T(e.message), 'error');
    }
    modal((box, close) => {
      box.append(
        h('h2', { text: L(g.title) }),
        h('p', { class: 'intro', text: L(g.intro) }),
        h('ol', null, g.steps.map((s) => h('li', { text: L(s) }))),
        h('div', { class: 'foot' },
          g.open.map((o) => btn(F('Открыть: {0}', L(o.label).toLowerCase()), '', () => api('/api/open', { target: o.id }).catch((e) => toast(T(e.message), 'error')))),
          btn(T('Понятно'), 'primary', close)),
      );
    });
  }

  // ------------------------------------------------------------ Карточка находки
  function findingCard(f, { actions = true } = {}) {
    const side = [];
    if (actions) {
      if (f.fix) side.push(btn(T('Исправить…'), 'primary small', () => openFix(f.fix)));
      for (const a of f.alt || []) side.push(btn(L(a.label), 'ghost small', () => openFix(a)));
      if (f.guide) side.push(btn(T('Как исправить'), 'small', () => openGuide(f.guide)));
      if (f.open) side.push(btn(T('Открыть настройки'), 'small', () => api('/api/open', { target: f.open }).catch((e) => toast(T(e.message), 'error'))));
    }
    const ev = f.evidence || [];
    const evList = (items) => h('ul', { class: 'ev' }, items.map((e) => h('li', { text: L(e) })));
    const files = actions && Array.isArray(f.files) && f.files.length ? f.files : null;
    return h('article', { class: 'finding ' + f.sev },
      h('div', null,
        h('div', { class: 'top' }, h('span', { class: 'sev ' + f.sev, text: SEV_LABEL[f.sev]() }), h('h3', { text: L(f.title) })),
        f.text ? h('p', { text: L(f.text) }) : null,
        files ? filesBlock(files, ev.length - files.length) : ev.length > 6
          ? [evList(ev.slice(0, 5)), h('details', null, h('summary', { text: F('Ещё {0}', ev.length - 5) }), evList(ev.slice(5)))]
          : ev.length ? evList(ev) : null,
      ),
      side.length ? h('div', { class: 'side-actions no-print' }, side) : null,
    );
  }

  // ---------- Скачанные файлы: кнопки у каждого файла
  function filesBlock(files, more) {
    return h('div', { class: 'files' },
      files.map((x) => h('div', { class: 'file-row' },
        h('div', { class: 'file-name' }, h('b', { text: x.name }), h('span', { class: 'muted small', text: L(x.why) })),
        h('div', { class: 'file-actions no-print' },
          btn(S.avBusy === x.path ? T('Проверяю…') : T('Проверить антивирусом'), 'small', () => avScanFile(x), 'shield'),
          btn(T('Показать в папке'), 'ghost small', () => api('/api/downloads/reveal', { path: x.path }).catch((e) => toast(T(e.message), 'error')), 'folder'),
          btn(T('В корзину'), 'ghost small', () => trashFile(x), 'trash')))),
      more > 0 ? h('p', { class: 'muted small', text: F('И ещё файлов: {0}', more) }) : null);
  }

  async function avScanFile(x) {
    if (S.avBusy) return;
    S.avBusy = x.path;
    render();
    try {
      const r = await api('/api/downloads/scan', { path: x.path });
      if (r.clean) toast(F('Угроз не найдено: {0}', r.name), 'ok');
      else {
        toast(F('Найдены угрозы в файле {0}. Антивирус убрал его в карантин.', r.name), 'error');
        runCheck(false);
      }
    } catch (e) {
      toast(T(e.message), 'error');
    } finally {
      S.avBusy = null;
      render();
    }
  }

  async function trashFile(x) {
    if (!confirm(F('Переместить «{0}» в корзину? Файл можно будет вернуть из корзины.', x.name))) return;
    try {
      await api('/api/downloads/trash', { path: x.path });
      toast(F('Файл в корзине: {0}', x.name), 'ok');
      runCheck(false);
    } catch (e) {
      toast(T(e.message), 'error');
    }
  }

  // ------------------------------------------------------------ Экраны
  const VIEWS = {
    summary: { icon: 'gem', label: () => T('Сводка'), render: viewSummary },
    checklist: { icon: 'list', label: () => T('Чек-лист'), render: viewChecklist },
    pc: { icon: 'pc', label: () => T('Этот ПК'), render: viewPc },
    guard: { icon: 'eye', label: () => T('Страж'), render: viewGuard },
    drills: { icon: 'target', label: () => T('Учения'), render: viewDrills, paid: 'drills' },
    entry: { icon: 'lock', label: () => T('Защита входа'), render: viewEntry, paid: 'entry' },
    ports: { icon: 'ports', label: () => T('Порты'), render: viewPorts },
    autostart: { icon: 'autostart', label: () => T('Автозагрузка'), render: viewAutostart },
    network: { icon: 'network', label: () => T('Сеть и трафик'), render: viewNetwork },
    apps: { icon: 'box', label: () => T('Обновление программ'), nav: () => T('Программы'), render: viewApps },
    bluetooth: { icon: 'bluetooth', label: () => T('Bluetooth'), render: viewBluetooth, paid: 'bluetooth' },
    journal: { icon: 'history', label: () => T('Исправления'), render: viewJournal },
    report: { icon: 'report', label: () => T('Отчёт'), render: viewReport },
    settings: { icon: 'settings', label: () => T('Настройки'), render: viewSettings },
  };
  /** Боковая панель по группам: так 14 разделов читаются легче. Раздел, не попавший в группы, уходит в последнюю. */
  const NAV_GROUPS = [
    { views: ['summary', 'checklist'] },
    { title: () => T('Компьютер'), views: ['pc', 'autostart', 'apps'] },
    { title: () => T('Защита'), views: ['guard', 'entry', 'drills'] },
    { title: () => T('Сеть'), views: ['network', 'ports', 'bluetooth'] },
    { title: () => T('Служебное'), views: ['journal', 'report', 'settings'] },
  ];
  {
    const grouped = new Set(NAV_GROUPS.flatMap((g) => g.views));
    for (const k of Object.keys(VIEWS)) if (!grouped.has(k)) NAV_GROUPS[NAV_GROUPS.length - 1].views.push(k);
  }

  function pageHead(title, sub, ...actions) {
    return h('div', { class: 'page-head' }, h('div', null, h('h1', { text: title }), sub ? h('p', { text: sub }) : null), actions.length ? h('div', { class: 'actions no-print' }, actions) : null);
  }

  function checkButtons() {
    return [
      btn(T('Проверить снова'), '', () => runCheck(false), 'refresh'),
      btn(T('Проверить полностью'), 'primary', () => runCheck(true), 'shield'),
    ];
  }

  function busyView() {
    const full = S.busy === 'full';
    const sp = h('div', { class: 'spinner' }, gem());
    return h('div', { class: 'busy' }, sp,
      h('h2', { text: full ? T('Полная проверка…') : T('Проверяю компьютер…') }),
      h('p', { class: 'muted', text: full ? T('Windows спросит разрешение администратора. Проверка только читает настройки и ничего не меняет.') : T('Обычно это занимает 10-20 секунд. Программа только читает настройки.') }));
  }

  /** После обновления программы помощник остаётся от прошлой версии - говорим об этом на сводке, а не только в настройках. */
  function helperNudge() {
    if (S.helper === undefined && !S.helperLoading) loadHelper();
    const st = S.helper;
    if (!st || !st.installed || !st.outdated || S.helperNudgeLater) return null;
    const busy = S.busy === 'helper';
    return h('div', { class: 'note warn helper-nudge no-print', role: 'status' }, icon('refresh'),
      h('div', { class: 'note-body' },
        h('b', { text: T('Обновите помощника администратора') }),
        h('p', { text: T('Адамант обновился, а помощник остался от прошлой версии. Пока его не обновить, «Проверить полностью» каждый раз спрашивает разрешение Windows, а сам помощник проверяет по старым правилам. Обновление - одно разрешение Windows.') }),
        h('div', { class: 'actions' },
          btn(busy ? T('Обновляю…') : T('Обновить помощника'), 'primary small', () => helperAction('install'), 'refresh'),
          btn(T('Позже'), 'small', () => { S.helperNudgeLater = true; render(); }))));
  }

  // ------------------------------------------------------------ Знакомство и первые шаги
  /** Знакомство для новичка: три коротких шага с Кирой. Само показывается один раз, потом - из «О программе». */
  function welcomeModal() {
    if (document.querySelector('.modal.welcome')) return;
    if (!S.data.settings.introDone) api('/api/settings', { introDone: true }).then((s) => { S.data.settings = s; }).catch(() => {});
    let step = 0;
    const m = modal((box, close) => {
      box.classList.add('welcome');
      const STEPS = [
        () => ({
          img: 'img/kira-keeper.jpg',
          title: T('Знакомьтесь: Адамант'),
          body: [
            h('p', { text: T('Адамант проверяет, хорошо ли защищён ваш компьютер: антивирус и брандмауэр, обновления, учётные записи, открытые порты, автозагрузку и домашнюю сеть. Всё найденное он объясняет простыми словами.') }),
            h('p', { text: T('Сам он ничего не меняет. Каждое исправление вы сначала видите целиком, потом нажимаете «Применить», и его всегда можно отменить.') }),
            h('div', { class: 'welcome-lang' }, h('span', { class: 'muted small', text: T('Язык') }),
              h('div', { class: 'lang' }, [['ru', 'Русский'], ['en', 'English']].map(([id, label]) => h('button', { type: 'button', 'aria-pressed': String(S.data.settings.lang === id),
                onclick: () => saveSettings({ lang: id }).then(draw) }, label)))),
          ],
        }),
        () => ({
          img: 'img/kira-sword.jpg',
          title: T('Как читать результаты'),
          body: [
            h('ul', { class: 'welcome-sev' }, [
              ['critical', T('опасно, исправьте в первую очередь.')],
              ['high', T('серьёзное замечание, стоит исправить.')],
              ['advice', T('можно сделать лучше, если хотите.')],
              ['unknown', T('это видно только после «Проверить полностью».')],
              ['ok', T('всё хорошо, ничего делать не нужно.')],
            ].map(([s, text]) => h('li', null, h('i', { class: 'dot ' + s }), h('span', null, h('b', { text: SEV_LABEL[s]() }), ' - ', text)))),
            h('p', { text: T('Нажмите на любую находку: там написано, чем это грозит и как исправить.') }),
          ],
        }),
        () => ({
          img: 'img/kira-knight.jpg',
          title: T('С чего начать'),
          body: [
            h('ol', { class: 'welcome-steps' },
              h('li', { text: T('Первая проверка запускается сама и идёт 10-20 секунд: программа только читает настройки.') }),
              h('li', { text: T('Исправьте то, что отмечено как «Критично».') }),
              h('li', { text: T('Поставьте помощника администратора - тогда Адамант увидит больше. Windows спросит разрешение один раз.') }),
              h('li', { text: T('Включите работу в фоне: Адамант будет проверять компьютер раз в сутки и сообщит, только если появится что-то важное.') })),
            h('p', { class: 'muted small', text: T('Окно Windows «Разрешить этому приложению вносить изменения?» должно появляться, только когда вы сами нажали кнопку. Если вы ничего не нажимали - выберите «Нет».') }),
            h('p', { class: 'muted small', text: T('Эти шаги будут на «Сводке», пока вы их не сделаете.') }),
          ],
        }),
      ];
      function draw() {
        const s = STEPS[step]();
        const last = step === STEPS.length - 1;
        const done = () => { close(); if (!report() && !S.busy) runCheck(false); };
        box.replaceChildren(
          h('div', { class: 'welcome-grid' },
            h('img', { src: s.img, alt: '', width: 180, height: 180, decoding: 'async' }),
            h('div', null, h('p', { class: 'welcome-step muted small', text: F('Шаг {0} из {1}', step + 1, STEPS.length) }), h('h2', { text: s.title }), kids(s.body))),
          h('div', { class: 'foot' },
            step ? btn(T('Назад'), 'ghost', () => { step -= 1; draw(); }) : btn(T('Пропустить'), 'ghost', close),
            last ? btn(report() || S.busy ? T('Понятно') : T('Проверить компьютер'), 'primary', done, report() || S.busy ? '' : 'shield')
              : btn(T('Дальше'), 'primary', () => { step += 1; draw(); })));
        const f = box.querySelector('.foot button.primary');
        if (f) f.focus();
      }
      draw();
    });
    const f = m.box.querySelector('.foot button.primary');
    if (f) f.focus();
  }

  /** «Первые шаги» на сводке: что ещё сделать, с кнопкой рядом с каждым шагом. Пропадает, когда всё сделано. */
  function firstSteps() {
    const r = report();
    if (!r || S.data.settings.stepsHidden) return null;
    if (S.helper === undefined && !S.helperLoading) loadHelper();
    const crit = allFindings().filter((f) => f.sev === 'critical').length;
    const st = S.helper;
    const helperOk = !!(st && st.installed);
    const steps = [
      { done: true, text: T('Проверить компьютер') },
      { done: !crit, text: crit ? F('Исправить критичное (осталось: {0})', crit) : T('Исправить критичное'), act: btn(T('Показать'), 'small', () => go('pc', 'critical')) },
      { done: helperOk, text: T('Поставить помощника администратора'), hint: T('Тогда Адамант видит BitLocker, журнал входов и исключения антивируса. Windows спросит разрешение один раз.'),
        act: st === undefined || S.helperLoading ? null : btn(S.busy === 'helper' ? T('Устанавливаю…') : T('Установить'), 'small', () => helperAction('install'), 'shield') },
      { done: !!S.data.settings.background, text: T('Включить работу в фоне'), hint: T('Проверка раз в сутки и уведомление, только если появилось что-то важное.'), act: btn(T('Включить'), 'small', () => saveSettings({ background: true })) },
    ];
    const left = steps.filter((s) => !s.done).length;
    if (!left) return null;
    return h('section', { class: 'card pad first-steps no-print' },
      h('div', { class: 'fs-head' },
        h('div', null, h('b', { text: T('Первые шаги') }), ' ', h('span', { class: 'muted small', text: F('сделано {0} из {1}', steps.length - left, steps.length) })),
        btn(T('Скрыть'), 'ghost small', () => saveSettings({ stepsHidden: true }))),
      h('ol', { class: 'fs-list' }, steps.map((s, i) => h('li', { class: s.done ? 'done' : '' },
        h('span', { class: 'fs-mark' }, s.done ? icon('check') : String(i + 1)),
        h('div', { class: 'fs-text' }, h('b', { text: s.text }), s.hint && !s.done ? h('p', { class: 'muted small', text: s.hint }) : null),
        s.done ? null : s.act || null))));
  }

  function viewSummary() {
    const r = report();
    if (!r) {
      return h('div', { class: 'page' }, helperNudge(), h('div', { class: 'hero' }, h('div', { class: 'gem' }, gem()),
        h('div', null, h('h1', { text: T('Проверка ещё не проводилась') }), h('p', { text: T('Программа посмотрит настройки защиты Windows, открытые порты, учётные записи, автозагрузку, шифрование и загрузку компьютера. Она ничего не меняет без вашего разрешения.') }),
          h('p', { class: 'legend', text: LEGEND() }),
          h('div', { class: 'actions' }, btn(T('Проверить компьютер'), 'primary', () => runCheck(false), 'shield')))));
    }
    const all = allFindings();
    const sum = Object.fromEntries(SEV.map((s) => [s, all.filter((f) => f.sev === s).length]));
    const tone = sum.critical ? 'critical' : sum.high ? 'high' : 'ok';
    const headline = { critical: T('Нужно вмешаться'), high: T('Есть что улучшить'), ok: T('Компьютер защищён') }[tone];
    const text = sum.critical
      ? F('Найдено критичных проблем: {0}. Их стоит исправить в первую очередь.', sum.critical)
      : sum.high ? F('Серьёзных дыр нет, но важных замечаний: {0}.', sum.high) : T('Критичных и важных проблем не найдено.');
    const top = all.filter((f) => f.sev === 'critical' || f.sev === 'high');
    return h('div', { class: 'page' },
      helperNudge(),
      firstSteps(),
      h('section', { class: 'hero ' + tone + (r.score ? ' grade-' + r.score.grade.id : '') }, h('div', { class: 'gem-col' }, h('div', { class: 'gem' }, gem()), r.score ? scoreBadge(r.score) : null),
        h('div', null,
          h('div', { class: 'status', text: headline }),
          h('h1', { text: S.data.report.facts.meta ? S.data.report.facts.meta.computer : T('Этот компьютер') }),
          h('p', { text }),
          r.score ? h('p', { class: 'grade-text' }, h('b', { text: F('Чистота камня: {0}.', L(r.score.grade.title)) }), ' ', L(r.score.grade.text)) : null,
          h('div', { class: 'actions no-print' }, checkButtons()),
          h('div', { class: 'meta', text: F('Проверка: {0}', fmtDate(r.at)) + ' · ' + (r.full ? T('полная, с правами администратора') : r.fullAt ? F('обычная; сведения администратора от {0}', fmtDate(r.fullAt)) : T('обычная - часть сведений видна только после полной проверки')) }))),
      h('div', { class: 'tiles' }, SEV.map((s) => h('button', { class: 'tile ' + s, type: 'button', onclick: () => go('pc', s) }, h('b', { text: String(sum[s]) }), h('span', { text: SEV_LABEL[s]() })))),
      h('h2', { text: T('По разделам') }),
      h('div', { class: 'cats' }, [...CAT_ORDER, 'guard', 'network'].map((c) => {
        const list = all.filter((f) => f.cat === c);
        const w = c === 'network' && !netChecked() ? 'unknown' : worst(list);
        const issues = list.filter((f) => ['critical', 'high', 'advice'].includes(f.sev)).length;
        const sub = c === 'network' && !netChecked() ? T('ещё не проверялась') : issues ? F('замечаний: {0}', issues) : T('в порядке');
        return h('button', { class: 'cat', type: 'button', onclick: () => go(c === 'network' ? 'network' : c === 'guard' ? 'guard' : c === 'ports' ? 'ports' : c === 'autostart' ? 'autostart' : 'pc') },
          h('i', { class: 'dot ' + w }), h('div', null, h('b', { text: CAT_LABEL[c]() }), h('span', { text: sub })));
      })),
      calmStrip(),
      top.length ? [h('h2', { text: T('Главное') }), h('div', { class: 'findings' }, top.map((f) => findingCard(f)))] : null,
    );
  }

  function viewPc() {
    const r = report();
    if (!r) return emptyCheck();
    const list = pcFindings().filter((f) => S.filter === 'all' || f.sev === S.filter);
    const chips = h('div', { class: 'chips no-print' }, ['all', ...SEV].map((s) => {
      const n = s === 'all' ? pcFindings().length : pcFindings().filter((f) => f.sev === s).length;
      return h('button', { class: 'chip', type: 'button', 'aria-pressed': String(S.filter === s), onclick: () => { S.filter = s; render(); } }, `${s === 'all' ? T('Все') : SEV_LABEL[s]()} · ${n}`);
    }));
    return h('div', { class: 'page' },
      pageHead(T('Этот ПК'), F('Проверка: {0}', fmtDate(r.at)), ...checkButtons()),
      chips,
      CAT_ORDER.map((c) => {
        const items = list.filter((f) => f.cat === c);
        if (!items.length) return null;
        return [h('div', { class: 'group' }, h('h2', { text: CAT_LABEL[c]() }), h('span', { class: 'muted small', text: String(items.length) })), h('div', { class: 'findings' }, items.map((f) => findingCard(f)))];
      }),
      list.length ? null : h('div', { class: 'empty', text: T('Таких находок нет.') }),
    );
  }

  // ------------------------------------------------------------ Индекс и спокойствие
  /** Индекс под камнем: число, ступень чистоты и грани. */
  function scoreBadge(sc) {
    return h('div', { class: 'score' },
      h('b', { class: 'num', text: String(sc.value) }),
      h('span', { text: L(sc.grade.title) }),
      h('small', { text: F('граней: {0} из {1}', sc.facets.done, sc.facets.total) }));
  }

  /** Маленький график индекса за последние недели (SVG, без библиотек). */
  function sparkline(points) {
    const pts = (points || []).slice(-30);
    if (pts.length < 2) return null;
    const W = 220, H = 46, P = 4;
    const xy = pts.map((p, i) => [P + (i * (W - 2 * P)) / (pts.length - 1), H - P - (Math.max(0, Math.min(100, p.value)) / 100) * (H - 2 * P)]);
    const d = xy.map(([x, y], i) => (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1)).join(' ');
    const s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', `0 0 ${W} ${H}`);
    s.setAttribute('class', 'trend');
    s.setAttribute('aria-hidden', 'true');
    const area = document.createElementNS(SVGNS, 'path');
    area.setAttribute('d', d + ` L${xy[xy.length - 1][0].toFixed(1)} ${H - P} L${P} ${H - P} Z`);
    area.setAttribute('class', 'trend-area');
    const line = document.createElementNS(SVGNS, 'path');
    line.setAttribute('d', d);
    line.setAttribute('class', 'trend-line');
    const dot = document.createElementNS(SVGNS, 'circle');
    dot.setAttribute('cx', xy[xy.length - 1][0]);
    dot.setAttribute('cy', xy[xy.length - 1][1]);
    dot.setAttribute('r', '3');
    dot.setAttribute('class', 'trend-dot');
    s.append(area, line, dot);
    return s;
  }

  /** Полоса спокойствия на сводке: что говорит Страж, как менялась защита, сколько дней под присмотром. */
  function calmStrip() {
    const g = S.data.guard && S.data.guard.weekly;
    const hist = S.data.history || [];
    const first = hist.length ? Date.parse(hist[0].at) : null;
    const days = first ? Math.max(1, Math.round((Date.now() - first) / 86_400_000)) : 0;
    const delta = hist.length > 1 ? hist[hist.length - 1].value - hist[0].value : 0;
    return h('div', { class: 'calm' },
      awaySummary(),
      h('button', { class: 'calm-card ' + (g && !g.calm ? 'alarm' : 'quiet'), type: 'button', onclick: () => go('guard') },
        icon('eye'),
        h('div', null, h('b', { text: T('Страж') }), h('span', { text: g ? L(g.headline) : T('Страж начнёт наблюдение после первой проверки.') }))),
      h('div', { class: 'calm-card' },
        sparkline(hist) || icon('gem'),
        h('div', null,
          h('b', { text: days ? F('Под присмотром: {0} дн.', days) : T('Первая проверка') }),
          h('span', { text: hist.length > 1 ? (delta > 0 ? F('Индекс +{0} с первой проверки: защита крепнет.', delta) : delta < 0 ? F('Индекс −{0} с первой проверки: защита ослабла.', -delta) : T('Защита держится на том же уровне.')) : T('Здесь появится, как крепнет защита.') }))),
    );
  }

  /** Красная полоса тревоги (приманки тронуты) - на всех экранах, пока человек не нажмёт «Понятно». */
  function alertBanner() {
    const list = (S.data && S.data.alerts) || [];
    if (!list.length) return null;
    const a = list[0];
    const ack = btn(T('Понятно'), '', async () => {
      await api('/api/alerts/ack', {}).catch(() => {});
      await load();
      render();
    });
    const more = list.length > 1 ? h('p', { class: 'small', text: F('Ещё тревог: {0}', list.length - 1) }) : null;
    if (a.kind === 'guard') {
      const items = a.items || [];
      return h('div', { class: 'alarm-banner', role: 'alert' },
        icon('warn'),
        h('div', null,
          h('b', { text: T('Страж: важное изменение в системе') }),
          h('ul', { class: 'ev alarm-list' }, items.slice(0, 6).map((x) => h('li', null, L(x.text), x.detail ? h('span', { class: 'mono small', text: ' ' + x.detail }) : null)),
            items.length > 6 ? h('li', { text: F('Ещё {0}', items.length - 6) }) : null),
          h('p', { text: T('Если это сделали не вы и не программа, которую вы только что ставили, нажмите «Тревога»: компьютер отключится от сети, пока вы разбираетесь.') }),
          h('p', { class: 'small', text: F('Когда: {0}', fmtDate(a.at)) }), more),
        h('div', { class: 'banner-actions' },
          paid('panic') ? btn(T('Тревога'), 'danger', panicModal, 'alarm') : null,
          btn(T('Открыть Стража'), '', () => go('guard')), ack));
    }
    const files = (a.files || []).map((f) => (typeof f === 'string' ? f : f.path)).filter(Boolean);
    return h('div', { class: 'alarm-banner', role: 'alert' },
      icon('warn'),
      h('div', null,
        h('b', { text: T('Тревога: кто-то изменил файлы-приманки') }),
        h('p', { text: T('Так ведут себя программы-шифровальщики. Сейчас же отключите интернет (выньте кабель или выключите Wi-Fi), сохраните открытые документы и не выключайте компьютер. Затем проведите полную проверку антивирусом.') }),
        h('p', { class: 'small', text: F('Когда: {0}', fmtDate(a.at)) + (files.length ? ' · ' + files.join(', ') : '') }), more),
      h('div', { class: 'banner-actions' }, paid('panic') ? btn(T('Отключить от сети'), 'danger', panicModal, 'alarm') : null, ack));
  }

  // ------------------------------------------------------------ «Тревога»: отключить от сети
  function panicModal() {
    if (!paid('panic')) { go('settings'); return; }
    if (S.data.panic && S.data.panic.active) { toast(T('Компьютер уже отключён от сети.')); return; }
    modal((box, close) => {
      box.append(
        h('h2', { text: T('Отключить компьютер от сети?') }),
        h('p', { class: 'intro', text: T('Адамант выключит сетевой кабель и Wi-Fi в Windows. Вирус или чужой человек на удалённом доступе потеряют связь, а ваши файлы не уйдут в интернет. Ничего не удаляется: сеть возвращается одной кнопкой.') }),
        h('ul', { class: 'ev' },
          h('li', { text: T('Windows спросит разрешение администратора.') }),
          h('li', { text: T('Интернет пропадёт сразу: если пишете письмо или документ в браузере, сохраните его.') }),
          h('li', { text: T('Адамант запишет, какие программы запускались за последние 30 минут, - это поможет найти виновника.') })),
        h('div', { class: 'foot' }, btn(T('Отмена'), '', close), btn(T('Отключить от сети'), 'danger', () => { close(); runPanic('isolate'); }, 'alarm')));
    });
  }
  async function runPanic(mode) {
    if (S.panicBusy) return;
    S.panicBusy = mode;
    render();
    try {
      const r = await api('/api/panic', { mode });
      S.data.panic = r.panic;
      if (mode === 'isolate') {
        const p = r.panic || {};
        toast(p.active ? T('Компьютер отключён от сети.') : p.none ? T('Сеть и так не подключена.') : T('Не удалось отключить сеть. Выньте кабель или выключите Wi-Fi вручную.'), p.active ? 'ok' : 'error');
      } else {
        toast(r.ok ? T('Сеть включена.') : T('Не все адаптеры включились. Включите их в «Параметры» → «Сеть и Интернет».'), r.ok ? 'ok' : 'error');
      }
    } catch (e) {
      toast(T(e.message), 'error');
    } finally {
      S.panicBusy = null;
      await load().catch(() => {});
      render();
    }
  }
  const unsigned = (x) => x.signature && x.signature !== 'Valid' && x.signature !== 'unknown';
  function panicBanner() {
    const p = S.data && S.data.panic;
    if (!p || !p.active) return null;
    const procs = (p.processes || []).filter((x) => x.path);
    const odd = procs.filter(unsigned);
    return h('div', { class: 'panic-banner', role: 'status' },
      icon('alarm'),
      h('div', null,
        h('b', { text: T('Компьютер отключён от сети') }),
        h('p', { text: F('С {0}. Выключено: {1}.', fmtDate(p.at), (p.adapters || []).map((a) => a.name).join(', ')) }),
        h('p', { text: T('Что делать: сохраните документы, проведите полную проверку антивирусом, с другого устройства смените пароли, которые вводили недавно. Когда убедитесь, что всё чисто, верните сеть.') }),
        procs.length ? h('details', null,
          h('summary', { text: F('Программы, запущенные за 30 минут до тревоги: {0}', procs.length) + (odd.length ? ' · ' + F('без подписи: {0}', odd.length) : '') }),
          h('ul', { class: 'ev' }, procs.map((x) => h('li', { class: unsigned(x) ? 'warn-text' : null, text: `${fmtDate(x.started)} · ${x.name} · ${x.path}` + (unsigned(x) ? ' · ' + T('без подписи') : '') })))) : null,
        p.restoreFailed && p.restoreFailed.length ? h('p', { class: 'small warn-text', text: F('Не включились: {0}', p.restoreFailed.map((f) => f.name).join(', ')) }) : null),
      h('div', { class: 'banner-actions' },
        btn(T('Проверить антивирусом'), '', () => api('/api/open', { target: 'defenderupdate' }).catch((e) => toast(T(e.message), 'error')), 'shield'),
        btn(S.panicBusy === 'restore' ? T('Включаю сеть…') : T('Вернуть сеть'), 'primary', () => runPanic('restore'), 'network')));
  }

  // ------------------------------------------------------------ Страж в реальном времени
  function realtimeSwitch() {
    const on = S.data.settings.realtime !== false;
    return h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(on), 'aria-label': T('Страж в реальном времени'), onclick: () => saveSettings({ realtime: !on }) });
  }
  const REALTIME_TEXT = () => T('Раз в минуту Адамант сверяет автозагрузку, службы, задачи планировщика, администраторов, Microsoft Defender, файл hosts и прокси. Новое и подменённое - сразу тревога в окне и в трее. Работает, пока работает Адамант (окно или значок в трее), и почти не нагружает компьютер.');
  function realtimeSection() {
    if (!paid('realtime')) return [h('h2', { text: T('Страж в реальном времени') }), paidCard('realtime')];
    const rt = S.data.realtime || {};
    const on = S.data.settings.realtime !== false;
    const log = rt.log || [];
    return [
      h('div', { class: 'group' }, h('h2', { text: T('Страж в реальном времени') }),
        h('span', { class: 'muted small', text: !on ? T('выключен') : rt.ready ? T('следит') : T('запускается…') })),
      h('div', { class: 'card pad' },
        h('div', { class: 'setting' }, h('div', null, h('b', { text: T('Сразу сообщать о важных изменениях') }), h('p', { text: REALTIME_TEXT() })), realtimeSwitch()),
        log.length ? h('ul', { class: 'ev' }, log.slice(0, 15).map((e) => h('li', { text: `${fmtDate(e.at)} · ${L(e.text)}` + (e.detail ? ` · ${e.detail}` : '') })))
          : h('p', { class: 'muted small', text: T('Тревог пока не было.') })),
    ];
  }

  // ------------------------------------------------------------ Telegram
  const TG_EVENTS = [
    ['away', () => T('«Пока вас не было»: неверные пароли, чужие входы, запуск программ')],
    ['canary', () => T('Приманки: похоже на шифровальщика')],
    ['guard', () => T('Страж в реальном времени')],
    ['panic', () => T('Нажата «Тревога»')],
  ];
  function telegramCard() {
    if (!paid('telegram')) return [h('h2', { class: 'group', text: T('Уведомления в Telegram') }), paidCard('telegram')];
    const tg = S.data.telegram || {};
    const save = async (patch, msg) => {
      try {
        S.data.telegram = await api('/api/telegram', patch);
        if (msg) toast(msg, 'ok');
      } catch (e) {
        toast(T(e.message), 'error');
      }
      render();
    };
    const call = async (url, okMsg) => {
      if (S.tgBusy) return;
      S.tgBusy = url;
      render();
      try {
        const r = await api(url, {});
        S.data.telegram = r;
        if (url.endsWith('find-chat')) toast(r.found ? F('Чат найден: {0}', r.chatName || '?') : T('Боту пока никто не писал. Откройте бота в Telegram, нажмите «Запустить» и напишите ему что-нибудь.'), r.found ? 'ok' : '');
        else toast(okMsg, 'ok');
      } catch (e) {
        toast(T(e.message), 'error');
      } finally {
        S.tgBusy = null;
        render();
      }
    };
    const ready = tg.hasToken && tg.chat;
    return [
      h('h2', { class: 'group', text: T('Уведомления в Telegram') }),
      h('div', { class: 'card pad' },
        h('div', { class: 'setting' },
          h('div', null, h('b', { text: T('Тревоги на телефон') }), h('p', { text: T('Короткое сообщение в Telegram, когда Адамант поднимает тревогу. Уходит только текст тревоги - без отчётов, файлов и списков программ. Выключено, пока вы сами не включите.') })),
          h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(!!tg.enabled), 'aria-label': T('Уведомления в Telegram'), disabled: !ready,
            onclick: () => save({ enabled: !tg.enabled }, !tg.enabled ? T('Уведомления в Telegram включены.') : T('Уведомления в Telegram выключены.')) })),
        h('ol', { class: 'steps small' },
          h('li', { text: T('В Telegram откройте @BotFather, отправьте /newbot и придумайте имя - он пришлёт ключ бота.') }),
          h('li', { text: T('Вставьте ключ сюда и нажмите «Сохранить».') }),
          h('li', { text: T('Откройте своего бота, нажмите «Запустить» и напишите ему что-нибудь. Затем нажмите «Найти чат».') })),
        h('div', { class: 'license-key' },
          h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', class: 'tg-token', placeholder: tg.hasToken ? F('Ключ сохранён ({0})', tg.tokenHint) : '123456789:AAE…', 'aria-label': T('Ключ бота'), value: S.tgDraft || '', oninput: (e) => { S.tgDraft = e.target.value; } }),
          btn(T('Сохранить'), '', () => {
            const v = (S.tgDraft || '').trim();
            if (!v) { toast(T('Вставьте ключ бота'), 'error'); return; }
            S.tgDraft = '';
            save({ token: v }, T('Ключ бота сохранён.'));
          }, 'lock')),
        tg.hasToken ? h('div', { class: 'actions' },
          btn(S.tgBusy === '/api/telegram/find-chat' ? T('Ищу…') : tg.chat ? F('Чат: {0}. Найти заново', tg.chatName || '?') : T('Найти чат'), tg.chat ? '' : 'primary', () => call('/api/telegram/find-chat'), 'send'),
          tg.chat ? btn(S.tgBusy === '/api/telegram/test' ? T('Отправляю…') : T('Отправить проверку'), '', () => call('/api/telegram/test', T('Проверка отправлена. Посмотрите в Telegram.')), 'send') : null,
          btn(T('Забыть бота'), 'ghost', () => { if (confirm(T('Удалить ключ бота и чат с этого компьютера?'))) save({ forget: true }, T('Бот забыт.')); })) : null,
        tg.chat ? h('div', { class: 'tg-events' }, TG_EVENTS.map(([k, label]) => h('label', { class: 'check' },
          h('input', { type: 'checkbox', checked: !(tg.events && tg.events[k] === false), onchange: (e) => save({ events: { [k]: e.target.checked } }) }), h('span', { text: label() })))) : null,
        tg.lastError ? h('p', { class: 'warn-text small', text: F('Последняя отправка не удалась: {0}', fmtDate(tg.lastError.at)) })
          : tg.lastSentAt ? h('p', { class: 'muted small', text: F('Последнее сообщение: {0}', fmtDate(tg.lastSentAt)) }) : null,
        h('p', { class: 'muted small', text: T('Ключ бота хранится только на этом компьютере. Сообщения идут через серверы Telegram - включайте, только если вам это подходит.') })),
    ];
  }

  // ------------------------------------------------------------ Страж
  function viewGuard() {
    const r = report();
    if (!r) return emptyCheck();
    const g = S.data.guard || {};
    const w = g.weekly || null;
    const log = g.log || [];
    const facts = r.facts || {};
    const guardFindings = pcFindings().filter((f) => f.cat === 'guard');
    const pending = log.filter((e) => !e.ack && e.sev !== 'info');
    const stat = (n, label, tone) => h('div', { class: 'stat ' + (tone || '') }, h('b', { class: 'num', text: n == null ? '-' : String(n) }), h('span', { text: label }));
    const ack = async (ids) => {
      await api('/api/guard/ack', { ids }).catch((x) => toast(T(x.message), 'error'));
      await load();
      render();
    };
    return h('div', { class: 'page' },
      pageHead(T('Страж'), T('Следит, не изменилось ли что-то в системе без вашего ведома, и ищет следы взлома в журналах Windows. Работает во время проверок и не замедляет компьютер.'), ...checkButtons()),
      h('section', { class: 'watch has-kira ' + (w && !w.calm ? 'alarm' : 'quiet') },
        h('figure', { class: 'kira' },
          h('img', { src: 'img/kira-sword.jpg', alt: T('Кира, страж «Адаманта», в алмазных доспехах с мечом'), width: 188, height: 188, decoding: 'async' })),
        h('div', null,
          h('div', { class: 'status', text: w && !w.calm ? T('Есть на что посмотреть') : T('Всё спокойно') }),
          h('h2', { text: w ? L(w.headline) : T('Страж запомнил, как устроена система, и начнёт сравнивать со следующей проверки.') }),
          w ? h('div', { class: 'stats' },
            stat(w.attempts, T('попыток входа'), w.attempts ? 'high' : 'ok'),
            stat(w.attackers, T('чужих адресов'), w.attackers ? 'high' : 'ok'),
            stat(w.detections, T('угроз найдено'), w.detectionsActive ? 'critical' : w.detections ? 'advice' : 'ok'),
            stat(w.changes, T('изменений'), w.unacknowledged ? 'advice' : 'ok')) : null)),
      guardFindings.length ? [h('h2', { text: T('Следы атак и подозрительное') }), h('div', { class: 'findings' }, guardFindings.map((f) => findingCard(f)))] : null,
      realtimeSection(),
      h('div', { class: 'group' }, h('h2', { text: T('Что менялось в системе') }), h('span', { class: 'muted small', text: T('за 60 дней') })),
      log.length ? h('div', { class: 'card changes' }, log.slice(0, 80).map((e) => h('div', { class: 'change ' + e.sev + (e.ack ? ' acked' : '') },
        h('i', { class: 'dot ' + (e.sev === 'high' ? 'high' : e.sev === 'advice' ? 'advice' : 'unknown') }),
        h('div', null,
          h('b', { text: (GUARD_KIND[e.kind] ? GUARD_KIND[e.kind]() : e.kind) + ': ' + (GUARD_CHANGE[e.change] ? GUARD_CHANGE[e.change]() : e.change) }),
          h('span', { text: L(e.label) + (e.change === 'changed' && (e.from != null || e.to != null) ? ` (${L(e.from) || '-'} → ${L(e.to) || '-'})` : '') }),
          h('small', { class: 'muted', text: fmtDate(e.at) })),
        e.own ? h('span', { class: 'tag', text: T('сам «Адамант»') }) : e.ack ? h('span', { class: 'tag', text: T('это вы') }) : e.sev === 'info' ? null : btn(T('Это я'), 'small', () => ack([e.id])))))
        : h('div', { class: 'empty card', text: T('Пока ничего не менялось. Страж сравнивает систему при каждой проверке.') }),
      pending.length > 1 ? h('p', { class: 'actions bulk' }, btn(F('Отметить всё как «это я» ({0})', pending.length), 'small', () => ack(pending.map((e) => e.id)))) : null,
      awaySection(),
      presenceView(facts.physical && facts.physical.presence),
      privacyView(facts.privacy),
      usbView(facts.physical && facts.physical.usb),
    );
  }

  /** Когда пользовались компьютером: 14 дней по часам, неверный пароль - красным. */
  function presenceView(p) {
    const ev = (p && p.events) || [];
    if (!ev.length) return null;
    const days = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    for (let i = (p.days || 14) - 1; i >= 0; i--) days.push(new Date(today.getTime() - i * 86_400_000));
    const failed = ev.filter((e) => e.kind === 'failed-local').length;
    const locale = document.documentElement.lang === 'en' ? 'en-GB' : 'ru-RU';
    return [
      h('div', { class: 'group' }, h('h2', { text: T('Когда компьютером пользовались') }), h('span', { class: 'muted small', text: T('за 14 дней') })),
      h('p', { class: 'muted small lead', text: T('Каждая строка - день, каждая клетка - час. Цвет клетки - самое важное, что было в этот час; число - сколько раз вводили неверный пароль. Наведите на клетку, чтобы увидеть подробности.') }),
      h('div', { class: 'card pad presence' },
        h('div', { class: 'p-row' }, h('span'), h('div', { class: 'p-axis' }, ['0:00', '6:00', '12:00', '18:00'].map((x) => h('span', { text: x }))), h('span')),
        days.map((d, i) => {
          const start = d.getTime();
          const hours = Array.from({ length: 24 }, () => ({}));
          let dayFailed = 0;
          for (const e of ev) {
            const at = Date.parse(e.at);
            if (!(at >= start && at < start + 86_400_000)) continue;
            const hr = Math.min(23, Math.floor((at - start) / 3_600_000));
            hours[hr][e.kind] = (hours[hr][e.kind] || 0) + 1;
            if (e.kind === 'failed-local') dayFailed++;
          }
          return h('div', { class: 'p-row' },
            h('span', { class: 'p-day' + (i === days.length - 1 ? ' today' : ''), text: d.toLocaleDateString(locale, { weekday: 'short', day: 'numeric', month: 'short' }) }),
            h('div', { class: 'p-hours' }, hours.map((c, hr) => {
              const kind = PRESENCE_ORDER.find((k) => c[k]);
              const failedN = c['failed-local'] || 0;
              const tip = Object.keys(c).length
                ? F('{0}:00-{1}:00', hr, hr + 1) + '\n' + PRESENCE_ORDER.concat(Object.keys(c).filter((k) => !PRESENCE_ORDER.includes(k))).filter((k) => c[k]).map((k) => `${PRESENCE[k] ? PRESENCE[k]() : k}: ${c[k]}`).join('\n')
                : null;
              return h('i', { class: 'p-cell' + (kind ? ' ' + kind : '') + (kind === 'failed-local' && failedN < 3 ? ' few' : ''), title: tip, text: failedN ? (failedN > 99 ? '99+' : String(failedN)) : null });
            })),
            h('span', { class: 'p-count' + (dayFailed ? ' bad' : ''), title: dayFailed ? F('неверных паролей за день: {0}', dayFailed) : null, text: dayFailed ? String(dayFailed) : '' }));
        }),
        h('div', { class: 'p-legend' }, ['boot', 'wake', 'logon', 'unlock', 'failed-local'].map((k) => h('span', null, h('i', { class: 'p-cell ' + k }), PRESENCE[k]()))),
        failed ? h('div', { class: 'note warn' }, icon('warn'), h('div', { text: F('Неверный пароль на этом компьютере вводили {0} раз. Если это были не вы - смените пароль и не оставляйте компьютер без блокировки (Win+L).', failed) })) : null,
        p.admin === false ? h('p', { class: 'muted small', text: T('Входы и неверные пароли видны после полной проверки.') }) : null),
    ];
  }

  /** Кто пользовался камерой и микрофоном. */
  function privacyView(pv) {
    if (!pv) return null;
    const rows = [['webcam', 'camera', T('Камера')], ['microphone', 'mic', T('Микрофон')]].map(([k, ic, title]) => {
      const src = pv[k] && Array.isArray(pv[k].apps) ? pv[k].apps : Array.isArray(pv[k]) ? pv[k] : [];
      const list = src.filter((x) => x.start || x.inUse).sort((x, y) => String(y.start || '').localeCompare(String(x.start || ''))).slice(0, 8);
      return h('div', { class: 'card pad dev' }, h('div', { class: 'dev-head' }, icon(ic), h('b', { text: title })),
        list.length ? h('ul', { class: 'ev' }, list.map((x) => h('li', null, h('span', { text: x.name || x.app || x.path || '?' }), ' - ', h('span', { class: 'muted', text: x.inUse ? T('сейчас включено') : fmtDate(x.start) }))))
          : h('p', { class: 'muted small', text: T('Никто не пользовался.') }));
    });
    return [h('div', { class: 'group' }, h('h2', { text: T('Кто включал камеру и микрофон') })), h('div', { class: 'two' }, rows)];
  }

  /** Флешки и диски, которые подключали. */
  function usbView(list) {
    if (!list || !list.length) return null;
    return [
      h('div', { class: 'group' }, h('h2', { text: T('Флешки и диски, которые подключали') }), h('span', { class: 'muted small', text: String(list.length) })),
      h('div', { class: 'card table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { text: T('Устройство') }), h('th', { text: T('Впервые') }), h('th', { text: T('Последний раз') }))),
        h('tbody', null, list.slice(0, 15).map((u) => h('tr', null,
          h('td', null, u.name || '?', u.present ? [' ', h('span', { class: 'tag local', text: T('подключено') })] : null),
          h('td', { text: fmtDate(u.first) }), h('td', { text: fmtDate(u.last) })))))),
    ];
  }

  // ------------------------------------------------------------ Учения
  async function runDrills() {
    if (S.busy) return;
    S.busy = 'drills';
    render();
    try {
      const res = await api('/api/drills/run', {});
      await load();
      toast(L(res.headline), res.passed === res.total ? 'ok' : '');
    } catch (e) {
      toast(F('Учения не удались: {0}', T(e.message)), 'error');
    } finally {
      S.busy = null;
      render();
    }
  }

  async function toggleCanary(on) {
    try {
      await api('/api/canary', { on });
      await load();
      toast(on ? T('Приманки расставлены. Программа следит за ними.') : T('Приманки убраны.'), 'ok');
    } catch (e) {
      toast(T(e.message), 'error');
    }
    render();
  }

  function viewDrills() {
    const last = S.data.drills;
    const list = S.data.drillList || [];
    const results = new Map(((last && last.results) || []).map((x) => [x.id, x]));
    const cs = S.data.canary || {};
    const s = S.data.settings;
    const STATUS = { passed: [T('атака отражена'), 'ok'], failed: [T('атака прошла'), 'critical'], skipped: [T('не проводилась'), 'unknown'], error: [T('не удалась'), 'unknown'] };
    const running = S.busy === 'drills';
    return h('div', { class: 'page' },
      pageHead(T('Учения'), T('Проверяем, срабатывает ли защита на самом деле. Атака изображается безвредными тестовыми образцами, которые придуманы именно для этого. Ничего не ломается и не меняется.'),
        btn(running ? T('Идут учения…') : T('Провести учения'), 'primary', runDrills, 'target')),
      running ? h('div', { class: 'busy' }, h('div', { class: 'spinner' }, gem()), h('h2', { text: T('Идут учения…') }), h('p', { class: 'muted', text: T('Обычно это меньше минуты. Антивирус может показать уведомление о тестовой угрозе - так и должно быть.') })) : null,
      !running && last ? h('section', { class: 'watch ' + (last.passed === last.total ? 'quiet' : 'alarm') },
        h('div', { class: 'watch-eye' }, icon('target')),
        h('div', null, h('div', { class: 'status', text: F('Учения от {0}', fmtDate(last.at)) }), h('h2', { text: L(last.headline) }))) : null,
      running ? null : h('div', { class: 'drills' }, list.map((d) => {
        const res = results.get(d.id);
        const st = res ? STATUS[res.status] || STATUS.error : null;
        return h('article', { class: 'drill card pad ' + (st ? st[1] : '') },
          h('div', { class: 'drill-head' }, h('b', { text: L(d.title) }), st ? h('span', { class: 'sev ' + st[1], text: st[0] }) : h('span', { class: 'tag', text: T('ещё не проводилась') })),
          h('p', { text: L(d.what) }),
          d.why ? h('p', { class: 'muted small', text: L(d.why) }) : null,
          res && res.detail ? h('p', { class: 'small', text: L(res.detail) + (res.ms ? F(' · за {0} с', (res.ms / 1000).toFixed(1)) : '') }) : null,
          res && res.advice ? h('div', { class: 'note warn' }, icon('warn'), h('div', { text: L(res.advice) })) : null,
          res && res.status === 'failed' && (res.fix || res.guide || res.open) ? h('p', { class: 'actions' },
            res.fix ? btn(T('Исправить…'), 'primary small', () => openFix({ id: res.fix })) : null,
            res.guide ? btn(T('Как исправить'), 'small', () => openGuide(res.guide)) : null,
            res.open ? btn(T('Открыть настройки'), 'small', () => api('/api/open', { target: res.open }).catch((e) => toast(T(e.message), 'error'))) : null) : null);
      })),
      h('h2', { text: T('Приманки для шифровальщиков') }),
      h('div', { class: 'card pad' },
        h('div', { class: 'setting' },
          h('div', null,
            h('b', { text: T('Расставить приманки в «Документах» и на рабочем столе') }),
            h('p', { text: T('Программа положит туда по два скрытых файла. Вы их не увидите и трогать не будете, а шифровальщик обычно начинает именно с них. Если файл изменится, Адамант сразу поднимет тревогу. Компьютер это не нагружает: Windows сама сообщает об изменениях.') })),
          h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(!!s.canary), 'aria-label': T('Приманки для шифровальщиков'), onclick: () => toggleCanary(!s.canary) })),
        s.canary ? h('p', { class: 'small muted', text: F('Расставлено файлов: {0}. Последняя проверка: {1}.', (cs.files || []).length, fmtDate(cs.lastCheck)) }) : null,
        s.canary && !s.background ? h('div', { class: 'note warn' }, icon('warn'), h('div', { text: T('Приманки охраняются, только пока программа работает. Включите «Работа в фоне» в настройках - тогда Адамант будет следить и с закрытым окном.') })) : null),
    );
  }

  // ------------------------------------------------------------ Пока вас не было
  /** «18 нояб., 14:02-15:40» или «18 нояб., 23:10 - 19 нояб., 08:05». */
  function fmtSpan(from, to) {
    const locale = document.documentElement.lang === 'en' ? 'en-GB' : 'ru-RU';
    const a = new Date(from);
    const b = to ? new Date(to) : null;
    const day = (d) => d.toLocaleDateString(locale, { day: 'numeric', month: 'short' });
    const time = (d) => d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
    if (!b) return F('{0}, с {1}', day(a), time(a));
    return day(a) === day(b) ? `${day(a)}, ${time(a)}-${time(b)}` : `${day(a)}, ${time(a)} - ${day(b)}, ${time(b)}`;
  }

  async function ackAway(ids) {
    try {
      await api('/api/away/ack', { ids });
      await load();
    } catch (e) {
      toast(T(e.message), 'error');
    }
    render();
  }

  /** Карточка на сводке: что было, пока компьютер стоял заблокированным. */
  function awaySummary() {
    const a = S.data.away;
    if (!a || !a.enabled || !S.data.settings.away || !a.last) return null;
    const l = a.last;
    const tone = l.level === 'alarm' ? 'alarm' : l.level === 'attention' ? 'attention' : 'quiet';
    return h('button', { class: 'calm-card ' + tone, type: 'button', onclick: () => go('guard') },
      icon('clock'),
      h('div', null, h('b', { text: F('Пока вас не было: {0}', fmtSpan(l.from, l.to)) }), h('span', { text: L(l.headline) })));
  }

  function procLine(list, label) {
    if (!list.length) return null;
    return h('p', { class: 'small' }, h('b', { text: label }), list.slice(0, 30).map((p) => p.name).join(', ') + (list.length > 30 ? ' …' : ''));
  }
  function spanCard(sp) {
    const tone = sp.level === 'alarm' ? 'critical' : sp.level === 'attention' ? 'advice' : 'ok';
    const ev = (sp.events || []).filter((e) => e.text);
    const procs = sp.processes || [];
    const files = sp.files || { count: 0, sample: [] };
    const photos = sp.photos || [];
    const photoBox = h('div', { class: 'photos' }, photos.map((p) => btn(F('Фото {0}', fmtDate(p.at)), 'small', async (e) => {
      const b = e.currentTarget;
      try {
        const r = await api('/api/away/photo-data', { id: p.id });
        if (!r.data || !/^data:image\/jpeg;base64,/.test(r.data)) throw new Error(T('Фото не найдено'));
        b.replaceWith(h('img', { class: 'away-photo', src: r.data, alt: F('Фото {0}', fmtDate(p.at)) }));
      } catch (x) {
        toast(T(x.message), 'error');
      }
    }, 'camera')));
    return h('article', { class: 'card pad span ' + tone },
      h('div', { class: 'drill-head' },
        h('b', { text: fmtSpan(sp.from, sp.to) }),
        sp.active ? h('span', { class: 'tag', text: T('идёт сейчас') })
          : sp.confirmed ? h('span', { class: 'tag local', text: T('это были вы') })
            : h('span', { class: 'sev ' + tone, text: tone === 'critical' ? T('тревога') : tone === 'advice' ? T('посмотрите') : T('спокойно') })),
      h('p', { text: L(sp.headline) }),
      sp.note ? h('p', { class: 'muted small', text: L(sp.note) }) : null,
      ev.length ? h('ul', { class: 'timeline' }, ev.slice(0, 40).map((e) => h('li', { class: e.after ? 'after' : '' },
        h('time', { text: new Date(e.at).toLocaleTimeString(document.documentElement.lang === 'en' ? 'en-GB' : 'ru-RU', { hour: '2-digit', minute: '2-digit' }) }),
        h('span', { text: L(e.text) })))) : null,
      procLine(procs.filter((p) => !p.after), T('Запускали программы: ')),
      // После разблокировки «Адамант» ещё час следит (вдруг разблокировали не вы) - это отдельной строкой, чтобы не путать.
      procLine(procs.filter((p) => p.after), T('После разблокировки запускали (если разблокировали не вы): ')),
      files.count ? h('details', { class: 'small files' },
        h('summary', { text: F('Изменилось файлов: {0}', files.count) }),
        h('ul', { class: 'ev' }, (files.sample || []).slice(0, 50).map((f) => h('li', { class: 'mono', text: f.path })))) : null,
      (sp.usb || []).length ? h('p', { class: 'small' }, h('b', { text: T('Подключали: ') }), sp.usb.map((u) => [u.drive, u.label].filter(Boolean).join(' ')).join(', ')) : null,
      photos.length ? photoBox : null,
      !sp.active && !sp.confirmed && sp.level !== 'calm' ? h('p', { class: 'actions' }, btn(T('Это был я'), 'small', () => ackAway([sp.id]), 'check')) : null);
  }

  /** Раздел в «Страже»: включение, фото, отлучки за 14 дней. */
  function awaySection() {
    const a = S.data.away;
    const s = S.data.settings;
    const on = !!s.away;
    const head = h('div', { class: 'group' }, h('h2', { text: T('Пока вас не было') }), on ? h('span', { class: 'muted small', text: T('за 14 дней') }) : null);
    if (!paid('away')) return [head, paidCard('away')];
    const enable = () => saveSettings(on ? { away: false } : { away: true, background: true });
    const settingsCard = h('div', { class: 'card pad' },
      h('div', { class: 'setting' },
        h('div', null,
          h('b', { text: T('Следить, пока вас нет') }),
          h('p', { text: T('Когда вы блокируете компьютер (Win+L) или он засыпает, Адамант записывает, кто пытался войти, какие программы запускали, какие флешки подключали и какие файлы меняли. Когда вернётесь - покажет. Работает вместе со значком в трее и почти не тратит ресурсы. Всё хранится только на этом компьютере.') })),
        h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(on), 'aria-label': T('Следить, пока вас нет'), onclick: enable })),
      on ? h('div', { class: 'setting' },
        h('div', null,
          h('b', { text: T('Фото того, кто ввёл неверный пароль') }),
          h('p', { text: T('Камера сделает снимок, если кто-то ввёл неверный пароль, пока вас не было (не больше трёх за отлучку). Если на заблокированном экране Windows не даёт включить камеру, снимок будет сделан сразу после разблокировки. Фото хранится только на этом компьютере.') })),
        h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(!!s.awayPhoto), 'aria-label': T('Фото того, кто ввёл неверный пароль'), onclick: () => saveSettings({ awayPhoto: !s.awayPhoto }) })) : null,
      on && a && a.logonsVisible === false ? h('div', { class: 'note warn' }, icon('warn'), h('div', null,
        T('Неверные пароли и чужие входы видны только с правами администратора. Установите «Помощник администратора» - это одно разрешение Windows, дальше он сам будет сообщать о попытках входа.'), ' ',
        h('button', { class: 'btn ghost small', type: 'button', onclick: () => go('settings') }, T('В настройки')))) : null,
      on && !s.background ? h('div', { class: 'note warn' }, icon('warn'), h('div', { text: T('Включите «Работа в фоне» в настройках: без значка в трее Адамант не узнает, что вы заблокировали компьютер.') })) : null);
    const spans = on && a ? (a.spans || []) : [];
    return [
      head,
      settingsCard,
      on ? (spans.length ? h('div', { class: 'spans' }, spans.slice(0, 20).map(spanCard))
        : h('div', { class: 'empty card', text: T('Отлучек пока не было. Заблокируйте компьютер (Win+L), когда отходите, - здесь появится, что происходило без вас.') })) : null,
    ];
  }

  // ------------------------------------------------------------ Защита входа
  function viewEntry() {
    const r = report();
    if (!r) return emptyCheck();
    const p = S.data.bitlockerPlan;
    const steps = (p && p.steps) || [];
    const done = steps.filter((x) => x.state === 'done').length;
    const STATE = { done: [T('готово'), 'ok'], todo: [T('сделать'), 'high'], blocked: [T('недоступно'), 'unknown'], unknown: [T('не видно'), 'unknown'] };
    const more = pcFindings().filter((f) => /^(login-|phys-)/.test(f.id) && f.sev !== 'ok' && f.sev !== 'unknown');
    const openBtn = (o) => btn(L(o.label), 'small', () => api('/api/open', { target: o.id }).catch((e) => toast(T(e.message), 'error')));
    return h('div', { class: 'page' },
      pageHead(T('Защита входа'), T('Как не дать войти в компьютер в обход пароля Windows: с загрузочной флешки, через BIOS или вынув диск. Пароль Windows от этого не спасает - спасает шифрование диска с PIN при включении.'), ...checkButtons()),
      p ? h('section', { class: 'watch ' + (steps.length && done === steps.length ? 'quiet' : 'alarm') },
        h('div', { class: 'watch-eye' }, icon('lock')),
        h('div', null,
          h('div', { class: 'status', text: steps.length && done === steps.length ? T('Вход в обход Windows закрыт') : T('Вход в обход Windows открыт') }),
          h('h2', { text: L(p.headline) }))) : null,
      steps.length ? h('ol', { class: 'steps' }, steps.map((st, i) => {
        const [label, tone] = STATE[st.state] || STATE.unknown;
        return h('li', { class: 'step card pad ' + st.state },
          h('div', { class: 'step-num ' + tone }, st.state === 'done' ? icon('check') : String(i + 1)),
          h('div', null,
            h('div', { class: 'drill-head' }, h('b', { text: L(st.title) }), h('span', { class: 'sev ' + tone, text: label })),
            h('p', { text: L(st.text) }),
            st.state !== 'done' && (st.fix || st.guide || (st.open || []).length) ? h('p', { class: 'actions' },
              st.fix ? btn(T('Сделать…'), 'primary small', () => openFix(st.fix)) : null,
              st.guide ? btn(T('Как сделать'), 'small', () => openGuide(st.guide)) : null,
              (st.open || []).map(openBtn)) : null));
      })) : null,
      p && p.needsFullCheck ? h('div', { class: 'note' }, icon('info'), h('div', { text: T('Часть шагов видна только после полной проверки (кнопка «Проверить полностью») или с «Помощником администратора».') })) : null,
      h('div', { class: 'note warn' }, icon('warn'), h('div', { text: T('Перед шифрованием обязательно сохраните ключ восстановления: мастер Windows сам предложит это сделать. Без ключа при сбросе BIOS или замене платы диск не открыть.') })),
      more.length ? [h('h2', { text: T('Что ещё усилить') }), h('div', { class: 'findings' }, more.map((f) => findingCard(f)))] : null,
    );
  }

  function emptyCheck() {
    return h('div', { class: 'page' }, h('div', { class: 'empty' }, h('p', { text: T('Сначала проведите проверку.') }), h('p', null, btn(T('Проверить компьютер'), 'primary', () => runCheck(false), 'shield'))));
  }

  /** Оценка порта: подпись и цвет метки. */
  const VERDICT = {
    close: { cls: 'bad', label: () => T('Лучше закрыть') },
    unknown: { cls: 'warn', label: () => T('Проверьте') },
    optional: { cls: '', label: () => T('Можно закрыть') },
    normal: { cls: 'local', label: () => T('Нормально') },
    system: { cls: 'local', label: () => T('Часть Windows') },
    local: { cls: 'local', label: () => T('Только этот ПК') },
  };
  const kids = (...a) => a.flat(Infinity).filter((c) => c != null && c !== false);
  const portTitle = (x) => F('Порт {0} {1}', x.proto.toUpperCase(), x.port);

  function closePorts(items) {
    openFix({ id: 'port-block', arg: { items: items.map((c) => (c.kind === 'program' ? { kind: 'program', path: c.path } : { kind: 'port', proto: c.proto, port: c.port })) } });
  }
  function reopenPort(record) {
    const e = ((S.data && S.data.journal) || []).find((j) => j.record === record);
    if (e) confirmUndo(e);
  }

  /** Подробно о порте: что это, кто открыл, что будет, если закрыть. */
  function portModal(x) {
    modal((box, close) => {
      const v = VERDICT[x.info.verdict] || VERDICT.optional;
      box.append(...kids(
        h('h2', { text: `${portTitle(x)} - ${L(x.info.name)}` }),
        h('p', { class: 'intro' }, h('span', { class: 'tag ' + v.cls, text: v.label() })),
        h('p', { text: L(x.info.what) }),
        h('ul', { class: 'ev' },
          h('li', { text: F('Программа: {0}', x.proc || '-') }),
          x.path ? h('li', { class: 'muted small', text: x.path }) : null,
          x.services && x.services.length ? h('li', { text: F('Службы: {0}', x.services.join(', ')) }) : null,
          h('li', { text: x.scope === 'net' ? T('Ждёт подключений со всей сети') : x.scope === 'local' ? T('Ждёт подключений только с этого компьютера') : F('Ждёт подключений на адресе {0}', x.addrs.join(', ')) })),
        x.close && x.info.breaks ? h('div', { class: 'note' }, icon('info'), h('div', null, h('b', { text: T('Если закрыть') }), h('p', { text: L(x.info.breaks) }))) : null,
        x.why ? h('p', { class: 'muted', text: L(x.why) }) : null,
        h('div', { class: 'foot' },
          x.blocked ? btn(T('Открыть обратно…'), '', () => { close(); reopenPort(x.blocked); }) : null,
          !x.blocked && x.close ? btn(T('Закрыть порт…'), 'primary', () => { close(); closePorts([x.close]); }, 'lock') : null,
          btn(T('Понятно'), x.close && !x.blocked ? '' : 'primary', close)),
      ));
    });
  }

  /** «Закрыть лишнее»: Адамант отмечает то, что дома обычно не нужно, человек снимает галочки. */
  function closeExtraModal(list) {
    if (!paid('ports')) {
      return modal((box, close) => box.append(h('h2', { text: T('Закрыть лишнее') }), paidCard('ports'), h('div', { class: 'foot' }, btn(T('Понятно'), '', close))));
    }
    const groups = [
      { title: T('Лучше закрыть'), list: list.filter((x) => x.info.verdict === 'close'), on: () => true },
      { title: T('Можно закрыть, если не пользуетесь'), list: list.filter((x) => x.info.verdict === 'optional'), on: (x) => x.info.home },
      { title: T('Незнакомые программы'), list: list.filter((x) => x.info.verdict === 'unknown'), on: () => false },
    ].filter((g) => g.list.length);
    const picked = new Map();
    for (const g of groups) for (const x of g.list) picked.set(x, g.on(x));
    modal((box, close) => {
      const go2 = btn('', 'primary', () => {
        const items = [...picked].filter(([, on]) => on).map(([x]) => x.close);
        close();
        closePorts(items);
      }, 'lock');
      const count = () => {
        const n = [...picked.values()].filter(Boolean).length;
        go2.disabled = !n;
        go2.lastChild.textContent = F('Закрыть выбранные: {0}…', n);
      };
      go2.append(document.createTextNode(''));
      box.append(...kids(
        h('h2', { text: T('Закрыть лишнее') }),
        h('p', { class: 'intro', text: T('Адамант отметил порты, которые дома обычно не нужны. Снимите галочку с того, чем пользуетесь. Ничего не закроется, пока вы не подтвердите на следующем шаге.') }),
        groups.length ? groups.map((g) => h('div', { class: 'extra-group' },
          h('h3', { text: g.title }),
          g.list.map((x) => h('label', { class: 'check extra-item' },
            h('input', { type: 'checkbox', checked: picked.get(x) || null, onchange: (e) => { picked.set(x, e.target.checked); count(); } }),
            h('div', null,
              h('b', { text: `${portTitle(x)} - ${L(x.info.name)}` }),
              h('div', { class: 'muted small', text: x.proc || '' }),
              x.info.breaks ? h('div', { class: 'small', text: F('Если закрыть: {0}', L(x.info.breaks)) }) : null))))) : h('p', { class: 'muted', text: T('Лишнего нет: всё, что открыто в сеть, нужно Windows или уже закрыто.') }),
        h('div', { class: 'foot' }, btn(T('Отмена'), '', close), groups.length ? go2 : null),
      ));
      count();
    });
  }

  function oldPorts(facts) {
    const rows = new Map();
    for (const x of [...((facts.ports || {}).tcp || []), ...((facts.ports || {}).udp || [])]) {
      const k = `${x.proto}:${x.port}:${x.pid}`;
      if (!rows.has(k)) rows.set(k, { ...x, addrs: [] });
      rows.get(k).addrs.push(x.addr);
    }
    const items = [...rows.values()].map((x) => {
      const scope = x.addrs.some((a) => a === '0.0.0.0' || a === '::') ? 'net' : x.addrs.every((a) => /^127\./.test(a) || a === '::1') ? 'local' : 'addr';
      return { ...x, scope, info: { name: PORT_NAMES[x.port] || '-', what: '', verdict: scope === 'local' ? 'local' : null }, close: null, why: null, blocked: null };
    }).sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
    return { items, firewallOff: [] };
  }

  function viewPorts() {
    const r = report();
    if (!r) return emptyCheck();
    // Сервер старше окна (программу обновили, а сервер не перезапустили) - показываем порты без объяснений.
    const old = S.data.ports === undefined;
    const pi = old ? oldPorts(r.facts) : S.data.ports || { items: [], firewallOff: [] };
    const all = pi.items || [];
    const list = all.filter((x) => !S.portsNet || x.scope !== 'local');
    const findings = pcFindings().filter((f) => f.cat === 'ports' && f.sev !== 'ok');
    const open = all.filter((x) => x.scope !== 'local' && !x.blocked);
    const extra = open.filter((x) => x.close && ['close', 'optional', 'unknown'].includes(x.info.verdict));
    // Один порт у нескольких программ (например, 5353) считаем один раз.
    const n = (v) => new Set(open.filter((x) => x.info.verdict === v).map((x) => x.proto + ':' + x.port)).size;
    const blocked = all.filter((x) => x.blocked).length;
    return h('div', { class: 'page' },
      pageHead(T('Открытые порты'), T('Порт - это «дверь», через которую другие устройства подключаются к программе на этом компьютере. Нажмите на порт, чтобы узнать, что это и можно ли его закрыть.')),
      pi.firewallOff && pi.firewallOff.length ? h('div', { class: 'note warn' }, icon('warn'), h('div', { class: 'note-body' },
        h('b', { text: T('Брандмауэр выключен') }),
        h('p', { text: T('Пока он выключен, закрыть порты нельзя: к любой программе можно подключиться из сети.') }),
        h('div', { class: 'actions' }, btn(T('Включить брандмауэр…'), 'primary small', () => openFix({ id: 'firewall-on' }), 'shield')))) : null,
      findings.length ? h('div', { class: 'findings' }, findings.map((f) => findingCard(f))) : null,
      old ? h('div', { class: 'note' }, icon('info'), h('div', { text: T('Объяснения и кнопка «Закрыть» появятся, когда Адамант перезапустится.') })) : h('div', { class: 'card pad ports-sum' },
        h('div', { class: 'ports-counts' },
          [['close', T('лучше закрыть')], ['unknown', T('проверьте')], ['optional', T('можно закрыть')], ['normal', T('нормально')], ['system', T('часть Windows')]]
            .map(([v, label]) => h('div', { class: 'pc-' + v }, h('b', { class: 'num', text: String(n(v)) }), h('span', { text: label }))),
          blocked ? h('div', { class: 'pc-blocked' }, h('b', { class: 'num', text: String(blocked) }), h('span', { text: T('закрыл Адамант') })) : null),
        h('p', { class: 'muted small', text: T('Считаются только порты, к которым можно подключиться с других устройств. Закрытый порт не мешает программе работать на этом компьютере.') }),
        h('div', { class: 'actions' },
          btn(T('Закрыть лишнее…'), extra.length ? 'primary' : '', () => closeExtraModal(extra), paid('ports') ? 'shield' : 'lock'))),
      h('div', { class: 'toolbar' },
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: S.portsNet || null, onchange: (e) => { S.portsNet = e.target.checked; render(); } }), T('Только доступные из сети')),
        h('span', { class: 'muted small', text: F('Показано: {0}', list.length) })),
      h('div', { class: 'card table-wrap' }, h('table', { class: 'ports' },
        h('thead', null, h('tr', null, [T('Порт'), T('Что это'), T('Оценка'), T('Программа'), ''].map((x) => h('th', { text: x })))),
        h('tbody', null, list.map((x) => {
          const v = x.blocked ? { cls: 'local', label: () => T('Закрыт Адамантом') } : VERDICT[x.info.verdict] || { cls: '', label: () => '-' };
          return h('tr', { class: 'clickable' + (findings.some((f) => f.id === 'port-' + x.port) && !x.blocked ? ' warn' : ''), onclick: old ? null : () => portModal(x) },
            h('td', null, h('b', { class: 'num', text: String(x.port) }), h('div', { class: 'muted small', text: x.proto.toUpperCase() })),
            h('td', null, h('div', { text: L(x.info.name) }), h('div', { class: 'muted small clamp', text: L(x.info.what) })),
            h('td', null, h('span', { class: 'tag ' + v.cls, text: v.label() }),
              x.scope === 'addr' ? h('div', { class: 'muted small', title: x.addrs.join(', '), text: x.addrs.length > 2 ? F('{0} и ещё {1}', x.addrs[0], x.addrs.length - 1) : x.addrs.join(', ') }) : null),
            h('td', null, h('div', { text: x.proc || '-' }), h('div', { class: 'muted small', text: (x.services || []).join(', ') || x.path || F('процесс {0}', x.pid) })),
            h('td', { class: 'row-act' },
              x.blocked ? btn(T('Открыть обратно…'), 'small', (e) => { e.stopPropagation(); reopenPort(x.blocked); })
                : x.close && x.scope !== 'local' ? btn(T('Закрыть…'), 'small', (e) => { e.stopPropagation(); closePorts([x.close]); }) : null));
        })))),
    );
  }

  function viewAutostart() {
    const r = report();
    if (!r) return emptyCheck();
    const a = r.facts.autostart || { items: [] };
    const suspicious = new Set(pcFindings().filter((f) => f.id.startsWith('autostart-suspicious-')).map((f) => f.id));
    const findings = pcFindings().filter((f) => f.cat === 'autostart' && f.sev !== 'ok');
    const items = (a.items || []).slice().sort((x, y) => (x.state === y.state ? x.name.localeCompare(y.name) : x.state === 'off' ? 1 : -1));
    return h('div', { class: 'page' },
      pageHead(T('Автозагрузка'), T('Программы, которые запускаются при входе в Windows. «Отключить» не удаляет программу: Windows просто перестаёт её запускать - так же, как в «Диспетчере задач».')),
      findings.length ? h('div', { class: 'findings' }, findings.map((f) => findingCard(f))) : null,
      h('div', { class: 'card table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, [T('Программа'), T('Где записана'), T('Команда'), T('Состояние'), ''].map((x) => h('th', { text: x })))),
        h('tbody', null, items.map((i) => h('tr', { class: suspicious.has(`autostart-suspicious-${i.loc}-${i.name}`) ? 'warn' : null },
          h('td', null, h('b', { text: i.name })),
          h('td', { class: 'small', text: LOC_LABEL[i.loc] ? LOC_LABEL[i.loc]() : i.loc }),
          h('td', { class: 'cmd', text: i.command }),
          h('td', null, h('span', { class: 'tag ' + (i.state === 'off' ? 'off' : 'local'), text: i.state === 'off' ? T('Отключена') : T('Запускается') })),
          h('td', null, i.state !== 'off' && DISABLE_LOCS.includes(i.loc) ? btn(T('Отключить…'), 'small', () => openFix({ id: 'autostart-off', arg: { loc: i.loc, name: i.name } })) : null),
        ))))),
      items.length ? null : h('div', { class: 'empty', text: T('В автозагрузке ничего нет.') }),
    );
  }

  // ---------- Своя сеть
  async function loadSubnets() {
    try {
      S.subnets = await api('/api/net/subnets');
      if (!S.selected) S.selected = new Set(S.subnets.filter((s) => s.recommended).map((s) => s.id));
    } catch (e) {
      S.subnets = [];
      toast(T(e.message), 'error');
    }
    render();
  }

  function confirmScan() {
    const chosen = (S.subnets || []).filter((s) => S.selected.has(s.id));
    if (!chosen.length) return toast(T('Выберите хотя бы одну сеть.'));
    modal((box, close) => {
      box.append(
        h('h2', { text: T('Проверить свою сеть?') }),
        h('p', { class: 'intro', text: T('Программа по очереди подключится к адресам вашей сети и посмотрит, какие службы на них открыты. Она ничего не меняет на устройствах, не подбирает пароли и не трогает адреса за пределами вашей сети.') }),
        h('ul', null, chosen.map((s) => h('li', { text: F('{0}: адреса {1} - {2} ({3} шт.)', s.alias, s.first, s.last, s.count) }))),
        h('p', { class: 'muted small', text: T('Обычно это занимает до минуты. Антивирус или роутер могут заметить проверку - это нормально.') }),
        h('div', { class: 'foot' }, btn(T('Отмена'), '', close), btn(T('Начать проверку'), 'primary', () => { close(); startScan([...S.selected]); }, 'search')),
      );
    });
  }

  async function startScan(selected) {
    S.busy = 'scan';
    S.progress = { done: 0, total: 1 };
    render();
    const timer = setInterval(async () => {
      try {
        const p = await api('/api/net/progress');
        if (p.progress) {
          S.progress = p.progress;
          const bar = document.querySelector('.progress i');
          if (bar) bar.style.width = Math.min(100, Math.round((p.progress.done / Math.max(1, p.progress.total)) * 100)) + '%';
        }
      } catch { /* следующая попытка */ }
    }, 700);
    try {
      const r = await api('/api/net/scan', { selected });
      await load();
      // Имена, которые назвали устройства, - сразу в «Кто в сети».
      for (const hst of (r && r.result && r.result.hosts) || []) {
        const m = String(hst.mac || '').toUpperCase().replace(/:/g, '-');
        const d = hst.name && m && ((S.traffic && S.traffic.devices) || []).find((x) => x.mac === m);
        if (d) { d.name = hst.name; d.nameSource = hst.nameSource || null; }
      }
      toast(T('Проверка сети закончена.'), 'ok');
    } catch (e) {
      toast(F('Проверка сети не удалась: {0}', T(e.message)), 'error');
    } finally {
      clearInterval(timer);
      S.busy = null;
      S.progress = null;
      render();
    }
  }

  // ---------- Сеть и трафик
  function fmtBytes(n) {
    if (n == null || !Number.isFinite(n)) return '-';
    const u = [T('Б'), T('КБ'), T('МБ'), T('ГБ'), T('ТБ')];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
  }
  const NET_CATEGORY = { Public: () => T('общественная'), Private: () => T('частная (домашняя)'), DomainAuthenticated: () => T('рабочая (домен)') };
  const KIND_NET = { wifi: () => 'Wi-Fi', ethernet: () => T('Кабель'), vpn: () => 'VPN', other: () => T('Подключение') };
  const WIFI_SEC = { open: () => T('без пароля'), wep: () => T('WEP - слабая'), tkip: () => T('WPA-TKIP - слабая'), ok: () => T('WPA2/WPA3 - надёжная'), unknown: () => T('не удалось определить') };

  async function refreshTraffic() {
    if (S.trafficBusy) return;
    S.trafficBusy = true;
    render();
    try {
      S.traffic = await api('/api/net/traffic', {});
    } catch (e) {
      toast(F('Не удалось посмотреть сеть: {0}', T(e.message)), 'error');
    } finally {
      S.trafficBusy = false;
      render();
    }
  }
  async function loadTraffic() {
    S.trafficTried = true;
    try {
      const r = await api('/api/net/traffic');
      if (r && r.traffic) { S.traffic = r.traffic; render(); return; }
    } catch { /* обновим */ }
    refreshTraffic();
  }

  function connectionCards(tr) {
    const cards = (tr.adapters || []).filter((a) => a.kind !== 'virtual').map((a) => {
      const w = a.kind === 'wifi' && tr.wifi && tr.wifi.connected ? tr.wifi : null;
      const row = (k, v) => (v ? h('div', { class: 'kv' }, h('span', { text: k }), h('b', { text: v })) : null);
      return h('div', { class: 'card pad net-card ' + a.kind },
        h('div', { class: 'net-card-top' }, h('span', { class: 'tag', text: (KIND_NET[a.kind] || KIND_NET.other)() }), h('b', { text: w ? w.ssid : a.alias })),
        w ? row(T('Защита Wi-Fi'), (WIFI_SEC[w.security] || WIFI_SEC.unknown)()) : null,
        w && w.signal != null ? row(T('Сигнал'), `${w.signal}%` + (w.band ? ` · ${w.band}` : '') + (w.channel ? F(' · канал {0}', w.channel) : '')) : null,
        row(T('Адрес'), (a.ipv4 || []).join(', ')),
        row(T('Роутер (шлюз)'), a.gateway),
        row(T('DNS'), (a.dns || []).join(', ')),
        row(T('Тип сети'), a.category && NET_CATEGORY[a.category] ? NET_CATEGORY[a.category]() : a.category),
        a.kind !== 'vpn' ? row(T('Сейчас'), a.rxRate != null ? F('↓ {0}/с · ↑ {1}/с', fmtBytes(a.rxRate), fmtBytes(a.txRate)) : null) : null,
        a.kind !== 'vpn' ? row(T('С включения'), a.rxTotal != null ? F('↓ {0} · ↑ {1}', fmtBytes(a.rxTotal), fmtBytes(a.txTotal)) : null) : null,
        a.kind === 'vpn' ? h('p', { class: 'small muted', text: T('Трафик программ идёт через зашифрованный туннель VPN.') }) : null);
    });
    return cards.length ? h('div', { class: 'net-cards' }, cards) : h('div', { class: 'empty', text: T('Активных подключений не найдено.') });
  }

  const NAME_SOURCE = {
    mdns: () => T('назвало себя само'), netbios: () => T('имя компьютера Windows'), router: () => T('имя у роутера'), dns: () => T('из кэша DNS'),
  };

  /** Имя устройства: подпись пользователя, иначе имя, которое назвало устройство. */
  function deviceName(d) {
    if (d.label) return h('div', null, h('b', { text: d.label }), d.name && d.name !== d.label ? h('div', { class: 'muted small', text: d.name }) : null);
    if (d.name) return h('div', null, h('b', { text: d.name }), NAME_SOURCE[d.nameSource] ? h('div', { class: 'muted small', text: NAME_SOURCE[d.nameSource]() }) : null);
    return h('span', { class: 'muted', text: d.gateway ? T('Роутер') : '-' });
  }

  /** Подпись устройства из «Кто в сети» (по MAC) - для таблицы поиска устройств. */
  function labelFor(mac) {
    const m = String(mac || '').toUpperCase().replace(/:/g, '-');
    const d = m && ((S.traffic && S.traffic.devices) || []).find((x) => x.mac === m);
    return d ? d.label : null;
  }

  function labelDevice(d) {
    modal((box, close) => {
      const input = h('input', { type: 'text', maxlength: '40', value: d.label || '', placeholder: d.name || T('Например: телефон мамы'), 'aria-label': T('Подпись') });
      const save = async (value) => {
        try {
          const r = await api('/api/net/device-label', { mac: d.mac, label: value });
          for (const x of (S.traffic && S.traffic.devices) || []) if (x.mac === r.mac) x.label = r.label;
          close();
          render();
        } catch (e) { toast(e.message); }
      };
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(input.value); });
      box.append(
        h('h2', { text: T('Подписать устройство') }),
        h('p', { class: 'intro', text: F('{0} · MAC {1}', d.ip, d.mac) }),
        h('label', { class: 'field' }, h('span', { class: 'muted small', text: T('Как назвать это устройство') }), input),
        h('p', { class: 'muted small', text: T('Подпись хранится только на этом компьютере и привязана к MAC-адресу устройства.') }),
        h('div', { class: 'foot' },
          d.label ? btn(T('Убрать подпись'), '', () => save('')) : null,
          btn(T('Отмена'), '', close),
          btn(T('Сохранить'), 'primary', () => save(input.value), 'check')),
      );
      setTimeout(() => { input.focus(); input.select(); }, 0);
    });
  }

  function trafficView(tr) {
    const sp = tr.speed || {};
    const tile = (n, label) => h('div', { class: 'stat' }, h('b', { class: 'num', text: n }), h('span', { text: label }));
    const wifiFindings = pcFindings().filter((f) => /^wifi-/.test(f.id) && f.sev !== 'ok');
    const where = (o) => (o.remotes || []).map((x) => h('span', { class: 'chip ' + x.scope, title: x.ip + ':' + x.port, text: (x.host || x.ip) + (x.port && x.port !== 443 ? ':' + x.port : '') }));
    return [
      h('div', { class: 'stats net-stats' },
        tile(fmtBytes(sp.rx) + T('/с'), T('приходит сейчас')),
        tile(fmtBytes(sp.tx) + T('/с'), T('уходит сейчас')),
        tile(String(tr.counts.programs), T('программ в сети')),
        tile(String(tr.counts.internet), T('соединений с интернетом'))),
      h('h2', { class: 'group', text: T('Подключение') }),
      tr.vpn && tr.vpn.on ? h('div', { class: 'note' }, icon('lock'), h('div', { text: F('VPN включён: {0}. Сайты видят адрес VPN-сервера, а не ваш.', tr.vpn.names.join(', ')) })) : null,
      connectionCards(tr),
      h('h2', { class: 'group', text: T('Утечки и опасности') }),
      h('div', { class: 'findings' }, [...tr.findings, ...wifiFindings].map((f) => findingCard(f))),
      h('div', { class: 'group' }, h('h2', { text: T('Куда уходит трафик') }), h('span', { class: 'muted small', text: T('программы и адреса, с которыми они сейчас соединены') })),
      tr.outgoing.length ? h('div', { class: 'card table-wrap' }, h('table', { class: 'net-table' },
        h('thead', null, h('tr', null, [T('Программа'), T('Соединений'), T('Куда')].map((x) => h('th', { text: x })))),
        h('tbody', null, tr.outgoing.map((o) => h('tr', null,
          h('td', null, h('b', { text: o.name }), o.path ? h('div', { class: 'muted small mono', text: o.path }) : null),
          h('td', { class: 'num', text: o.internet === o.count ? String(o.count) : F('{0} (в интернет {1})', o.count, o.internet) }),
          h('td', null, h('div', { class: 'chips' }, where(o), o.more ? h('span', { class: 'muted small', text: F('ещё {0}', o.more) }) : null))))))) : h('div', { class: 'empty', text: T('Сейчас программы не соединены с сетью.') }),
      h('p', { class: 'muted small', text: tr.counts.dnsNames ? T('Имена сайтов взяты из кэша DNS этого компьютера; новых запросов программа не делает.') : T('Имена сайтов не видны: кэш DNS пуст (так бывает с VPN или защищённым DNS). Новых запросов программа не делает, поэтому показаны адреса.') }),
      h('div', { class: 'group' }, h('h2', { text: T('Кто подключается к вам') }), h('span', { class: 'muted small', text: T('входящие соединения и порты, открытые для сети') })),
      tr.incoming.length ? h('div', { class: 'card table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, [T('Программа'), T('Порт'), T('Откуда')].map((x) => h('th', { text: x })))),
        h('tbody', null, tr.incoming.map((i) => h('tr', null,
          h('td', { text: i.name }), h('td', { class: 'num', text: String(i.port) }),
          h('td', null, h('span', { class: 'chip ' + i.scope, text: i.host || i.ip }), h('span', { class: 'muted small', text: i.scope === 'internet' ? T(' из интернета') : T(' из вашей сети') }))))))) : h('p', { class: 'muted small', text: T('Сейчас к компьютеру никто не подключён.') }),
      tr.listening.length ? h('details', { class: 'card pad small' },
        h('summary', { text: F('Открытые порты: {0} (из них программ не Windows: {1})', tr.listening.length, tr.listening.filter((l) => !l.system).length) }),
        h('ul', { class: 'ev' }, tr.listening.map((l) => h('li', { text: F('{0}: порт {1}{2}', l.name, l.port, l.all ? T(', для всей сети') : F(', адрес {0}', l.addr)) })))) : null,
      tr.devices ? [
        h('div', { class: 'group' }, h('h2', { text: F('Кто в сети: {0}', tr.devices.length) }), h('span', { class: 'muted small', text: T('устройства, которые этот компьютер недавно видел в своей сети') })),
        tr.devices.length ? h('div', { class: 'card table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, [T('Имя'), T('Адрес'), T('MAC-адрес'), T('Что это')].map((x) => h('th', { text: x })))),
          h('tbody', null, tr.devices.map((d) => h('tr', null,
            h('td', { class: 'dev-name' }, deviceName(d), d.mac ? h('button', { class: 'icon-btn', type: 'button', title: T('Подписать устройство'), 'aria-label': T('Подписать устройство'), onclick: () => labelDevice(d) }, icon('edit')) : null),
            h('td', null, h('b', { class: 'num', text: d.ip }), d.isNew ? h('span', { class: 'tag new', text: T('новое') }) : null),
            h('td', { class: 'mono', text: d.mac || '-' }),
            h('td', { class: 'small', text: d.gateway ? T('Роутер') : d.randomMac ? T('Личный (случайный) MAC: обычно телефон или планшет') : T('Устройство') }))))))
          : h('div', { class: 'empty', text: T('Соседей в сети не видно.') }),
        tr.devices.some((d) => !d.label && !d.name) ? h('p', { class: 'muted small', text: T('Имя есть не у всех: телефоны и роутеры часто его не сообщают. Нажмите «Найти устройства» - программа спросит имя у самих устройств вашей сети. Или подпишите устройство сами (карандаш рядом с именем).') }) : null,
      ] : null,
    ];
  }

  // ---------- Чек-лист безопасности
  function loadChecklist() {
    S.checklistLoading = true;
    return api('/api/checklist')
      .then((r) => { S.checklist = r; })
      .catch((e) => toast(T(e.message), 'error'))
      .finally(() => { S.checklistLoading = false; render(); });
  }

  async function markChecklist(id, done) {
    try {
      S.checklist = await api('/api/checklist', { id, done });
    } catch (e) {
      toast(T(e.message), 'error');
    }
    render();
  }

  const checkDone = (i) => i.state === 'ok' || (!!i.marked && i.state !== 'todo');

  function checkItem(i) {
    const done = checkDone(i);
    const chip = i.state === 'ok' ? h('span', { class: 'chip ok', text: T('Проверено: в порядке') })
      : i.state === 'todo' ? h('span', { class: 'chip todo', text: T('Нужно сделать') })
        : i.marked ? h('span', { class: 'chip mine', text: T('Отмечено вами') })
          : h('span', { class: 'chip', text: i.auto ? T('Проверка не видит - отметьте сами') : T('Отметьте сами') });
    return h('div', { class: 'check-item' + (done ? ' done' : '') + (i.state === 'todo' ? ' todo' : '') },
      h('label', { class: 'cb', title: i.state === 'ok' ? T('Программа проверила: всё в порядке') : null },
        h('input', { type: 'checkbox', checked: done || null, disabled: i.state === 'ok' || null, 'aria-label': L(i.title), onchange: (e) => markChecklist(i.id, e.target.checked) })),
      h('div', { class: 'body' },
        h('b', { text: L(i.title) }),
        h('p', { class: 'muted small', text: L(i.why) }),
        h('details', null, h('summary', { text: T('Как сделать') }), h('p', { class: 'small', text: L(i.how) })),
        i.marked && i.state === 'todo' ? h('p', { class: 'small warn-text', text: T('Вы отметили пункт, но проверка видит, что он ещё не сделан.') }) : null),
      h('div', { class: 'ci-side no-print' }, chip,
        i.fix ? btn(T('Сделать автоматически'), 'primary small', () => openFix(i.fix), 'shield') : null,
        i.open && (S.data.openTargets || []).includes(i.open) ? btn(T('Открыть настройки'), 'small', () => api('/api/open', { target: i.open }).catch((e) => toast(T(e.message), 'error'))) : null));
  }

  function viewChecklist() {
    const r = report();
    const c = S.checklist;
    // Заново - при первом открытии, после новой проверки и после проверки Bluetooth (S.checklist = null).
    const forAt = r ? r.at : null;
    if ((!c || S.checklistFor !== forAt) && !S.checklistLoading && S.checklistTried !== `${forAt}|${!!c}`) {
      S.checklistTried = `${forAt}|${!!c}`;
      S.checklistFor = forAt;
      loadChecklist();
    }
    if (!c) return h('div', { class: 'page' }, pageHead(T('Чек-лист безопасности')), h('div', { class: 'busy' }, h('div', { class: 'spinner' }, gem())));
    const total = c.items.length;
    const doneN = c.items.filter(checkDone).length;
    const todo = c.items.filter((i) => i.state === 'todo').length;
    const bar = h('div', { class: 'progress' }, h('i'));
    bar.firstChild.style.width = Math.round((doneN / Math.max(1, total)) * 100) + '%';
    return h('div', { class: 'page' },
      pageHead(T('Чек-лист безопасности'), T('Главные правила защиты в одном списке. Что программа может проверить, она отмечает сама; что можно исправить кнопкой - исправляется кнопкой «Сделать автоматически». Остальное отметьте сами, когда сделаете.'),
        btn(T('Обновить'), '', loadChecklist, 'refresh')),
      h('div', { class: 'card pad check-progress' },
        h('div', null, h('b', { class: 'num', text: F('{0} из {1}', doneN, total) }), h('span', { class: 'muted', text: T(' пунктов сделано') })),
        bar,
        todo ? h('p', { class: 'small', text: F('Программа видит, что не сделано: {0}. Начните с них - они отмечены «Нужно сделать».', todo) }) : null,
        c.checked ? null : h('p', { class: 'small muted', text: T('Запустите проверку на «Сводке» - программа сама отметит то, что уже в порядке.') })),
      c.groups.map((g) => {
        const items = c.items.filter((i) => i.group === g.id);
        if (!items.length) return null;
        return [
          h('div', { class: 'group' }, h('h2', { text: L(g.title) }), h('span', { class: 'muted small', text: F('{0} из {1}', items.filter(checkDone).length, items.length) })),
          (g.intro || []).map((x) => h('details', { class: 'card pad explain' }, h('summary', { text: L(x.title) }), h('p', { text: L(x.text) }))),
          h('div', { class: 'checklist' }, items.map(checkItem)),
        ];
      }),
    );
  }

  // ---------- Bluetooth
  async function refreshBluetooth() {
    if (S.btBusy) return;
    S.btBusy = true;
    render();
    try {
      S.bluetooth = await api('/api/bluetooth', {});
      S.checklist = null;
      S.checklistTried = null;
    } catch (e) {
      toast(F('Не удалось проверить Bluetooth: {0}', T(e.message)), 'error');
    } finally {
      S.btBusy = false;
      render();
    }
  }

  async function loadBluetooth() {
    S.btTried = true;
    try {
      const r = await api('/api/bluetooth');
      if (r && r.bluetooth) { S.bluetooth = r.bluetooth; render(); return; }
    } catch { /* обновим */ }
    refreshBluetooth();
  }

  function signal(rssi) {
    if (rssi == null) return h('span', { class: 'muted', text: '-' });
    const lvl = rssi >= -60 ? 4 : rssi >= -70 ? 3 : rssi >= -80 ? 2 : 1;
    const where = rssi >= -60 ? T('совсем рядом') : rssi >= -75 ? T('в этой комнате') : T('дальше');
    return h('div', { class: 'sig-wrap' },
      h('span', { class: 'sig s' + lvl, 'aria-hidden': 'true' }, [1, 2, 3, 4].map(() => h('i'))),
      h('span', { class: 'small', text: `${rssi} dBm` }), h('div', { class: 'muted small', text: where }));
  }

  const BT_THREATS = [
    [() => T('Поддельная клавиатура'), () => T('Устройства вроде Flipper Zero и «BadUSB» притворяются Bluetooth-клавиатурой. Если такое устройство сопряжено, оно за секунды набирает команды: скачивает вирус или отправляет файлы. Держите в списке Bluetooth только свои устройства.')],
    [() => T('Навязчивые окна «Подключить»'), () => T('В людных местах кто-то может рассылать поддельные объявления, и на телефоне и компьютере всплывают окна «подключить наушники». Нажатие на «Подключить» сопрягает чужое устройство. Не соглашайтесь на сопряжение, которого не ждали.')],
    [() => T('Слежка с помощью меток'), () => T('AirTag, SmartTag и Tile подкладывают в сумку или машину, чтобы видеть, где человек. Если чужая метка встречается рядом снова и снова - проверьте вещи. Телефоны сами предупреждают о такой метке.')],
    [() => T('Уязвимости Bluetooth'), () => T('В драйверах Bluetooth время от времени находят ошибки, через которые можно взломать устройство без сопряжения. Обновляйте Windows и выключайте Bluetooth, когда он не нужен.')],
    [() => T('Чужие файлы'), () => T('Не принимайте файлы по Bluetooth от незнакомых: так передают вредоносные программы.')],
  ];

  function viewBluetooth() {
    if (!S.btTried) loadBluetooth();
    const b = S.bluetooth;
    const stat = (n, label, tone) => h('div', { class: 'stat ' + (tone || '') }, h('b', { class: 'num', text: n }), h('span', { text: label }));
    return h('div', { class: 'page' },
      pageHead(T('Bluetooth'), T('Какие устройства сопряжены с компьютером, кто рядом и чем это может грозить. Программа только слушает эфир несколько секунд: ничего не подключает и не сопрягает.'),
        btn(S.btBusy ? T('Слушаю эфир…') : T('Проверить снова'), 'primary', refreshBluetooth, 'refresh'),
        btn(T('Открыть настройки'), '', () => api('/api/open', { target: 'bluetooth' }).catch((e) => toast(T(e.message), 'error')))),
      !b ? h('div', { class: 'busy' }, h('div', { class: 'spinner' }, gem()), h('p', { class: 'muted', text: T('Слушаю эфир Bluetooth… Это занимает около 15 секунд.') })) : [
        h('p', { class: 'muted small', text: F('Обновлено: {0}', fmtDate(b.at)) }),
        h('div', { class: 'stats net-stats' },
          stat(!b.radio.present ? T('нет') : b.radio.on === false ? T('выключен') : T('включён'), b.adapter ? b.adapter.name : T('Bluetooth')),
          stat(String(b.counts.paired), T('сопряжено')),
          stat(String(b.counts.nearby), F('рядом за {0} с', b.seconds)),
          stat(String(b.counts.trackers), T('меток для поиска вещей'), b.counts.trackers ? 'advice' : '')),
        h('div', { class: 'findings' }, b.findings.map((f) => findingCard(f))),
        b.radio.present ? [
          h('div', { class: 'group' }, h('h2', { text: F('Сопряжённые устройства: {0}', b.paired.length) }), h('span', { class: 'muted small', text: T('устройства, которым вы разрешили подключаться к компьютеру') })),
          b.paired.length ? h('div', { class: 'card table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, [T('Имя'), T('Что это'), T('MAC-адрес')].map((x) => h('th', { text: x })))),
            h('tbody', null, b.paired.map((p) => h('tr', { class: p.attack ? 'row-bad' : null },
              h('td', null, h('b', { text: p.name || '-' }), p.le ? h('div', { class: 'muted small', text: 'Bluetooth LE' }) : null),
              h('td', { class: 'small', text: L(p.kindLabel) }),
              h('td', { class: 'mono', text: p.mac }))))))
            : h('div', { class: 'empty', text: T('Сопряжённых устройств нет.') }),
          h('div', { class: 'group' }, h('h2', { text: F('Рядом: {0}', b.nearby.length) }), h('span', { class: 'muted small', text: F('устройства Bluetooth LE, которые были слышны за {0} с; адреса многих устройств случайные и меняются', b.seconds) })),
          b.nearby.length ? h('div', { class: 'card table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, [T('Устройство'), T('Что это'), T('Сигнал'), T('Адрес')].map((x) => h('th', { text: x })))),
            h('tbody', null, b.nearby.map((d) => h('tr', { class: d.kind === 'attack' ? 'row-bad' : d.kind === 'tracker' ? 'row-warn' : null },
              h('td', null, h('b', { text: d.name || d.vendor || T('без имени') }), d.name && d.vendor ? h('div', { class: 'muted small', text: d.vendor }) : null, d.paired ? h('span', { class: 'tag', text: T('сопряжено') }) : null),
              h('td', { class: 'small', text: L(d.kindLabel) + (d.tracker ? ` (${d.tracker})` : '') }),
              h('td', null, signal(d.rssi)),
              h('td', null, h('span', { class: 'mono', text: d.addr }), d.random ? h('div', { class: 'muted small', text: T('случайный адрес') }) : null))))))
            : h('div', { class: 'empty', text: b.radio.on === false ? T('Bluetooth выключен - эфир не слушали.') : T('Рядом ничего не слышно.') }),
        ] : null,
      ],
      h('details', { class: 'card pad explain' }, h('summary', { text: T('Чем может грозить Bluetooth') }),
        h('ul', { class: 'threats' }, BT_THREATS.map(([title, text]) => h('li', null, h('b', { text: title() }), ' ', text())))),
    );
  }

  function viewNetwork() {
    if (!S.trafficTried) loadTraffic();
    if (!S.subnets && !S.subnetsLoading) { S.subnetsLoading = true; loadSubnets().finally(() => { S.subnetsLoading = false; }); }
    const tr = S.traffic;
    const sc = scan();
    const subs = S.subnets || [];
    const scanning = S.busy === 'scan';
    return h('div', { class: 'page' },
      pageHead(T('Сеть и трафик'), T('Как вы подключены, куда уходит и откуда приходит трафик, кто есть в вашей сети и нет ли утечек. Программа только смотрит: ничего не отправляет и не меняет.'),
        btn(S.trafficBusy ? T('Смотрю сеть…') : T('Обновить'), 'primary', refreshTraffic, 'refresh'),
        btn(T('Найти устройства'), '', confirmScan, 'search')),
      tr ? [h('p', { class: 'muted small', text: F('Обновлено: {0}', fmtDate(tr.at)) }), trafficView(tr)]
        : h('div', { class: 'busy' }, h('div', { class: 'spinner' }, gem()), h('p', { class: 'muted', text: T('Смотрю подключения и трафик… Это занимает около 10 секунд.') })),
      routerBlock(),
      h('div', { class: 'group' }, h('h2', { text: T('Поиск устройств и открытых служб') })),
      h('div', { class: 'note' }, icon('lock'), h('div', { text: T('Только обнаружение: обычные подключения к портам, заголовок веб-страницы и имя устройства (его спрашиваем у самого устройства и у вашего роутера). Никаких атак и подбора паролей. Адреса в интернете программа не проверяет.') })),
      subs.length ? h('div', { class: 'subnets' }, subs.map((s) => h('label', { class: 'subnet' },
        h('input', { type: 'checkbox', disabled: scanning || null, checked: S.selected.has(s.id) || null, onchange: (e) => { if (e.target.checked) S.selected.add(s.id); else S.selected.delete(s.id); } }),
        h('div', null, h('b', { text: s.alias }), h('div', { class: 'muted small', text: F('{0} · ваш адрес {1}{2}', s.id, s.address, s.gateway ? F(' · шлюз {0}', s.gateway) : '') }),
          s.virtual ? h('div', { class: 'small', text: T('Виртуальный адаптер или VPN. Проверяйте, только если это ваша сеть.') }) : null),
        h('span', { class: 'muted small', text: F('{0} адресов', s.count) }),
      ))) : h('div', { class: 'empty', text: T('Подключений к частной сети не найдено.') }),
      scanning ? h('div', { class: 'card pad' }, h('b', { text: T('Проверяю сеть…') }), h('div', { class: 'progress' }, h('i'))) : null,
      sc && !scanning ? [
        h('div', { class: 'group' }, h('h2', { text: T('Результат') }), h('span', { class: 'muted small', text: F('Проверка: {0}', fmtDate(sc.at)) })),
        h('div', { class: 'findings' }, sc.findings.map((f) => findingCard(f))),
        h('h2', { class: 'group', text: F('Устройства: {0}', sc.result.hosts.length) }),
        h('div', { class: 'card table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, [T('Адрес'), T('Имя'), T('Тип'), T('MAC-адрес'), T('Открытые порты'), T('Веб-страница')].map((x) => h('th', { text: x })))),
          h('tbody', null, sc.result.hosts.map((d) => h('tr', null,
            h('td', null, h('b', { class: 'num', text: d.ip }), d.gateway ? h('div', { class: 'muted small', text: T('шлюз') }) : null),
            h('td', null, deviceName({ ...d, gateway: false, label: labelFor(d.mac) })),
            h('td', { text: KIND_LABEL[d.kind] ? KIND_LABEL[d.kind]() : d.kind }),
            h('td', { class: 'mono', text: d.mac || '-' }),
            h('td', { class: 'small', text: d.open.length ? d.open.map((p) => (PORT_NAMES[p] ? `${p} ${PORT_NAMES[p]}` : String(p))).join(', ') : T('нет открытых') }),
            h('td', { class: 'small muted', text: d.http ? [d.http.title, d.http.server].filter(Boolean).join(' · ') || '-' : '-' }),
          ))))),
      ] : null,
    );
  }

  async function checkRouter() {
    if (S.routerBusy) return;
    S.routerBusy = true;
    render();
    try {
      S.data.router = await api('/api/net/router', {});
      S.checklist = null;
      S.checklistTried = null;
    } catch (e) {
      toast(F('Не удалось спросить роутер: {0}', T(e.message)), 'error');
    } finally {
      S.routerBusy = false;
      render();
    }
  }

  function routerBlock() {
    const rt = routerInfo();
    const maps = rt && rt.result && Array.isArray(rt.result.mappings) ? rt.result.mappings : [];
    return [
      h('div', { class: 'group' }, h('h2', { text: T('Роутер: что открыто в интернет') }), btn(S.routerBusy ? T('Спрашиваю роутер…') : T('Проверить роутер'), 'small', checkRouter, 'router')),
      h('div', { class: 'note' }, icon('lock'), h('div', { text: T('Программа спрашивает сам роутер по UPnP, какие порты он открыл в интернет. Запросы идут только внутри вашей сети; программа ничего не открывает и не закрывает.') })),
      rt ? [
        h('p', { class: 'muted small', text: F('Проверка: {0}', fmtDate(rt.at)) }),
        h('div', { class: 'findings' }, (rt.findings || []).map((f) => findingCard(f))),
        maps.length ? h('div', { class: 'card table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, [T('Протокол'), T('Порт в интернете'), T('Куда ведёт'), T('Описание')].map((x) => h('th', { text: x })))),
          h('tbody', null, maps.map((m) => h('tr', { class: m.enabled === false ? 'muted' : null },
            h('td', { text: m.proto }), h('td', { class: 'num', text: String(m.external) }),
            h('td', { class: 'mono', text: `${m.client || '?'}:${m.internal}` }),
            h('td', { class: 'small', text: m.description || '-' })))))) : null,
      ] : null,
    ];
  }

  // ---------- Обновление программ (winget)
  const UPGRADE_REASON = {
    'no-upgrade': () => T('новой версии для этой системы нет'), 'no-installer': () => T('нет установщика для этой системы'),
    'not-found': () => T('программа не найдена в каталоге'), pinned: () => T('обновление закреплено в winget'),
    reboot: () => T('готово, нужна перезагрузка'), running: () => T('закройте программу и повторите'),
    cancelled: () => T('отменено'), 'no-winget': () => T('нет winget'),
  };
  async function loadApps() {
    S.appsTried = true;
    try { S.apps = await api('/api/apps'); } catch { S.apps = null; }
    if (S.apps && S.apps.progress && S.apps.progress.running) pollApps();
    render();
  }
  async function findUpdates() {
    if (S.appsBusy) return;
    S.appsBusy = true;
    render();
    try {
      const list = await api('/api/apps/list', {});
      S.apps = { ...(S.apps || {}), list };
    } catch (e) {
      toast(F('Не удалось найти обновления: {0}', T(e.message)), 'error');
    } finally {
      S.appsBusy = false;
      render();
    }
  }
  function pollApps() {
    if (S.appsPoll) return;
    S.appsPoll = setInterval(async () => {
      try {
        const r = await api('/api/apps');
        S.apps = r;
        if (!r.progress.running) {
          clearInterval(S.appsPoll);
          S.appsPoll = null;
          const ok = r.progress.results.filter((x) => x.ok).length;
          toast(F('Обновление закончено: {0} из {1}.', ok, r.progress.total), ok === r.progress.total ? 'ok' : '');
        }
      } catch { /* сервер занят */ }
      if (S.view === 'apps') render();
    }, 2000);
  }
  function confirmUpgrade(items) {
    modal((box, close) => {
      box.append(
        h('h2', { text: items.length === 1 ? F('Обновить {0}?', items[0].name) : F('Обновить программы: {0}?', items.length) }),
        h('p', { class: 'intro', text: T('Адамант скачает и установит новые версии через winget из каталога Microsoft. Установщики работают тихо, без вопросов; для некоторых программ Windows спросит разрешение администратора.') }),
        h('ul', { class: 'ev' }, items.slice(0, 12).map((x) => h('li', { text: F('{0}: {1} → {2}', x.name, x.version, x.available) })), items.length > 12 ? h('li', { text: F('Ещё {0}', items.length - 12) }) : null),
        h('div', { class: 'note' }, icon('info'), h('div', { text: T('Закройте программы, которые обновляете, и сохраните открытые в них файлы. Нажимая «Обновить», вы принимаете условия каталога winget и лицензии этих программ.') })),
        h('div', { class: 'foot' }, btn(T('Отмена'), '', close), btn(T('Обновить'), 'primary', async () => {
          close();
          try {
            const p = await api('/api/apps/upgrade', { ids: items.map((x) => x.id) });
            S.apps = { ...(S.apps || {}), progress: p };
            pollApps();
          } catch (e) {
            toast(T(e.message), 'error');
          }
          render();
        }, 'download')));
    });
  }
  function progressBar(done, total) {
    const bar = h('div', { class: 'progress' }, h('i'));
    bar.firstChild.style.width = Math.round((done / Math.max(1, total)) * 100) + '%';
    return bar;
  }
  function upgradeLine(x) {
    if (x.ok) return F('{0} → {1}: обновлено{2}', x.name, x.available, x.reason === 'reboot' ? T(', нужна перезагрузка') : '');
    return F('{0}: {1}', x.name, UPGRADE_REASON[x.reason] ? UPGRADE_REASON[x.reason]() : F('не получилось (код {0})', x.hex || '?'));
  }
  function viewApps() {
    if (!S.appsTried) loadApps();
    const a = S.apps || {};
    const list = a.list;
    const p = a.progress || {};
    const items = list ? list.items || [] : [];
    const running = !!p.running;
    return h('div', { class: 'page' },
      pageHead(T('Обновление программ'), T('Старые версии программ - частая дверь для вирусов. Адамант находит программы, для которых вышла новая версия, и ставит её одной кнопкой через winget - встроенный в Windows установщик Microsoft.'),
        btn(S.appsBusy ? T('Ищу обновления…') : T('Найти обновления'), items.length ? '' : 'primary', findUpdates, 'refresh'),
        items.length && !running ? btn(T('Обновить всё'), 'primary', () => confirmUpgrade(items), 'download') : null),
      h('div', { class: 'note' }, icon('info'), h('div', { text: T('Чтобы узнать о новых версиях, winget спрашивает свой каталог у Microsoft. Это обычный запрос каталога: сведения о вас и ваших файлах не отправляются. Без вашей кнопки программа в интернет не обращается.') })),
      running ? h('div', { class: 'card pad' },
        h('b', { text: F('Обновляю {0} из {1}: {2}', Math.min(p.done + 1, p.total), p.total, p.current || '') }),
        progressBar(p.done, p.total),
        h('p', { class: 'muted small', text: T('Можно пользоваться компьютером. Если Windows спросит разрешение - это установщик программы.') })) : null,
      !running && p.results && p.results.length ? h('div', { class: 'card pad' },
        h('b', { text: F('Последнее обновление: {0} из {1}', p.results.filter((x) => x.ok).length, p.total) }),
        h('ul', { class: 'ev' }, p.results.map((x) => h('li', { class: x.ok ? null : 'warn-text', text: upgradeLine(x) })))) : null,
      !list ? h('div', { class: 'empty', text: S.appsBusy ? T('Спрашиваю каталог winget… Это занимает до минуты.') : T('Нажмите «Найти обновления», чтобы узнать, какие программы устарели.') })
        : !items.length ? h('div', { class: 'note ok' }, icon('check'), h('div', { text: F('Все программы, которые знает winget, обновлены. Проверка: {0}', fmtDate(list.at)) }))
        : [
          h('div', { class: 'group' }, h('h2', { text: F('Можно обновить: {0}', items.length) }), h('span', { class: 'muted small', text: F('Проверка: {0}', fmtDate(list.at)) })),
          h('div', { class: 'card table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, [T('Программа'), T('Сейчас'), T('Новая версия'), ''].map((x) => h('th', { text: x })))),
            h('tbody', null, items.map((x) => h('tr', null,
              h('td', null, h('b', { text: x.name }), h('div', { class: 'muted small mono', text: x.id })),
              h('td', { class: 'mono', text: x.version }),
              h('td', { class: 'mono', text: x.available }),
              h('td', { class: 'no-print' }, running ? null : btn(T('Обновить'), 'small', () => confirmUpgrade([x]), 'download'))))))),
        ],
    );
  }

  // ---------- Журнал исправлений
  function viewJournal() {
    const j = S.data.journal || [];
    return h('div', { class: 'page' },
      pageHead(T('Исправления'), T('Всё, что программа меняла по вашей команде. Каждое исправление можно откатить: прежние значения хранятся в папке, доступной только администраторам.')),
      j.length ? h('div', { class: 'findings' }, j.map((e) => h('article', { class: 'finding' },
        h('div', null,
          h('div', { class: 'top' }, h('span', { class: 'sev ' + (e.undoneAt ? 'unknown' : 'ok'), text: e.undoneAt ? T('Откачено') : T('Применено') }), h('h3', { text: L(e.title) })),
          h('p', { class: 'small', text: e.undoneAt ? F('Применено {0}, откачено {1}', fmtDate(e.at), fmtDate(e.undoneAt)) : F('Применено {0}', fmtDate(e.at)) }),
          h('div', { class: 'ev' }, diffTable(e.changes)),
          e.reboot && !e.undoneAt ? h('p', { class: 'small muted', text: T('Нужна перезагрузка, чтобы изменения вступили в силу.') }) : null),
        e.undoneAt ? null : h('div', { class: 'side-actions' }, btn(T('Откатить…'), 'small', () => confirmUndo(e))),
      ))) : h('div', { class: 'empty', text: T('Программа ещё ничего не меняла.') }),
    );
  }

  function confirmUndo(e) {
    modal((box, close) => {
      const foot = h('div', { class: 'foot' });
      const body = h('div', null, h('p', { class: 'intro', text: T('Программа вернёт значения, которые были до исправления. Windows попросит разрешение администратора.') }), diffTable((e.changes || []).map((c) => ({ what: c.what, from: c.to, to: c.from }))));
      const go2 = btn(T('Откатить'), 'primary', async () => {
        box.dataset.locked = '1';
        go2.disabled = true;
        go2.textContent = T('Ждём разрешения Windows…');
        try {
          const res = await api('/api/fix/undo', { record: e.record });
          delete box.dataset.locked;
          body.replaceChildren(resultView(res, true));
          foot.replaceChildren(btn(T('Закрыть'), 'primary', close));
          if (res.ok) {
            toast(T('Исправление откачено.'), 'ok');
            await load();
            runCheck(false);
          }
        } catch (err) {
          delete box.dataset.locked;
          go2.disabled = false;
          go2.textContent = T('Откатить');
          toast(err.code === 'CANCELLED' ? T('Вы отклонили запрос прав администратора. Ничего не изменилось.') : T(err.message), err.code === 'CANCELLED' ? '' : 'error');
        }
      });
      foot.append(btn(T('Отмена'), '', close), go2);
      box.append(h('h2', { text: F('Откатить: {0}', L(e.title)) }), body, foot);
    });
  }

  // ---------- Отчёт
  async function saveReport() {
    try {
      const r = await fetch('/api/report.html', { headers: { 'X-Adamant-Key': KEY } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const blob = await r.blob();
      const name = (/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '') || [])[1] || 'adamant-report.html';
      const a = h('a', { href: URL.createObjectURL(blob), download: name });
      document.body.append(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    } catch (e) {
      toast(T(e.message), 'error');
    }
  }

  function viewReport() {
    const r = report();
    if (!r) return emptyCheck();
    const all = allFindings();
    const meta = r.facts.meta || {};
    return h('div', { class: 'page' },
      pageHead(T('Отчёт о защите компьютера'), F('{0} · {1} · проверка {2}', meta.computer || '-', meta.osCaption || '', fmtDate(r.at)),
        btn(T('Печать или PDF'), '', () => window.print(), 'print'), btn(T('Сохранить отчёт'), 'primary', saveReport, 'download')),
      h('div', { class: 'tiles' }, SEV.map((s) => h('div', { class: 'tile ' + s }, h('b', { text: String(all.filter((f) => f.sev === s).length) }), h('span', { text: SEV_LABEL[s]() })))),
      SEV.map((s) => {
        const list = all.filter((f) => f.sev === s);
        if (!list.length) return null;
        return [h('div', { class: 'group' }, h('h2', { text: SEV_LABEL[s]() }), h('span', { class: 'muted small', text: String(list.length) })), h('div', { class: 'findings' }, list.map((f) => findingCard(f, { actions: false })))];
      }),
      h('p', { class: 'muted small', text: T('Отчёт составлен на этом компьютере и никуда не отправлялся.') }),
    );
  }

  // ---------- Настройки
  async function saveSettings(patch) {
    try {
      S.data.settings = await api('/api/settings', patch);
      setLang(S.data.settings.lang);
      if ('background' in patch) toast(patch.background ? T('Работа в фоне включена: значок появится в трее.') : T('Работа в фоне выключена.'), 'ok');
    } catch (e) {
      toast(T(e.message), 'error');
    }
    render();
  }


  // ------------------------------------------------------------ Помощник администратора
  async function loadHelper() {
    S.helperLoading = true;
    try {
      S.helper = await api('/api/helper');
    } catch {
      S.helper = null;
    }
    S.helperLoading = false;
    if (S.view === 'settings' || S.view === 'summary') render();
  }

  async function helperAction(kind) {
    if (S.busy) return;
    const update = kind === 'install' && !!(S.helper && S.helper.installed);
    S.busy = 'helper';
    render();
    try {
      const res = await api('/api/helper/' + kind, {});
      S.helper = res.status;
      toast(update ? T('Помощник администратора обновлён.') : kind === 'install' ? T('Помощник администратора установлен.') : T('Помощник администратора удалён.'), 'ok');
    } catch (e) {
      toast(e.code === 'CANCELLED' ? T('Разрешение администратора не получено') : T(e.message), 'error');
    } finally {
      S.busy = null;
      render();
    }
  }

  function helperCard() {
    const st = S.helper;
    if (st === undefined && !S.helperLoading) loadHelper();
    const busy = S.busy === 'helper';
    const intro = T('Проверяет то, что видно только администратору (BitLocker, журнал «Безопасность», исключения антивируса), раз в сутки и сразу после неудачного входа. Разрешение администратора нужно один раз - при установке. Сама программа прав администратора не получает: помощник лежит в защищённой папке и только читает.');
    let body;
    if (st === undefined || S.helperLoading) body = h('p', { class: 'muted small', text: T('Проверяю помощника…') });
    else if (!st || !st.installed) {
      body = [h('p', { text: intro }), h('p', { class: 'actions' }, btn(busy ? T('Устанавливаю…') : T('Установить помощника'), 'primary', () => helperAction('install'), 'shield'))];
    } else if (st.trusted && !st.problem) {
      body = [
        h('p', null, h('b', { text: T('Помощник работает.') }), ' ', F('Полная проверка: {0}. Журнал входов: {1}.', st.lastFull ? fmtDate(st.lastFull) : T('ещё не было'), st.lastSecurity ? fmtDate(st.lastSecurity) : T('ещё не было'))),
        h('p', { class: 'muted small', text: T('«Проверить полностью» теперь работает без окна разрешения Windows.') }),
        h('p', { class: 'actions' },
          st.outdated ? btn(T('Обновить помощника'), 'primary small', () => helperAction('install'), 'refresh') : null,
          btn(T('Удалить помощника'), 'small danger', () => helperAction('uninstall'))),
      ];
    } else {
      body = [
        h('div', { class: 'note warn' }, icon('warn'), h('div', { text: st.problem ? L(st.problem) : T('Помощник установлен, но программа ему не доверяет: файлы или права на папку изменены.') })),
        st.lastError ? h('p', { class: 'muted small', text: st.lastError.error }) : null,
        h('p', { class: 'actions' },
          btn(T('Установить заново'), 'primary small', () => helperAction('install'), 'refresh'),
          btn(T('Удалить помощника'), 'small danger', () => helperAction('uninstall'))),
      ];
    }
    return [h('h2', { class: 'group', text: T('Помощник администратора') }), h('div', { class: 'card pad' }, body)];
  }

  function viewSettings() {
    const s = S.data.settings;
    return h('div', { class: 'page' },
      pageHead(T('Настройки')),
      h('div', { class: 'card pad' },
        h('div', { class: 'setting' }, h('div', null, h('b', { text: T('Язык') }), h('p', { text: T('Язык окна, отчёта и уведомлений.') })),
          h('div', { class: 'lang' }, h('button', { type: 'button', 'aria-pressed': String(s.lang === 'ru'), onclick: () => saveSettings({ lang: 'ru' }) }, 'Русский'), h('button', { type: 'button', 'aria-pressed': String(s.lang === 'en'), onclick: () => saveSettings({ lang: 'en' }) }, 'English'))),
        h('div', { class: 'setting' }, h('div', null, h('b', { text: T('Работа в фоне') }), h('p', { text: T('Значок в трее, проверка раз в сутки и уведомление, только если появилось что-то критичное или важное. Проверка идёт с низким приоритетом и не мешает работе и играм. Значок запускается при входе в Windows для вашей учётной записи.') })),
          h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': String(!!s.background), 'aria-label': T('Работа в фоне'), onclick: () => saveSettings({ background: !s.background }) })),
        paid('realtime') ? h('div', { class: 'setting' }, h('div', null, h('b', { text: T('Страж в реальном времени') }), h('p', { text: REALTIME_TEXT() })), realtimeSwitch()) : null,
      ),
      telegramCard(),
      helperCard(),
      h('h2', { class: 'group', text: T('Версия') }),
      licenseCard(),
      h('h2', { class: 'group', text: T('О программе') }),
      h('div', { class: 'card pad' },
        h('p', null, h('b', { text: F('Адамант {0}', S.data.version) }), ' - ', T('проверка защиты компьютера с Windows и своей сети.')),
        updateBox(),
        h('p', { class: 'actions' }, btn(T('Показать знакомство снова'), 'small', () => { if (S.data.settings.stepsHidden) saveSettings({ stepsHidden: false }); welcomeModal(); }, 'gem')),
        h('p', { class: 'legend', text: LEGEND() }),
        h('ul', { class: 'ev' },
          h('li', { text: tgEnabled() ? T('Программа не собирает статистику. В интернет уходят только тревоги в ваш Telegram - вы это включили.') : T('Программа сама ничего не отправляет в интернет и не собирает статистику.') }),
          h('li', { text: T('Проверки только читают настройки. Изменения - только по кнопке «Применить», с разрешения администратора и с возможностью отката.') }),
          h('li', { text: T('Проверка сети - только частные адреса ваших адаптеров, без атак и подбора паролей.') })),
        h('p', { class: 'small muted', text: T('Связь с автором: вопросы, предложения и сообщения об уязвимостях.') }),
        h('div', { class: 'contacts' }, CONTACTS.map(([id, label, value]) => h('button', {
          type: 'button', class: 'contact', title: value,
          onclick: () => api('/api/open', { target: id }).catch((e) => toast(T(e.message), 'error')),
        }, h('b', { text: label() }), h('span', { text: value }))))),
    );
  }

  /** «Проверить обновления»: по кнопке спрашиваем у GitHub номер последней версии; скачивает браузер, ставит человек. */
  async function checkUpdate() {
    S.update = { busy: true };
    render();
    try {
      S.update = { res: await api('/api/update/check', {}) };
    } catch (e) {
      S.update = { error: e.message };
    }
    render();
  }
  function updateBox() {
    const u = S.update || {};
    const r = u.res;
    const lang = S.data.settings.lang === 'en' ? 'download-en' : 'download';
    const openPage = () => api('/api/open', { target: lang }).catch((e) => toast(T(e.message), 'error'));
    return h('div', { class: 'update-box' },
      h('div', { class: 'actions' }, btn(u.busy ? T('Проверяю…') : T('Проверить обновления'), 'small', u.busy ? null : checkUpdate, 'refresh')),
      r && r.newer ? h('div', { class: 'note warn' }, icon('download'), h('div', { class: 'note-body' },
        h('b', { text: F('Вышла новая версия: {0}', r.latest) }),
        h('p', { text: T('Скачайте установщик и запустите его поверх этой версии: настройки, проверки и журнал сохранятся.') }),
        h('div', { class: 'actions' }, btn(T('Открыть страницу загрузки'), 'primary small', openPage, 'download')))) : null,
      r && !r.newer ? h('p', { class: 'small', text: F('У вас последняя версия ({0}).', r.current) }) : null,
      u.error ? h('p', { class: 'small warn-text', text: T(u.error) }) : null,
      h('p', { class: 'small muted', text: T('По этой кнопке Адамант спрашивает у GitHub только номер последней версии. Сведения о вас и компьютере не отправляются. Сама программа обновления не скачивает и не ставит.') }));
  }

  /** Связь с автором (адреса заданы на сервере в OPEN_TARGETS, окно открывает только их). */
  const CONTACTS = [
    ['contact-telegram', () => 'Telegram', '@data_diver_ru'],
    ['contact-site', () => T('Сайт'), 'datadiver-ru.github.io'],
    ['contact-github', () => 'GitHub', 'datadiver-ru'],
    ['contact-mail', () => T('Почта'), 'data.diver.ru@gmail.com'],
  ];

  // ------------------------------------------------------------ Полная версия
  /** Открыт ли раздел полной версии (сервер проверяет то же самое сам). */
  const paid = (f) => !!(S.data && S.data.license && S.data.license.features && S.data.license.features[f]);
  const tgEnabled = () => !!(S.data && S.data.telegram && S.data.telegram.enabled && paid('telegram'));
  const buyFull = () => api('/api/open', { target: 'contact-telegram' }).catch((e) => toast(T(e.message), 'error'));

  /** Что даёт каждый раздел полной версии. */
  const PAID_INFO = {
    bluetooth: () => ({
      title: T('Bluetooth'),
      points: [
        T('Какие устройства сопряжены с компьютером и что это за устройства.'),
        T('Кто рядом: устройства в эфире, производитель, тип и сила сигнала.'),
        T('Предупреждение о Flipper Zero, BadUSB и рассылке поддельных окон «подключить наушники».'),
        T('Метки для поиска вещей (AirTag, SmartTag, Tile) совсем рядом с вами.'),
      ],
      free: T('В бесплатной версии программа проверяет главное: не сопряжено ли с компьютером устройство для атак.'),
    }),
    entry: () => ({
      title: T('Защита входа'),
      points: [
        T('Мастер «Закрыть вход в обход Windows» - по шагам, с проверкой каждого шага.'),
        T('Ключ восстановления BitLocker, PIN при включении, пароль BIOS/UEFI и порядок загрузки.'),
        T('Защита от загрузки с флешки и подмены специальных возможностей.'),
      ],
      free: T('Находки о входе в Windows видны в разделе «Этот ПК» и в бесплатной версии.'),
    }),
    drills: () => ({
      title: T('Учения'),
      points: [
        T('Безвредные учебные атаки: проверка, что антивирус и защита срабатывают на деле.'),
        T('Учебный вирус EICAR, сценарий AMSI, защита папок от шифровальщиков, взгляд соседа по сети.'),
        T('Приманки для шифровальщиков: тревога, как только кто-то тронет скрытые файлы.'),
      ],
    }),
    away: () => ({
      title: T('Пока вас не было'),
      points: [
        T('Пока компьютер заблокирован или спит, записывает неверные пароли, входы, запуск программ, флешки и изменения файлов.'),
        T('Фото того, кто ввёл неверный пароль (по желанию).'),
        T('Хронология отлучки и кнопка «Это был я».'),
      ],
    }),
    realtime: () => ({
      title: T('Страж в реальном времени'),
      points: [
        T('Новая программа в автозагрузке, новая служба или задача, новый администратор - тревога через минуту, а не при следующей проверке.'),
        T('Выключили Microsoft Defender, изменили файл hosts или включили прокси - сразу видно.'),
        T('Обновления программ и свои изменения Адаманта тревогу не поднимают.'),
      ],
      free: T('В бесплатной версии Страж сравнивает систему при каждой проверке.'),
    }),
    panic: () => ({
      title: T('Тревога'),
      points: [
        T('Одна кнопка отключает компьютер от сети: кабель и Wi-Fi.'),
        T('Список программ, запущенных за 30 минут до тревоги, и что делать дальше.'),
        T('Сеть возвращается кнопкой «Вернуть сеть».'),
      ],
    }),
    ports: () => ({
      title: T('Закрыть лишнее'),
      points: [
        T('Одна кнопка закрывает все лишние порты: Адамант сам отмечает, что дома обычно не нужно.'),
        T('Перед закрытием видно, что перестанет работать.'),
        T('Всё открывается обратно одной кнопкой.'),
      ],
      free: T('В бесплатной версии порты закрываются по одному: кнопка «Закрыть» у каждого порта.'),
    }),
    telegram: () => ({
      title: T('Уведомления в Telegram'),
      points: [
        T('Тревоги приходят на телефон: «Пока вас не было», приманки, Страж, «Тревога».'),
        T('Ваш собственный бот: ключ хранится только на этом компьютере.'),
        T('Выключено, пока вы сами не включите.'),
      ],
    }),
  };

  function paidCard(feature) {
    const info = PAID_INFO[feature]();
    return h('div', { class: 'card pad paid' },
      h('div', { class: 'paid-head' }, icon('lock'), h('div', null, h('b', { text: F('«{0}» - в полной версии', info.title) }), h('p', { class: 'muted small', text: T('Ключ проверяется на этом компьютере, без интернета.') }))),
      h('ul', { class: 'ev' }, info.points.map((p) => h('li', { text: p }))),
      info.free ? h('p', { class: 'muted small', text: info.free }) : null,
      h('div', { class: 'actions' },
        btn(T('Купить полную версию'), 'primary', buyFull, 'gem'),
        btn(T('У меня есть ключ'), '', keyModal, 'lock')));
  }

  /** Включить ключ (или убрать его - key = null). true - получилось. */
  async function setLicenseKey(key) {
    try {
      S.data.license = await api('/api/license', { key });
      S.licenseDraft = '';
      S.bluetooth = null;
      S.btTried = false;
      await load();
      toast(key ? T('Полная версия включена. Спасибо!') : T('Ключ убран. Работает бесплатная версия.'), 'ok');
      return true;
    } catch (e) {
      toast(T(e.message), 'error');
      return false;
    } finally {
      render();
    }
  }

  /** «У меня есть ключ»: поле для ключа сразу в окошке, где бы человек ни был. */
  function keyModal() {
    modal((box, close) => {
      const area = h('textarea', { rows: '4', spellcheck: 'false', placeholder: 'ADAMANT1.…', 'aria-label': T('Ключ полной версии') });
      const submit = async () => {
        const key = area.value.trim();
        if (!key) { toast(T('Вставьте ключ полной версии'), 'error'); area.focus(); return; }
        box.dataset.locked = '1';
        const ok = await setLicenseKey(key);
        delete box.dataset.locked;
        if (ok) close();
      };
      box.append(
        h('h2', { text: T('Ввести ключ') }),
        h('p', { class: 'muted', text: T('Вставьте ключ, который пришёл после покупки, и нажмите «Активировать». Ключ проверяется на этом компьютере, без интернета.') }),
        h('div', { class: 'license-key' }, area),
        h('div', { class: 'foot' }, btn(T('Отмена'), 'ghost', close), btn(T('Активировать'), 'primary', submit, 'lock')));
      setTimeout(() => area.focus(), 0);
    });
  }

  /** Закрытый раздел: что в нём есть; для Bluetooth - ещё и бесплатная проверка устройств для атак. */
  function lockedView(key, feature) {
    const v = VIEWS[key];
    let extra = null;
    if (feature === 'bluetooth') {
      if (!S.btTried) loadBluetooth();
      const b = S.bluetooth;
      extra = !b ? h('p', { class: 'muted', text: T('Проверяю сопряжённые устройства…') }) : [
        h('p', { class: 'muted small', text: F('Обновлено: {0}', fmtDate(b.at)) + ' · ' + F('Сопряжённые устройства: {0}', b.counts.paired) }),
        b.findings.length ? h('div', { class: 'findings' }, b.findings.map((f) => findingCard(f)))
          : h('div', { class: 'note ok' }, icon('check'), h('div', { text: !b.radio.present ? T('Bluetooth на этом компьютере нет') : T('Среди сопряжённых устройств нет устройств для атак.') })),
      ];
    }
    return h('div', { class: 'page' }, pageHead(v.label(), T('Этот раздел - в полной версии Адаманта.')), extra, paidCard(feature));
  }

  function licenseCard() {
    const l = S.data.license || {};
    const full = l.edition === 'full';
    const text = full
      ? (l.expires ? F('Ключ выдан: {0}. Действует до {1}.', l.licensee, l.expires) : F('Ключ выдан: {0}. Бессрочно.', l.licensee))
      : l.expired ? F('Срок ключа для {0} закончился {1}. Работает бесплатная версия.', l.licensee, l.expires)
        : T('Проверка, находки, исправления, Страж, сеть, роутер, расширения, скачанные файлы, обновление программ, чек-лист и отчёт работают полностью. В полной версии ещё Bluetooth, «Защита входа», «Учения» с приманками, «Пока вас не было», Страж в реальном времени, кнопка «Тревога» и уведомления в Telegram.');
    const setKey = setLicenseKey;
    return h('div', { class: 'card pad' },
      h('div', { class: 'setting' },
        h('div', null, h('b', { text: full ? T('Полная версия') : T('Бесплатная версия') }), h('p', { text })),
        full ? btn(T('Убрать ключ'), 'ghost', () => { if (confirm(T('Убрать ключ с этого компьютера? Разделы полной версии закроются.'))) setKey(null); }) : btn(T('Купить полную версию'), 'primary', buyFull, 'gem')),
      full ? null : h('div', { class: 'license-key' },
        h('textarea', { rows: '3', spellcheck: 'false', placeholder: 'ADAMANT1.…', 'aria-label': T('Ключ полной версии'), oninput: (e) => { S.licenseDraft = e.target.value; } }, S.licenseDraft || ''),
        btn(T('Активировать'), '', () => { if ((S.licenseDraft || '').trim()) setKey(S.licenseDraft.trim()); else toast(T('Вставьте ключ полной версии'), 'error'); }, 'lock')));
  }

  // ------------------------------------------------------------ Каркас
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && S.menuOpen) { S.menuOpen = false; render(); }
  });

  function go(view, filter) {
    S.menuOpen = false;
    S.view = view;
    if (filter) S.filter = filter;
    render(true);
  }

  function render(resetScroll) {
    const app = document.getElementById('app');
    if (S.error) {
      app.replaceChildren(h('div', { class: 'busy' }, h('div', { class: 'spinner' }, gem()), h('h2', { text: T('Адамант') }), h('p', { class: 'muted', text: S.error })));
      return;
    }
    if (!S.data) return;
    const prevMain = app.querySelector('.main');
    const scroll = !resetScroll && prevMain ? prevMain.scrollTop : 0;
    const all = allFindings();
    const urgent = (cat) => all.filter((f) => f.sev === 'critical' && (!cat || cat(f))).length;
    const important = (cat) => all.filter((f) => f.sev === 'high' && (!cat || cat(f))).length;
    const badge = (key) => {
      const cat = { pc: (f) => CAT_ORDER.includes(f.cat), guard: (f) => f.cat === 'guard', ports: (f) => f.cat === 'ports', autostart: (f) => f.cat === 'autostart', network: (f) => f.cat === 'network' }[key];
      if (!cat) return null;
      const c = urgent(cat);
      const hi = important(cat);
      return c ? h('span', { class: 'badge', text: String(c) }) : hi ? h('span', { class: 'badge high', text: String(hi) }) : null;
    };
    const navBtn = (k) => {
      const v = VIEWS[k];
      return h('button', { type: 'button', 'aria-current': S.view === k ? 'page' : null, onclick: () => go(k), title: v.nav ? v.label() : null }, icon(v.icon), (v.nav || v.label)(), v.paid && !paid(v.paid) ? h('span', { class: 'nav-lock', title: T('В полной версии') }, icon('lock')) : badge(k));
    };
    const navTree = () => h('nav', { class: 'nav', 'aria-label': T('Разделы') }, NAV_GROUPS.map((g) => h('div', { class: 'nav-group', role: 'group', 'aria-label': g.title ? g.title() : null },
      g.title ? h('div', { class: 'nav-title', 'aria-hidden': 'true', text: g.title() }) : null,
      g.views.filter((k) => VIEWS[k]).map(navBtn))));
    const alarmBtn = () => (paid('panic') ? h('button', { type: 'button', class: 'side-alarm' + (S.data.panic && S.data.panic.active ? ' on' : ''), title: T('Отключить компьютер от сети'), onclick: () => (S.data.panic && S.data.panic.active ? go('summary') : panicModal()) }, icon('alarm'), S.data.panic && S.data.panic.active ? T('Сеть отключена') : T('Тревога')) : null);
    const privacy = () => h('div', { class: 'privacy' }, icon('lock'), h('span', { text: tgEnabled() ? T('В интернет - только тревоги в ваш Telegram') : T('Ничего не отправляется в интернет') }));
    const langBtns = () => h('div', { class: 'lang' }, ['ru', 'en'].map((l) => h('button', { type: 'button', 'aria-pressed': String(S.data.settings.lang === l), onclick: () => saveSettings({ lang: l }) }, l.toUpperCase())));
    const side = h('aside', { class: 'side' },
      h('div', { class: 'brand' }, h('img', { src: '/favicon.png', alt: '' }), h('div', null, h('b', { text: T('АДАМАНТ') }), h('span', { text: T('защита компьютера') }))),
      navTree(),
      h('div', { class: 'side-foot' }, alarmBtn(), privacy(), langBtns()));
    // Узкое окно (половина экрана): боковой панели нет - вверху полоса с «Тревогой» и меню разделов.
    const cur = VIEWS[S.view];
    const topbar = h('header', { class: 'topbar no-print' },
      h('img', { src: '/favicon.png', alt: '' }),
      h('div', { class: 'tb-title' }, h('b', { text: T('АДАМАНТ') }), h('span', { text: cur ? (cur.nav || cur.label)() : '' })),
      h('div', { class: 'tb-actions' }, alarmBtn(),
        h('button', { type: 'button', class: 'menu-btn', 'aria-expanded': String(!!S.menuOpen), 'aria-controls': 'mnav', onclick: () => { S.menuOpen = !S.menuOpen; render(); } }, icon(S.menuOpen ? 'cross' : 'menu'), T('Разделы'))),
      S.menuOpen ? h('div', { class: 'mnav', id: 'mnav' }, navTree(), h('div', { class: 'mnav-foot' }, privacy(), langBtns())) : null);
    const backdrop = S.menuOpen ? h('div', { class: 'mnav-backdrop', onclick: () => { S.menuOpen = false; render(); } }) : null;
    const checking = S.busy === 'check' || S.busy === 'full';
    const showBusy = checking && (S.view === 'summary' || (!report() && ['pc', 'ports', 'autostart', 'report'].includes(S.view)));
    const view = VIEWS[S.view];
    const content = showBusy ? h('div', { class: 'page' }, busyView()) : view.paid && !paid(view.paid) ? lockedView(S.view, view.paid) : view.render();
    // Плавное появление - только при переходе в другой раздел, а не при каждом обновлении данных.
    const main = h('main', { class: resetScroll ? 'main enter' : 'main' }, panicBanner(), alertBanner(), content);
    app.replaceChildren(h('div', { class: 'shell' }, side, topbar, main, backdrop));
    main.scrollTop = scroll;
    if (S.busy === 'scan' && S.progress) {
      const bar = main.querySelector('.progress i');
      if (bar) bar.style.width = Math.round((S.progress.done / Math.max(1, S.progress.total)) * 100) + '%';
    }
  }

  // ------------------------------------------------------------ Запуск
  /** Заставка (index.html): держим, пока Кира поднимает меч и разгораются лучи, затем плавно убираем. */
  const SPLASH_FROM = performance.now();
  function hideSplash() {
    const sp = document.getElementById('splash');
    if (!sp || sp.classList.contains('out')) return;
    const quiet = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const wait = Math.max(0, (quiet ? 400 : 2300) - (performance.now() - SPLASH_FROM));
    setTimeout(() => {
      sp.classList.add('out');
      setTimeout(() => sp.remove(), 900);
    }, wait);
  }

  async function start() {
    setLang('ru');
    if (!KEY) {
      S.error = T('Откройте Адамант ярлыком на рабочем столе или в меню «Пуск».');
      hideSplash();
      return render();
    }
    try {
      await load();
    } catch (e) {
      S.error = e.status === 401 ? T('Окно устарело: программа была перезапущена. Откройте Адамант ярлыком ещё раз.') : F('Не удалось связаться с программой: {0}', e.message);
      hideSplash();
      return render();
    }
    render();
    hideSplash();
    // Первый запуск: знакомство, когда заставка уже ушла.
    if (!S.data.settings.introDone && !report()) setTimeout(welcomeModal, Math.max(0, 3300 - (performance.now() - SPLASH_FROM)));
    setInterval(async () => {
      try {
        const hb = await api('/api/heartbeat', {});
        // Тревога от приманок: показываем сразу, не дожидаясь действий человека.
        if (hb && typeof hb.alerts === 'number' && hb.alerts !== (S.data.alerts || []).length) {
          await load();
          render();
        }
      } catch { /* сервер перезапускается */ }
    }, 15_000);
    const r = report();
    if (!r || Date.now() - Date.parse(r.at) > 6 * 3600_000) runCheck(false);
  }
  start();
})();
