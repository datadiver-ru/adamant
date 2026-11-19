'use strict';
/**
 * Исправления, которые можно применить кнопкой. Здесь - описание для человека («что изменится»)
 * и проверка аргументов. Сами изменения и откат делает server/ps/fix.ps1 с правами администратора:
 * он знает только эти же исправления и свои команды из аргументов не берёт.
 */
const { tx, t } = require('./i18n');
const { arr } = require('./rules');

const yesNo = (v, on, off) => (v ? on : off);
const SID_RE = /^S-1-5-21-\d+-\d+-\d+-\d+$/;
const PROFILE_NAMES = { Domain: t('доменная сеть'), Private: t('частная сеть'), Public: t('общедоступная сеть') };
const AUTOSTART_LOCS =['HKLM-Run', 'HKLM-Run32', 'HKCU-Run', 'Startup-User', 'Startup-Common'];

const FIXES = {
  'firewall-on': {
    title: t('Включить брандмауэр Windows'),
    changes(f) {
      const profiles = arr(f.firewall && f.firewall.profiles).filter((p) => String(p.enabled) === 'False');
      return profiles.map((p) => ({ what: tx('Брандмауэр: профиль {0}', PROFILE_NAMES[p.name] || p.name), from: t('выключен'), to: t('включён') }));
    },
    commands: ['Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'],
    notes: [t('Правила для программ не меняются. Если какая-то программа перестанет принимать подключения из сети, Windows спросит, разрешить ли ей это.')],
  },
  'defender-realtime': {
    title: t('Включить защиту Microsoft Defender в реальном времени'),
    changes: () => [{ what: t('Защита Microsoft Defender в реальном времени'), from: t('выключена'), to: t('включена') }],
    commands: ['Set-MpPreference -DisableRealtimeMonitoring $false'],
    notes: [t('Если защиту выключила групповая политика или другой антивирус, Windows может не дать её включить - программа об этом скажет.')],
  },
  'smb1-off': {
    title: t('Отключить устаревший протокол SMBv1'),
    changes(f) {
      const s = f.smb || {};
      const out = [];
      if (s.server1 === true) out.push({ what: t('Сервер SMBv1'), from: t('включён'), to: t('выключен') });
      if (s.feature === 'Enabled' || (s.clientDriver && Number(s.clientStart) !== 4)) out.push({ what: t('Компонент Windows «Поддержка SMB 1.0»'), from: t('установлен'), to: t('удалён') });
      if (!out.length) out.push({ what: t('Сервер SMBv1'), from: t('проверяется'), to: t('выключен') });
      return out;
    },
    commands: ['Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force', 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'],
    notes: [t('Очень старые сетевые хранилища и принтеры (примерно до 2010 года) могут перестать открываться по сети.'), t('Чтобы компонент удалился полностью, может понадобиться перезагрузка.')],
  },
  'rdp-nla': {
    title: t('Включить проверку подлинности на уровне сети для RDP'),
    changes: (f) => [{ what: t('Проверка подлинности на уровне сети (NLA)'), from: yesNo(Number(f.rdp && f.rdp.nla) === 1, t('включена'), t('выключена')), to: t('включена') }],
    commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f'],
    notes: [t('Подключиться смогут только клиенты, которые поддерживают NLA: это все версии Windows начиная с 7.')],
  },
  'rdp-off': {
    title: t('Выключить удалённый рабочий стол'),
    changes: () => [{ what: t('Подключения к удалённому рабочему столу'), from: t('разрешены'), to: t('запрещены') }],
    commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f'],
    notes: [t('Если вы сами подключаетесь к этому компьютеру удалённо, после этого подключиться не получится.')],
  },
  'uac-on': {
    title: t('Включить контроль учётных записей (UAC)'),
    changes(f) {
      const u = f.uac || {};
      const out = [];
      if (Number(u.enableLua) === 0) out.push({ what: t('Контроль учётных записей (UAC)'), from: t('выключен'), to: t('включён') });
      if (Number(u.consentAdmin) === 0) out.push({ what: t('Запрос подтверждения для администраторов'), from: t('без запроса'), to: t('запрос на защищённом рабочем столе') });
      if (Number(u.secureDesktop) === 0) out.push({ what: t('Запрос на защищённом рабочем столе'), from: t('выключен'), to: t('включён') });
      return out;
    },
    commands: ['reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f', '… /v ConsentPromptBehaviorAdmin /d 5 (только если было 0)', '… /v PromptOnSecureDesktop /d 1'],
    notes: [t('Если UAC был выключен совсем, он заработает после перезагрузки.')],
  },
  'updates-on': {
    title: t('Включить обновления Windows'),
    changes(f) {
      const u = f.updates || {};
      const out = [];
      if (u.service === 'Disabled') out.push({ what: t('Служба «Центр обновления Windows»'), from: t('отключена'), to: t('вручную (как в Windows по умолчанию)') });
      if (Number(u.noAutoUpdate) === 1) out.push({ what: t('Политика «Не обновлять автоматически»'), from: t('включена'), to: t('удалена') });
      return out;
    },
    commands: ['Set-Service -Name wuauserv -StartupType Manual', 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v NoAutoUpdate /f'],
    notes: [t('После этого откройте «Центр обновления Windows» и нажмите «Проверить наличие обновлений».')],
  },
  'guest-off': {
    title: t('Отключить гостевую учётную запись'),
    changes: (f) => {
      const g = arr(f.accounts && f.accounts.users).find((u) => /-501$/.test(u.sid));
      return [{ what: tx('Учётная запись «{0}»', g ? g.name : 'Guest'), from: t('включена'), to: t('отключена') }];
    },
    commands: ['Disable-LocalUser -SID <SID гостя>'],
    notes: [t('Учётная запись не удаляется, её можно снова включить.')],
  },
  'admin-off': {
    title: t('Отключить встроенную учётную запись «Администратор»'),
    changes: (f) => {
      const a = arr(f.accounts && f.accounts.users).find((u) => /-500$/.test(u.sid));
      return [{ what: tx('Учётная запись «{0}»', a ? a.name : 'Administrator'), from: t('включена'), to: t('отключена') }];
    },
    commands: ['Disable-LocalUser -SID <SID встроенного администратора>'],
    notes: [t('Программа не даст отключить её, если вы работаете под ней или если других администраторов нет.')],
    arg(f) {
      const sid = f.meta && f.meta.userSid;
      if (!SID_RE.test(sid || '')) throw new Error(t('Не удалось определить вашу учётную запись'));
      return { userSid: sid };
    },
  },
  'autologon-off': {
    title: t('Выключить автоматический вход и удалить пароль из реестра'),
    changes: () => [
      { what: t('Автоматический вход'), from: t('включён'), to: t('выключен') },
      { what: t('Пароль автоматического входа в реестре'), from: t('записан'), to: t('удалён') },
    ],
    commands: ['reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f', 'reg delete "…\\Winlogon" /v DefaultPassword /f'],
    notes: [t('При включении компьютера Windows будет спрашивать пароль.'), t('Для отката прежнее значение хранится в папке, доступной только администраторам.')],
  },
  'autostart-off': {
    title: t('Отключить программу в автозагрузке'),
    changes: (f, a) => [{ what: tx('Автозагрузка: {0}', a.name), from: t('запускается'), to: t('отключена') }],
    commands: ['reg add "…\\Explorer\\StartupApproved\\…" /v <имя> /t REG_BINARY /d 03… /f'],
    notes: [t('Программа не удаляется: запись остаётся, Windows просто её не запускает. Так же отключает «Диспетчер задач».')],
    arg(f, a) {
      const items = arr(f.autostart && f.autostart.items);
      if (!a || !AUTOSTART_LOCS.includes(a.loc) || typeof a.name !== 'string') throw new Error(t('Неверная запись автозагрузки'));
      const item = items.find((i) => i.loc === a.loc && i.name === a.name);
      if (!item) throw new Error(t('Такой записи в автозагрузке уже нет - обновите проверку'));
      const sid = f.autostart.userSid || (f.meta && f.meta.userSid);
      if (!SID_RE.test(sid || '')) throw new Error(t('Не удалось определить вашу учётную запись'));
      return { loc: item.loc, name: item.name, userSid: sid };
    },
  },
  'port-block': {
    title: t('Закрыть порты брандмауэром'),
    changes: (f, a) => arr(a.items).map((i) => ({
      what: i.kind === 'program' ? tx('Программа «{0}»', i.name) : tx('Порт {0} {1} - {2}', i.proto.toUpperCase(), i.port, i.name),
      from: t('открыт для сети'),
      to: t('закрыт брандмауэром'),
    })),
    commands: ['New-NetFirewallRule -Group Адамант -Direction Inbound -Action Block -Protocol <TCP|UDP> -LocalPort <порт>', 'New-NetFirewallRule -Group Адамант -Direction Inbound -Action Block -Program <программа>   (если номер порта меняется)'],
    notes: (f, a) => [
      t('Программы не удаляются и не останавливаются: брандмауэр просто не пускает к ним подключения с других устройств.'),
      ...arr(a.items).filter((i) => i.breaks).map((i) => tx('{0}: {1}', i.kind === 'program' ? i.name : tx('порт {0}', i.port), i.breaks)),
      t('Открыть обратно можно кнопкой «Открыть обратно» у порта или в разделе «Исправления».'),
    ],
    arg: (f, a) => require('./ports').validateBlock(f, a),
    scriptArg: (a) => require('./ports').toScript(a),
  },
};

// ---------------------------------------------------------------- Защита от взлома (rules-deep.js) и физический доступ
{
  const { SAFE_ASR } = require('./rules-deep');
  const hard = (f) => (f && f.hardening) || {};
  const num = (v) => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
  const cur = (v, names) => (v == null ? t('не задано') : names && names[num(v)] ? names[num(v)] : String(v));
  const UNDO = t('Всё можно вернуть как было в разделе «Исправления».');
  const REBOOT = t('Начнёт действовать после перезагрузки.');
  /** Программы специальных возможностей, которые запускаются с экрана блокировки. Тот же список - в fix.ps1 ($IfeoExes). */
  const IFEO_EXES = ['sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe'];
  const MP_ONOFF = { 0: t('выключена'), 1: t('включена'), 2: t('только запись в журнал') };
  const CFA = { 0: t('выключен'), 1: t('включён'), 2: t('только запись в журнал'), 3: t('только защита дисков'), 4: t('только запись в журнал') };
  const ASR = { 0: t('выключено'), 1: t('блокировать'), 2: t('только запись в журнал'), 6: t('предупреждать') };

  Object.assign(FIXES, {
    'llmnr-off': {
      title: t('Выключить старый поиск имён в сети (LLMNR)'),
      changes: (f) => [{ what: t('Многоадресное разрешение имён (LLMNR)'), from: num(hard(f).llmnr) === 0 ? t('выключено') : t('включено'), to: t('выключено') }],
      commands: ['reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f'],
      notes: [t('Компьютеры и принтеры в сети по-прежнему находятся по имени через DNS. Очень старое устройство может перестать находиться по имени - тогда откройте его по адресу.'), UNDO],
    },
    'wdigest-off': {
      title: t('Запретить хранить пароль в памяти открытым текстом (WDigest)'),
      changes: (f) => [{ what: t('Хранение пароля для WDigest'), from: num(hard(f).wdigest && hard(f).wdigest.useLogonCredential) === 1 ? t('включено') : t('проверяется'), to: t('выключено') }],
      commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'],
      notes: [t('Чтобы пароль исчез из памяти, выйдите из Windows и войдите снова или перезагрузите компьютер.'), t('Если эту настройку включили не вы, на компьютере мог побывать взломщик: смените пароль Windows и проверьте компьютер антивирусом.'), UNDO],
    },
    'lsa-ppl-on': {
      title: t('Включить защиту паролей в памяти (защита LSA)'),
      changes: (f) => [{ what: t('Защита LSA (RunAsPPL)'), from: cur((hard(f).lsa || {}).runAsPPL), to: t('включена (2, без блокировки в прошивке)') }],
      commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 2 /f'],
      notes: [REBOOT, t('Включается без записи в прошивку (UEFI), поэтому откат работает полностью.'), t('Редкие старые программы, которые встраиваются во вход в Windows (некоторые считыватели смарт-карт, старые VPN), могут перестать работать. Тогда откатите исправление в разделе «Исправления» и перезагрузитесь.')],
      reboot: true,
      arg(f) {
        const build = num(hard(f).build) || num(f.meta && f.meta.osBuild) || 0;
        if (build < 22621) throw new Error(t('Нужна Windows 11 версии 22H2 или новее'));
        return null;
      },
    },
    'autorun-off': {
      title: t('Выключить автозапуск с флешек и дисков'),
      changes: (f) => {
        const a = hard(f).autorun || {};
        return [
          { what: t('Автозапуск для всех типов дисков (NoDriveTypeAutoRun)'), from: cur(a.machineDriveTypes), to: '255' },
          { what: t('Запуск autorun.inf (NoAutorun)'), from: cur(a.machineNoAutorun), to: '1' },
        ];
      },
      commands: ['reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f', 'reg add "…\\Policies\\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f'],
      notes: [t('Флешки и диски открываются как обычно, просто с них ничего не запускается само. Окно «Выберите, что делать с этим диском» больше не появится - открывайте диск в Проводнике.'), UNDO],
    },
    'remote-assistance-off': {
      title: t('Запретить приглашения «Удалённого помощника»'),
      changes: () => [{ what: t('Приглашения удалённому помощнику'), from: t('разрешены'), to: t('запрещены') }],
      commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f'],
      notes: [t('Если вам помогают через «Удалённый помощник» Windows, верните настройку в разделе «Исправления».')],
    },
    'ps2-off': {
      title: t('Удалить старый PowerShell 2.0'),
      changes: () => [{ what: t('Компонент Windows «PowerShell 2.0»'), from: t('установлен'), to: t('удалён') }],
      commands: ['Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'],
      notes: [t('Обычный PowerShell остаётся. Перестанут запускаться только очень старые сценарии, написанные для версии 2.0.'), t('Может понадобиться перезагрузка.'), UNDO],
    },
    'pua-on': {
      title: t('Блокировать нежелательные программы (Defender)'),
      changes: (f) => [{ what: t('Блокировка нежелательных программ'), from: cur((hard(f).mp || {}).pua, MP_ONOFF), to: t('включена') }],
      commands: ['Set-MpPreference -PUAProtection Enabled'],
      notes: [t('Defender будет останавливать программы с навязчивой рекламой и установщики с «довесками». Если он заблокирует нужную программу, её можно разрешить в «Безопасность Windows» → «Журнал защиты».'), UNDO],
    },
    'cloud-on': {
      title: t('Включить облачную защиту Defender'),
      changes: (f) => [{ what: t('Облачная защита (MAPS)'), from: cur((hard(f).mp || {}).maps, { 0: t('выключена'), 1: t('базовая'), 2: t('расширенная') }), to: t('расширенная') }],
      commands: ['Set-MpPreference -MAPSReporting Advanced'],
      notes: [t('Defender будет сверять незнакомые файлы с базой Microsoft в интернете.'), t('Если настройку не даёт изменить защита от подделки или политика, программа об этом скажет - тогда включите её в «Безопасность Windows».'), UNDO],
    },
    'cfa-on': {
      title: t('Включить защиту папок от программ-шантажистов'),
      changes: (f) => [{ what: t('Контролируемый доступ к папкам'), from: cur((hard(f).mp || {}).cfa, CFA), to: t('включён') }],
      commands: ['Set-MpPreference -EnableControlledFolderAccess Enabled'],
      notes: [
        t('Защита может мешать нужным программам сохранять файлы в «Документы», «Изображения» и на рабочий стол - например, старым играм или редакторам.'),
        t('Windows покажет уведомление, какая программа заблокирована. Её можно разрешить: «Безопасность Windows» → «Защита от программ-шантажистов» → «Разрешить работу приложения через контролируемый доступ к папкам».'),
        UNDO,
      ],
    },
    'asr-safe': {
      title: t('Включить правила, которые блокируют приёмы вирусов'),
      changes: (f) => {
        const rules = new Map(arr((hard(f).mp || {}).asr).filter((r) => r && r.id).map((r) => [String(r.id).toLowerCase(), num(r.action)]));
        const out = Object.keys(SAFE_ASR).filter((id) => rules.get(id) !== 1).map((id) => ({
          what: tx('Правило защиты: {0}', SAFE_ASR[id]), from: rules.has(id) ? cur(rules.get(id), ASR) : t('не задано'), to: t('блокировать'),
        }));
        return out.length ? out : [{ what: t('Правила защиты от приёмов вирусов'), from: t('проверяется'), to: t('блокировать') }];
      },
      commands: Object.keys(SAFE_ASR).map((id) => `Add-MpPreference -AttackSurfaceReductionRules_Ids ${id} -AttackSurfaceReductionRules_Actions Enabled`),
      notes: [
        t('Это осторожный набор правил: они почти не мешают обычной работе.'),
        t('С флешек перестанут запускаться неподписанные программы. Редкие надстройки Office, которые запускают другие программы, тоже могут перестать работать.'),
        t('Если правило заблокирует нужное, Windows покажет уведомление. При откате в разделе «Исправления» каждое правило вернётся к прежнему состоянию.'),
      ],
    },
    'driver-blocklist-on': {
      title: t('Блокировать известные уязвимые драйверы'),
      changes: (f) => [{ what: t('Список уязвимых драйверов Microsoft'), from: cur(hard(f).driverBlocklist, { 0: t('выключен'), 1: t('включён') }), to: t('включён') }],
      commands: ['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f'],
      notes: [REBOOT, t('Очень старые драйверы (некоторые утилиты для разгона и подсветки, старые защиты от читов в играх) могут перестать загружаться. Тогда откатите исправление в разделе «Исправления».')],
      reboot: true,
    },
    'ifeo-clean': {
      title: t('Убрать подмену специальных возможностей на экране входа'),
      changes: (f, a) => {
        const list = arr(f.physical && f.physical.accessibility);
        return arr(a && a.exes).map((exe) => {
          const e = list.find((x) => x && String(x.exe).toLowerCase() === String(exe).toLowerCase());
          return { what: tx('Перехват запуска {0}', exe), from: e && e.debugger ? String(e.debugger) : t('записан'), to: t('удалён') };
        });
      },
      commands: ['reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<программа>" /v Debugger /f'],
      notes: [
        t('Через такой перехват на экране входа вместо залипания клавиш или экранной клавиатуры открывается командная строка с полными правами - без пароля.'),
        t('Исправление убирает только перехват в реестре. Если подменён сам файл программы, восстановите системные файлы командой sfc /scannow.'),
        UNDO,
      ],
      arg(f, a) {
        const raw = arr(a && a.exes);
        if (!raw.length || raw.length > IFEO_EXES.length || !raw.every((x) => typeof x === 'string')) throw new Error(t('Не указаны программы специальных возможностей'));
        const hooked = arr(f.physical && f.physical.accessibility).filter((e) => e && typeof e.exe === 'string' && typeof e.debugger === 'string' && e.debugger.trim());
        const exes = [];
        for (const x of raw) {
          const canon = IFEO_EXES.find((n) => n.toLowerCase() === x.toLowerCase());
          if (!canon) throw new Error(t('Программа не из списка специальных возможностей'));
          if (!hooked.some((e) => e.exe.toLowerCase() === canon.toLowerCase())) throw new Error(t('Перехвата у этой программы уже нет - обновите проверку'));
          if (!exes.includes(canon)) exes.push(canon);
        }
        return { exes };
      },
    },
    'lock-timeout': {
      title: t('Блокировать компьютер после 10 минут бездействия'),
      changes: (f) => {
        const v = num((hard(f).lock || {}).inactivityTimeoutSecs);
        return [{ what: t('Автоблокировка при бездействии'), from: v ? tx('через {0} с', v) : t('не задана'), to: tx('через {0} с', 600) }];
      },
      commands: ['reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v InactivityTimeoutSecs /t REG_DWORD /d 600 /f'],
      notes: [t('Если к компьютеру 10 минут не прикасаться, он заблокируется. Чтобы продолжить, нужно ввести пароль или ПИН-код.'), t('Если уже стоит меньший срок, программа его не меняет.'), UNDO],
    },
  });
}

// ---------------------------------------------------------------- Вход в Windows (rules-login.js) и ПИН-код BitLocker (bitlocker-plan.js)
const LOGIN = (() => {
  const { LOCKOUT, FOREVER } = require('./rules-login');
  const login = (f) => (f && f.login) || {};
  const num = (v) => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
  const UNDO = t('Всё можно вернуть как было в разделе «Исправления».');
  const minsOf = (sec) => Math.max(1, Math.round(sec / 60));
  const lockFor = (sec) => (num(sec) == null ? t('проверяется') : num(sec) === FOREVER ? t('до разблокировки администратором') : tx('{0} мин', minsOf(num(sec))));
  const FVE = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE';
  /** Значения политики BitLocker: 0 - не разрешать, 1 - требовать, 2 - разрешать (как в gpedit.msc). */
  const FVE_NAMES = { 0: t('не разрешать'), 1: t('требовать'), 2: t('разрешать') };
  const fveShown = (v) => (num(v) == null ? t('не задано') : FVE_NAMES[num(v)] || String(v));
  const FVE_WHAT = {
    UseAdvancedStartup: t('Политика BitLocker: дополнительная проверка при запуске'),
    UseTPMPIN: t('Политика BitLocker: ПИН-код вместе с TPM'),
    UseTPM: t('Политика BitLocker: только TPM, без ПИН-кода'),
    UseTPMKey: t('Политика BitLocker: TPM и флешка-ключ'),
    UseTPMKeyPIN: t('Политика BitLocker: TPM, флешка-ключ и ПИН-код'),
  };
  const FVE_FIELDS = { UseAdvancedStartup: 'useAdvancedStartup', UseTPMPIN: 'useTpmPin', UseTPM: 'useTpm', UseTPMKey: 'useTpmKey', UseTPMKeyPIN: 'useTpmKeyPin' };

  /** Политика FVE из сведений: раздел login (читается без прав администратора) или physical. */
  function fvePolicy(f) {
    const a = login(f).bitlocker && login(f).bitlocker.policy;
    const b = f && f.physical && f.physical.bitlocker && f.physical.bitlocker.policy;
    return a || b || null;
  }
  /**
   * Что запишет bitlocker-pin-policy. Та же логика - в fix.ps1 (Fve-Specs):
   * UseAdvancedStartup = 1; если ПИН-код уже «требуется» (1) - больше ничего не трогаем;
   * иначе UseTPMPIN = 2, а UseTPM, UseTPMKey, UseTPMKeyPIN без значения или «требовать» → 2 («не разрешать» остаётся).
   */
  function fveSpecs(p) {
    const v = (name) => num(p ? p[FVE_FIELDS[name]] : null);
    const out = [{ name: 'UseAdvancedStartup', value: 1 }];
    if (v('UseTPMPIN') !== 1) {
      out.push({ name: 'UseTPMPIN', value: 2 });
      for (const n of ['UseTPM', 'UseTPMKey', 'UseTPMKeyPIN']) if (v(n) == null || v(n) === 1) out.push({ name: n, value: 2 });
    }
    return out.map((s) => ({ ...s, from: v(s.name), changed: v(s.name) !== s.value }));
  }
  /** Разрешает ли политика ПИН-код при запуске (мастер BitLocker тогда предложит «Ввести ПИН-код»). */
  function pinAllowed(p) {
    if (!p) return null;
    const v = (k) => num(p[k]);
    return v('useAdvancedStartup') === 1 && [1, 2].includes(v('useTpmPin')) && (v('useTpmPin') === 1 || ![v('useTpm'), v('useTpmKey'), v('useTpmKeyPin')].includes(1));
  }
  /** Выпуск Windows: 'home' (EditionID Core…), 'pro' (Pro, Enterprise, Education…) или 'unknown'. */
  function edition(f) {
    const id = String((login(f).edition && login(f).edition.id) || (f && f.meta && f.meta.edition) || '');
    const cap = String((f && f.meta && f.meta.osCaption) || '');
    if (id) {
      if (/^core/i.test(id)) return 'home';
      if (/^(professional|enterprise|education|iotenterprise|server)/i.test(id)) return 'pro';
      return 'unknown';
    }
    if (/home|домашн/i.test(cap)) return 'home';
    if (/\b(pro|enterprise|education)\b|корпоративн|для образовательных/i.test(cap)) return 'pro';
    return 'unknown';
  }

  Object.assign(FIXES, {
    'lockout-policy': {
      title: t('Закрывать вход после 10 неверных паролей'),
      changes: (f) => {
        const lo = login(f).lockout || {};
        const thr = num(lo.threshold);
        return [
          { what: t('Порог блокировки: неверных паролей подряд'), from: thr == null ? t('проверяется') : thr === 0 ? t('не задан (0)') : String(thr), to: String(LOCKOUT.threshold) },
          { what: t('За сколько времени считаются ошибки'), from: num(lo.windowSec) == null ? t('проверяется') : tx('{0} мин', minsOf(num(lo.windowSec))), to: tx('{0} мин', LOCKOUT.windowSec / 60) },
          { what: t('На сколько закрывается вход'), from: lockFor(lo.durationSec), to: tx('{0} мин', LOCKOUT.durationSec / 60) },
        ];
      },
      commands: [
        'NetUserModalsSet (level 3): lockout_threshold=10, lockout_observation_window=600, lockout_duration=600',
        'net accounts /lockoutthreshold:10 /lockoutwindow:10 /lockoutduration:10',
      ],
      notes: (f) => {
        const lo = login(f).lockout || {};
        const thr = num(lo.threshold);
        const out = [
          t('Правило действует для всех локальных учётных записей этого компьютера.'),
          t('Если вы сами ошибётесь 10 раз подряд, вход откроется через 10 минут - ждать придётся и вам.'),
          t('Программа делает то же, что команда net accounts, но одним вызовом Windows (NetUserModalsSet), чтобы три значения изменились вместе.'),
          t('Откат в разделе «Исправления» вернёт прежние значения точно, до секунды.'),
        ];
        if (thr != null) {
          const w = num(lo.windowSec);
          const d = num(lo.durationSec);
          out.push(thr === 0
            ? t('Вернуть вручную: в командной строке администратора введите net accounts /lockoutthreshold:0')
            : tx('Вернуть вручную: в командной строке администратора введите net accounts /lockoutthreshold:{0} /lockoutwindow:{1} /lockoutduration:{2}', thr, w == null ? '?' : minsOf(w), d == null ? '?' : d === FOREVER ? 0 : minsOf(d)));
        }
        return out;
      },
      arg(f) {
        const l = login(f);
        if (l.partOfDomain === true) throw new Error(t('Компьютер в домене: правила входа задаёт администратор домена - программа их не меняет'));
        const thr = num(l.lockout && l.lockout.threshold);
        if (thr != null && thr >= 1 && thr <= LOCKOUT.threshold) throw new Error(t('Блокировка входа уже включена (после 10 неверных паролей или раньше) - менять нечего'));
        return null;
      },
    },
    'require-cad': {
      title: t('Требовать Ctrl+Alt+Del перед входом'),
      changes: (f) => {
        const c = login(f).cad || {};
        return [{ what: t('Ctrl+Alt+Del перед входом (DisableCAD)'), from: c.required === false ? t('не требуется') : t('проверяется'), to: t('требуется') }];
      },
      commands: ['reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableCAD /t REG_DWORD /d 0 /f'],
      notes: [
        t('На экране блокировки сначала нажмите Ctrl+Alt+Del, потом вводите пароль или ПИН-код. Вход по лицу или отпечатку тоже начнётся после этого сочетания.'),
        t('На планшете без клавиатуры это неудобно: подключите клавиатуру или не включайте эту настройку.'),
        t('Начнёт действовать при следующей блокировке экрана или входе.'),
        UNDO,
      ],
      arg(f) {
        const c = login(f).cad;
        if (c && c.required === true) throw new Error(t('Ctrl+Alt+Del перед входом уже требуется - менять нечего'));
        return null;
      },
    },
    'bitlocker-pin-policy': {
      title: t('Разрешить ПИН-код BitLocker при включении компьютера'),
      changes: (f) => fveSpecs(fvePolicy(f)).filter((s) => s.changed).map((s) => ({
        what: FVE_WHAT[s.name],
        from: s.name === 'UseAdvancedStartup' ? (s.from == null ? t('не задана') : s.from === 1 ? t('включена') : t('выключена')) : fveShown(s.from),
        to: s.name === 'UseAdvancedStartup' ? t('включена') : fveShown(s.value),
      })),
      commands: [
        `reg add "${FVE}" /v UseAdvancedStartup /t REG_DWORD /d 1 /f`,
        `reg add "${FVE}" /v UseTPMPIN /t REG_DWORD /d 2 /f`,
        '… /v UseTPM, UseTPMKey, UseTPMKeyPIN /d 2 (только если значения нет или там 1 - «требовать»)',
      ],
      notes: [
        t('Программа меняет только разрешение. Диск она не шифрует и ПИН-код не ставит: это делает мастер BitLocker самой Windows - он же заставит сохранить ключ восстановления.'),
        t('Разрешаются обычные способы открыть диск: только TPM, TPM с ПИН-кодом, TPM с флешкой-ключом. Уже включённое шифрование не меняется, пока вы сами не добавите ПИН-код.'),
        t('Если компьютером управляет организация (домен, Intune) или эта политика уже настроена в gpedit.msc, Windows может вернуть прежние значения.'),
        t('Откат в разделе «Исправления» вернёт прежние значения политики, а тех, которых раньше не было, - удалит.'),
      ],
      arg(f) {
        if (edition(f) === 'home') throw new Error(t('В Windows Домашняя BitLocker с ПИН-кодом недоступен'));
        const p = fvePolicy(f);
        if (p && !fveSpecs(p).some((s) => s.changed)) throw new Error(t('ПИН-код BitLocker уже разрешён политикой - менять нечего'));
        return null;
      },
    },
  });
  return { fveSpecs, fvePolicy, pinAllowed, edition };
})();

/** Проверенный аргумент для fix.ps1 (или null). Бросает ошибку, если исправление неизвестно или аргумент не подходит. */
function validate(id, facts, arg) {
  const fix = FIXES[id];
  if (!fix) throw new Error(t('Неизвестное исправление'));
  return fix.arg ? fix.arg(facts || {}, arg) : null;
}

/** Что изменится - для окна подтверждения. */
function plan(id, facts, arg) {
  const fix = FIXES[id];
  const a = validate(id, facts, arg);
  return {
    id,
    arg: a,
    title: fix.title,
    changes: fix.changes(facts || {}, a || {}),
    commands: fix.commands,
    notes: typeof fix.notes === 'function' ? fix.notes(facts || {}, a || {}) : fix.notes,
  };
}

/** Аргументы командной строки для fix.ps1. */
function scriptArgs(action, { id, arg, record } = {}) {
  if (action === 'apply') {
    if (!FIXES[id]) throw new Error(t('Неизвестное исправление'));
    const out = ['-Action', 'apply', '-Id', id];
    const sa = arg && FIXES[id].scriptArg ? FIXES[id].scriptArg(arg) : arg;
    if (sa) out.push('-Arg', Buffer.from(JSON.stringify(sa), 'utf8').toString('base64'));
    return out;
  }
  if (action === 'undo') {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(record || '')) throw new Error(t('Неверная запись журнала'));
    return ['-Action', 'undo', '-Record', record];
  }
  throw new Error('action');
}

module.exports = { FIXES, plan, validate, scriptArgs, AUTOSTART_LOCS, LOGIN };
