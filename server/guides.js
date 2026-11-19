'use strict';
/**
 * Пошаговые инструкции для того, что программа сама не меняет: прошивка (BIOS/UEFI), BitLocker,
 * TPM, пароли - ошибка в них может стоить данных или загрузки системы. Плюс кнопки «Открыть …»
 * для нужных окон Windows (только из списка OPEN_TARGETS).
 */
const { spawn } = require('node:child_process');
const path = require('node:path');
const { tx, t } = require('./i18n');

const SYS = process.env.SystemRoot || 'C:\\Windows';
const sys32 = (exe) => path.join(SYS, 'System32', exe);

/** Окна Windows, которые можно открыть кнопкой. Только чтение/просмотр: сами по себе ничего не меняют. */
const OPEN_TARGETS = {
  windowsupdate: { label: t('Центр обновления Windows'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:windowsupdate'] },
  security: { label: t('Безопасность Windows'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://threatsettings'] },
  defenderupdate: { label: t('Обновления защиты'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://threat'] },
  firewall: { label: t('Брандмауэр и защита сети'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://network'] },
  bitlocker: { label: t('Шифрование диска BitLocker'), cmd: [sys32('control.exe'), '/name', 'Microsoft.BitLockerDriveEncryption'] },
  deviceencryption: { label: t('Шифрование устройства'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:deviceencryption'] },
  tpm: { label: t('Управление TPM'), cmd: [sys32('mmc.exe'), 'tpm.msc'] },
  recovery: { label: t('Особые варианты загрузки'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:recovery'] },
  signin: { label: t('Варианты входа'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:signinoptions'] },
  users: { label: t('Другие пользователи'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:otherusers'] },
  startup: { label: t('Автозагрузка в параметрах'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:startupapps'] },
  sysinfo: { label: t('Сведения о системе'), cmd: [sys32('msinfo32.exe')] },
  shares: { label: t('Общие папки'), cmd: [sys32('mmc.exe'), 'fsmgmt.msc'] },
  lockscreen: { label: t('Экран блокировки и вход'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:signinoptions-dynamiclock'] },
  activation: { label: t('Активация и выпуск Windows'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:activation'] },
  bluetooth: { label: t('Bluetooth и устройства'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:bluetooth'] },
  power: { label: t('Питание и спящий режим'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:powersleep'] },
  backup: { label: t('Резервное копирование Windows'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:backup'] },
  restore: { label: t('Защита системы (точки восстановления)'), cmd: [sys32('SystemPropertiesProtection.exe')] },
  camera: { label: t('Доступ к камере'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:privacy-webcam'] },
  microphone: { label: t('Доступ к микрофону'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:privacy-microphone'] },
  wifi: { label: t('Сети Wi-Fi'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:network-wifisettings'] },
  apps: { label: t('Установленные приложения'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:appsfeatures'] },
  features: { label: t('Компоненты Windows'), cmd: [sys32('OptionalFeatures.exe')] },
  coreisolation: { label: t('Изоляция ядра'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://coreisolation'] },
  ransomware: { label: t('Защита от программ-шантажистов'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://ransomwareprotection'] },
  appbrowser: { label: t('Управление приложениями и браузером'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://appbrowser'] },
  devicesecurity: { label: t('Безопасность устройства'), cmd: [path.join(SYS, 'explorer.exe'), 'windowsdefender://devicesecurity'] },
  eventvwr: { label: t('Просмотр событий'), cmd: [sys32('mmc.exe'), 'eventvwr.msc'] },
  sharing: { label: t('Дополнительные параметры общего доступа'), cmd: [path.join(SYS, 'explorer.exe'), 'ms-settings:network-advancedsharing'] },
  // Связь с автором: только эти адреса, открываются в браузере по умолчанию по кнопке в «О программе».
  'contact-telegram': { label: 'Telegram', cmd: [path.join(SYS, 'explorer.exe'), 'https://t.me/data_diver_ru'] },
  'contact-site': { label: t('Сайт'), cmd: [path.join(SYS, 'explorer.exe'), 'https://datadiver-ru.github.io/'] },
  'contact-github': { label: 'GitHub', cmd: [path.join(SYS, 'explorer.exe'), 'https://github.com/datadiver-ru'] },
  'contact-mail': { label: t('Почта'), cmd: [path.join(SYS, 'explorer.exe'), 'mailto:data.diver.ru@gmail.com'] },
  // Страница загрузки новой версии - по кнопке после «Проверить обновления».
  download: { label: t('Страница загрузки'), cmd: [path.join(SYS, 'explorer.exe'), 'https://datadiver-ru.github.io/adamant.html'] },
  'download-en': { label: t('Страница загрузки'), cmd: [path.join(SYS, 'explorer.exe'), 'https://datadiver-ru.github.io/en/adamant.html'] },
};

function openTarget(name) {
  const tgt = OPEN_TARGETS[name];
  if (!tgt) throw new Error(t('Неизвестное окно'));
  const [exe, ...args] = tgt.cmd;
  spawn(exe, args, { detached: true, stdio: 'ignore', windowsHide: false }).unref();
}

/** Клавиша входа в настройки прошивки по производителю. */
function firmwareKey(manufacturer) {
  const m = String(manufacturer || '');
  const table = [
    [/dell/i, 'F2'], [/hewlett|hp\b/i, t('Esc, затем F10')], [/lenovo/i, t('F1 или F2 (на ноутбуках - Enter, затем F1)')],
    [/asus/i, t('Del или F2')], [/acer/i, 'F2'], [/msi|micro-star/i, 'Del'], [/gigabyte/i, 'Del'], [/asrock/i, t('F2 или Del')],
    [/samsung/i, 'F2'], [/huawei|honor/i, 'F2'], [/microsoft/i, t('кнопка увеличения громкости при включении')],
  ];
  const hit = table.find(([re]) => re.test(m));
  return hit ? hit[1] : t('Del, F2, F10 или Esc');
}

const enterFirmware = (f) => [
  t('Сохраните открытые документы.'),
  t('Нажмите «Открыть: особые варианты загрузки» ниже, затем «Перезагрузить сейчас».'),
  t('После перезагрузки выберите «Поиск и устранение неисправностей» → «Дополнительные параметры» → «Параметры встроенного ПО UEFI» → «Перезагрузить».'),
  tx('Другой способ: сразу после включения часто нажимайте клавишу {0}.', firmwareKey(f && f.firmware && f.firmware.manufacturer)),
];

const GUIDES = {
  'bios-password': (f) => ({
    title: t('Как поставить пароль на BIOS/UEFI'),
    intro: t('Пароль администратора прошивки не даёт постороннему выключить защиту загрузки или загрузиться с флешки. Программа сама его не ставит: если пароль потерять, сбросить его бывает можно только в сервисе.'),
    steps: [
      ...enterFirmware(f),
      t('В настройках найдите раздел Security (Безопасность) или Main.'),
      t('Выберите Administrator Password или Supervisor Password (пароль администратора) и задайте пароль. Пароль на включение (Power-On / User Password) - по желанию.'),
      t('Запишите пароль и храните отдельно от компьютера, например в менеджере паролей.'),
      t('Нажмите F10 (Save & Exit) и подтвердите сохранение.'),
      t('Вернитесь в «Адамант» и запустите полную проверку. Если прошивка не сообщает о пароле Windows, пункт останется «не видно» - это нормально.'),
    ],
    open: ['recovery'],
  }),
  'boot-order': (f) => ({
    title: t('Как поставить диск Windows первым в порядке загрузки'),
    intro: t('Порядок загрузки меняется только в настройках прошивки. Программа его не трогает: неверный порядок может помешать запуску Windows.'),
    steps: [
      ...enterFirmware(f),
      t('Откройте раздел Boot (Загрузка).'),
      t('Поставьте первым Windows Boot Manager (диспетчер загрузки Windows).'),
      t('Если вы не загружаетесь с флешек, выключите загрузку с USB и по сети (Network/PXE Boot).'),
      t('Сохраните настройки: F10 (Save & Exit).'),
    ],
    open: ['recovery'],
  }),
  secureboot: (f) => ({
    title: t('Как включить безопасную загрузку (Secure Boot)'),
    intro: t('Secure Boot работает только в режиме UEFI. Если Windows установлена в старом режиме BIOS (диск MBR), простое переключение сделает её незагружаемой - сначала диск нужно преобразовать.'),
    steps: [
      t('Нажмите «Открыть: сведения о системе» и посмотрите «Режим BIOS». Если там «Устаревший», сначала преобразуйте диск командой mbr2gpt (инструкция Microsoft: «MBR2GPT.EXE») и сделайте резервную копию.'),
      ...enterFirmware(f),
      t('Откройте раздел Boot или Security. Если есть пункт CSM (Compatibility Support Module), выключите его.'),
      t('Включите Secure Boot (Enabled). Если пункт недоступен, выберите стандартные ключи: Install default Secure Boot keys / Restore Factory Keys.'),
      t('Сохраните настройки: F10 (Save & Exit). Windows должна загрузиться как обычно.'),
    ],
    open: ['sysinfo', 'recovery'],
  }),
  tpm: (f) => ({
    title: t('Как включить модуль TPM'),
    intro: t('На большинстве компьютеров после 2016 года TPM встроен в процессор, но может быть выключен в прошивке.'),
    steps: [
      ...enterFirmware(f),
      t('Найдите в разделах Security или Advanced пункт Intel PTT / Intel Platform Trust Technology (для Intel) или AMD fTPM / Firmware TPM (для AMD).'),
      t('Включите его (Enabled) и сохраните настройки: F10.'),
      t('В Windows нажмите «Открыть: управление TPM» - там должно быть «TPM готов к использованию».'),
    ],
    open: ['recovery', 'tpm'],
  }),
  bitlocker: (f) => ({
    title: t('Как зашифровать диск'),
    intro: t('Программа не включает шифрование сама: при этом создаётся ключ восстановления, который нужно сохранить вам. Без него при сбое данные не вернуть.'),
    steps: [
      t('Windows Pro и выше: нажмите «Открыть: шифрование диска BitLocker» → «Включить BitLocker» у диска C:.'),
      t('Windows Домашняя: нажмите «Открыть: шифрование устройства». Если такого пункта нет, на этой версии шифрование недоступно.'),
      t('Сохраните ключ восстановления: в учётной записи Microsoft, на флешке или распечатайте. Не храните его только на этом же диске.'),
      t('Выберите «Шифровать только занятое место» для нового компьютера или «Весь диск» - для давно используемого.'),
      t('Шифрование идёт в фоне, работать можно. Когда закончится, запустите проверку ещё раз.'),
    ],
    open: ['bitlocker', 'deviceencryption'],
  }),
  update: () => ({
    title: t('Как установить обновления Windows'),
    intro: t('Обновления закрывают уязвимости, через которые заражают компьютеры без участия человека.'),
    steps: [t('Нажмите «Открыть: центр обновления Windows».'), t('Нажмите «Проверить наличие обновлений» и установите всё найденное.'), t('Перезагрузите компьютер, если Windows попросит.')],
    open: ['windowsupdate'],
  }),
  'defender-update': () => ({
    title: t('Как обновить базы антивируса'),
    intro: t('Базы обновляются вместе с Windows, но иногда это ломается.'),
    steps: [t('Нажмите «Открыть: обновления защиты».'), t('Нажмите «Проверить наличие обновлений».'), t('Если обновление не идёт, проверьте, что работает «Центр обновления Windows».')],
    open: ['defenderupdate', 'windowsupdate'],
  }),
  tamper: () => ({
    title: t('Как включить защиту от подделки'),
    intro: t('Эту настройку можно включить только вручную - так задумано в Windows.'),
    steps: [t('Нажмите «Открыть: безопасность Windows».'), t('В разделе «Параметры защиты от вирусов и угроз» включите «Защита от подделки».')],
    open: ['security'],
  }),
  'firewall-inbound': () => ({
    title: t('Как запретить входящие подключения по умолчанию'),
    intro: t('Обычно брандмауэр блокирует входящие подключения, кроме разрешённых программ.'),
    steps: [t('Нажмите «Открыть: брандмауэр и защита сети».'), t('Выберите «Восстановить для брандмауэров значения по умолчанию», если вы не настраивали правила специально.')],
    open: ['firewall'],
  }),
  password: () => ({
    title: t('Как задать пароль учётной записи'),
    intro: t('У каждой учётной записи, под которой входят в Windows, должен быть пароль или ПИН-код.'),
    steps: [t('Войдите под этой учётной записью и нажмите «Открыть: варианты входа».'), t('Выберите «Пароль» → «Добавить» или «Изменить».'), t('Если учётной записью никто не пользуется, отключите или удалите её в «Другие пользователи».')],
    open: ['signin', 'users'],
  }),
  admins: () => ({
    title: t('Как сократить число администраторов'),
    intro: t('Для повседневной работы удобнее и безопаснее обычная учётная запись.'),
    steps: [t('Нажмите «Открыть: другие пользователи».'), t('У лишних администраторов выберите «Изменить тип учётной записи» → «Стандартный пользователь».'), t('Оставьте хотя бы одного администратора, пароль от которого вы знаете.')],
    open: ['users'],
  }),
  shares: () => ({
    title: t('Как проверить общие папки'),
    intro: t('Общая папка видна всем в сети, у кого есть права.'),
    steps: [t('Нажмите «Открыть: общие папки».'), t('Ненужные папки закройте: правой кнопкой → «Прекратить общий доступ».'), t('У нужных проверьте разрешения: «Все» (Everyone) с правом записи - плохая идея.')],
    open: ['shares'],
  }),
  autostart: () => ({
    title: t('Как отключить программу в автозагрузке'),
    intro: t('Отключение не удаляет программу, а только не даёт ей запускаться при входе.'),
    steps: [t('Нажмите «Открыть: автозагрузка в параметрах».'), t('Выключите переключатель у ненужной программы.')],
    open: ['startup'],
  }),
  'local-service': () => ({
    title: t('Что делать с открытой службой'),
    intro: t('Служба на этом компьютере принимает подключения из сети.'),
    steps: [t('Если вы не знаете эту программу, найдите её в списке портов и удалите через «Параметры» → «Приложения».'), t('Если программа нужна, в её настройках разрешите подключения только с этого компьютера (адрес 127.0.0.1) или поставьте пароль.'), t('Убедитесь, что брандмауэр включён.')],
    open: ['firewall'],
  }),
  'bios-update': (f) => ({
    title: t('Как обновить BIOS/UEFI'),
    intro: tx('Обновление прошивки выпускает производитель компьютера или материнской платы ({0}). Программа его не скачивает и не ставит.', (f && f.firmware && f.firmware.manufacturer) || '-'),
    steps: [t('Нажмите «Открыть: сведения о системе» и запишите модель и «Версию BIOS».'), t('На официальном сайте производителя найдите раздел поддержки своей модели и сравните версии.'), t('Если вышла новая, следуйте инструкции производителя. Подключите ноутбук к зарядке и не выключайте компьютер во время обновления.'), t('Если диск зашифрован BitLocker, перед обновлением приостановите защиту, а после - возобновите.')],
    open: ['sysinfo'],
  }),
  'router': () => ({
    title: t('Как защитить роутер'),
    intro: t('Роутер - дверь из вашей сети в интернет. Его настройки открываются в браузере по адресу шлюза.'),
    steps: [t('Войдите в настройки роутера (адрес шлюза указан в находке) и смените пароль администратора, если он стандартный (admin/admin).'), t('Включите доступ к настройкам по HTTPS, если роутер это умеет, и выключите доступ из интернета (Remote Management).'), t('Выключите WPS и Telnet, если они есть в настройках.'), t('Проверьте обновление прошивки роутера в его настройках или на сайте производителя.')],
    open: [],
  }),
  device: () => ({
    title: t('Как закрыть лишнюю службу на устройстве'),
    intro: t('На устройстве в вашей сети открыта служба, которая часто становится целью атак.'),
    steps: [t('Определите устройство по адресу: его имя и тип часто видны в настройках роутера в списке клиентов.'), t('В настройках устройства выключите эту службу или поставьте сложный пароль.'), t('Обновите прошивку устройства.'), t('Если устройство вам незнакомо, отключите его от сети и смените пароль Wi-Fi.')],
    open: [],
  }),
};

// Инструкции из дополнительных модулей (у них второй аргумент - помощники, чтобы не было циклических require).
Object.assign(GUIDES, require('./guides-deep').GUIDES, require('./guides-ready').GUIDES, require('./guides-physical').GUIDES, require('./guides-login').GUIDES, require('./guides-extra').GUIDES);

function guide(id, facts) {
  const g = GUIDES[id];
  if (!g) return null;
  const out = g(facts || {}, { enterFirmware, firmwareKey });
  return { id, ...out, open: out.open.map((k) => ({ id: k, label: OPEN_TARGETS[k].label })) };
}

module.exports = { guide, GUIDES, OPEN_TARGETS, openTarget, firmwareKey };
