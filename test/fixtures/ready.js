'use strict';
/**
 * Сведения разделов software, wifi, readiness, privacy (server/ps/sections) для тестов rules-ready.js.
 * Ответы netsh - на английском и русском, как их печатает Windows с разным языком интерфейса.
 */
const { NOW } = require('./facts');

const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();
const hoursAgo = (n) => new Date(NOW - n * 3_600_000).toISOString();

// ---------------------------------------------------------------- netsh (EN)

const EN_PROFILE_HOME = `
Profile HomeNet on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : HomeNet
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks
        MAC Randomization  : Disabled

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "HomeNet"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension          : Not present

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Cipher                 : GCMP
    Security key           : Present

Cost settings
-------------
    Cost                   : Unrestricted
    Congested              : No
    Approaching Data Limit : No
    Over Data Limit        : No
    Roaming                : No
    Cost Source            : Default
`;

const EN_PROFILE_CAFE = `
Profile Cafe Free WiFi on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : Cafe Free WiFi
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks
        MAC Randomization  : Disabled

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "Cafe Free WiFi"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]

Security settings
-----------------
    Authentication         : Open
    Cipher                 : None
    Security key           : Absent
`;

const EN_PROFILE_HOTEL_MANUAL = EN_PROFILE_CAFE.replace(/Cafe Free WiFi/g, 'Hotel Guest').replace('Connect automatically', 'Connect manually');

const EN_INTERFACES_OPEN = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 4b2f8c9e-1111-2222-3333-444455556666
    Physical address       : aa:bb:cc:dd:ee:ff
    Interface type         : Primary
    State                  : connected
    SSID                   : Cafe Free WiFi
    AP BSSID               : 11:22:33:44:55:66
    Band                   : 2.4 GHz
    Channel                : 6
    Network type           : Infrastructure
    Radio type             : 802.11n
    Authentication         : Open
    Cipher                 : None
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 144.4
    Transmit rate (Mbps)   : 144.4
    Signal                 : 90%
    Profile                : Cafe Free WiFi
    QoS MSCS Configured         : 0
    QoS Map Configured          : 0
    QoS Map Allowed by Policy   : 0

    Hosted network status  : Not available
`;

const EN_INTERFACES_DISCONNECTED = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 4b2f8c9e-1111-2222-3333-444455556666
    Physical address       : aa:bb:cc:dd:ee:ff
    Interface type         : Primary
    State                  : disconnected
    Radio status           : Hardware On
                             Software On

    Hosted network status  : Not available
`;

const EN_NO_WIFI = 'There is no wireless interface on the system.';

// ---------------------------------------------------------------- netsh (RU)

const RU_PROFILE_HOME = `
Профиль Дом_5G в интерфейсе Беспроводная сеть:
=======================================================================

Применено: Все профили пользователей

Сведения о профиле
-------------------
    Версия                 : 1
    Тип                    : Беспроводная ЛВС
    Имя                    : Дом_5G
    Параметры управления   :
        Режим подключения  : Подключаться автоматически
        Широковещательная передача в сети  : Подключаться, только если эта сеть ведет вещание
        Автоматическое переключение : Не переключаться на другие сети
        Случайный MAC-адрес : Отключено

Параметры подключения
---------------------
    Количество SSID        : 1
    Имя SSID               : "Дом_5G"
    Тип сети               : Инфраструктура
    Тип радио              : [ Любой тип радио ]
    Расширение поставщика  : Не представлено

Параметры безопасности
-----------------
    Проверка подлинности   : WPA3-Personal
    Шифр                   : GCMP
    Ключ безопасности      : Присутствует

Параметры стоимости
-------------
    Стоимость              : Неограниченная
`;

const RU_PROFILE_DACHA_WEP = `
Профиль Дача в интерфейсе Беспроводная сеть:
=======================================================================

Применено: Все профили пользователей

Сведения о профиле
-------------------
    Версия                 : 1
    Тип                    : Беспроводная ЛВС
    Имя                    : Дача
    Параметры управления   :
        Режим подключения  : Подключаться вручную
        Широковещательная передача в сети  : Подключаться, только если эта сеть ведет вещание

Параметры подключения
---------------------
    Количество SSID        : 1
    Имя SSID               : "Dacha"
    Тип сети               : Инфраструктура

Параметры безопасности
-----------------
    Проверка подлинности   : Открытая
    Шифр                   : WEP
    Ключ безопасности      : Присутствует
`;

const RU_PROFILE_OFFICE_TKIP = RU_PROFILE_HOME.replace(/Дом_5G/g, 'Офис').replace('WPA3-Personal', 'WPA-Personal').replace('GCMP', 'TKIP');

const RU_PROFILE_VOKZAL_OPEN = `
Профиль Вокзал_Free в интерфейсе Беспроводная сеть:
=======================================================================

Сведения о профиле
-------------------
    Имя                    : Вокзал_Free
    Параметры управления   :
        Режим подключения  : Подключаться автоматически

Параметры безопасности
-----------------
    Проверка подлинности   : Открытая
    Шифр                   : Нет
    Ключ безопасности      : Отсутствует
`;

const RU_INTERFACES_CONNECTED = `
В системе 1 интерфейс:

    Имя                    : Беспроводная сеть
    Описание               : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 4b2f8c9e-1111-2222-3333-444455556666
    Физический адрес       : aa:bb:cc:dd:ee:ff
    Тип интерфейса         : Основной
    Состояние              : подключено
    SSID                   : Дом_5G
    BSSID                  : 11:22:33:44:55:66
    Диапазон               : 5 ГГц
    Канал                  : 36
    Тип сети               : Инфраструктура
    Тип радио              : 802.11ax
    Проверка подлинности   : WPA3-Personal
    Шифр                   : GCMP
    Режим подключения      : Автоматическое подключение
    Скорость приема (Мбит/с) : 1201
    Скорость передачи (Мбит/с) : 1201
    Сигнал                 : 96%
    Профиль                : Дом_5G

    Состояние размещенной сети  : Недоступно
`;

const RU_INTERFACES_OPEN = RU_INTERFACES_CONNECTED.replace(/Дом_5G/g, 'Вокзал_Free').replace('WPA3-Personal', 'Открытая').replace('GCMP', 'Нет');

// ---------------------------------------------------------------- Разделы целиком

const wifi = (interfaces, profiles) => ({ service: 'Running', interfaces, profiles: Object.entries(profiles).map(([name, text]) => ({ name, text })) });

const wifiGoodEn = () => wifi(EN_INTERFACES_DISCONNECTED, { HomeNet: EN_PROFILE_HOME, 'Hotel Guest': EN_PROFILE_HOTEL_MANUAL });
const wifiBadEn = () => wifi(EN_INTERFACES_OPEN, { HomeNet: EN_PROFILE_HOME, 'Cafe Free WiFi': EN_PROFILE_CAFE });
const wifiGoodRu = () => wifi(RU_INTERFACES_CONNECTED, { 'Дом_5G': RU_PROFILE_HOME });
const wifiBadRu = () => wifi(RU_INTERFACES_OPEN, { 'Дом_5G': RU_PROFILE_HOME, 'Дача': RU_PROFILE_DACHA_WEP, 'Офис': RU_PROFILE_OFFICE_TKIP, 'Вокзал_Free': RU_PROFILE_VOKZAL_OPEN });

const app = (name, version, publisher = '') => ({ name, version, publisher, installDate: null, scope: 'hklm' });

function softwareGood() {
  const items = [
    app('7-Zip 25.01 (x64)', '25.01', 'Igor Pavlov'),
    app('WinRAR 7.13 (64-bit)', '7.13.0', 'win.rar GmbH'),
    app('Google Chrome', '157.0.8103.79', 'Google LLC'),
    app('Microsoft Edge', '157.0.4341.60', 'Microsoft Corporation'),
    app('Mozilla Firefox (x64 ru)', '158.0.1', 'Mozilla'),
    app('Zoom Workplace', '7.1.9 (48550)', 'Zoom Communications, Inc.'),
    app('AnyDesk', 'ad 9.5.2', 'AnyDesk Software GmbH'),
    app('Java 8 Update 471', '8.0.4710.8', 'Oracle Corporation'),
    app('Microsoft 365 - ru-ru', '16.0.19328.20000', 'Microsoft Corporation'),
    app('Microsoft Office профессиональный плюс 2024 - ru-ru', '16.0.17932.20000', 'Microsoft Corporation'),
    app('Python 3.13.5 (64-bit)', '3.13.5150.0', 'Python Software Foundation'),
    app('Яндекс Диск', '3.2.43', 'ООО «ЯНДЕКС»'),
    app('Macrium Reflect Free', '8.0.7783', 'Paramount Software (UK) Ltd.'),
  ];
  return { count: items.length, truncated: false, items, flashFiles: [] };
}

function softwareBad() {
  const items = [
    app('Adobe Flash Player 32 ActiveX', '32.0.0.465', 'Adobe'),
    app('Microsoft Silverlight', '5.1.50918.0', 'Microsoft Corporation'),
    app('QuickTime 7', '7.79.80.95', 'Apple Inc.'),
    app('Java 7 Update 80', '7.0.800', 'Oracle'),
    app('Java 8 Update 151', '8.0.1510.12', 'Oracle Corporation'),
    app('Python 2.7.18 (64-bit)', '2.7.18150', 'Python Software Foundation'),
    app('7-Zip 19.00 (x64)', '19.00', 'Igor Pavlov'),
    app('7-Zip 24.09 (x64)', '24.09', 'Igor Pavlov'),
    app('WinRAR 6.02 (64-bit)', '6.02.0', 'win.rar GmbH'),
    app('PuTTY release 0.76 (64-bit)', '0.76.0.0', 'Simon Tatham'),
    app('AnyDesk', 'ad 6.3.2', 'AnyDesk Software GmbH'),
    app('TeamViewer', '15.40.8', 'TeamViewer'),
    app('Zoom', '5.12.0 (11129)', 'Zoom Video Communications, Inc.'),
    app('VLC media player', '3.0.16', 'VideoLAN'),
    app('Notepad++ (64-bit x64)', '8.4.6', 'Notepad++ Team'),
    app('Adobe Reader XI (11.0.23)', '11.0.23', 'Adobe Systems Incorporated'),
    app('Microsoft Office профессиональный плюс 2016', '16.0.4266.1001', 'Microsoft Corporation'),
    app('Google Chrome', '120.0.6099.130', 'Google LLC'),
    app('Yandex', '24.4.1.951', 'ООО «ЯНДЕКС»'),
  ];
  return { count: items.length, truncated: false, items, flashFiles: ['C:\\Windows\\System32\\Macromed\\Flash\\Flash.ocx'] };
}

const knownFolders = (base) => ({ desktop: `${base}\\Desktop`, documents: `${base}\\Documents`, pictures: `${base}\\Pictures` });

/** Копии есть: документы и рабочий стол в OneDrive, точки восстановления свежие. */
function readinessGood() {
  return {
    restore: { rpSessionInterval: 1, disableSR: null, policyDisableSR: null, policyDisableConfig: null, lastCreated: daysAgo(3), lastSkipped: null, points: null, lastPoint: null, protectedDrives: null, systemDrive: 'C:' },
    fileHistory: { configured: false, lastBackup: null, policyDisabled: null },
    oneDrive: { accounts: [{ account: 'Personal', folder: 'C:\\Users\\user\\OneDrive' }], roots: ['C:\\Users\\user\\OneDrive'] },
    knownFolders: { desktop: 'C:\\Users\\user\\OneDrive\\Desktop', documents: 'C:\\Users\\user\\OneDrive\\Документы', pictures: 'C:\\Users\\user\\Pictures' },
  };
}

/** Копий нет нигде, точки восстановления выключены. */
function readinessBad() {
  return {
    restore: { rpSessionInterval: 0, disableSR: null, policyDisableSR: null, policyDisableConfig: null, lastCreated: null, lastSkipped: null, points: null, lastPoint: null, protectedDrives: null, systemDrive: 'C:' },
    fileHistory: { configured: false, lastBackup: null, policyDisabled: null },
    oneDrive: { accounts: [], roots: [] },
    knownFolders: knownFolders('C:\\Users\\user'),
  };
}

const cap = (apps, value = 'Allow') => ({ value, machineValue: 'Allow', count: apps.length, apps });
const pkg = (name, start, stop) => ({ name, path: '', packaged: true, value: 'Allow', start, stop, inUse: !!start && !stop });
const exe = (path, start, stop, signature = null) => ({ name: path.split('\\').pop(), path, packaged: false, value: '', start, stop, inUse: !!start && !stop, exists: true, signature });

/** Камерой пользовались обычные программы. */
function privacyGood() {
  return {
    webcam: cap([pkg('Microsoft.WindowsCamera', daysAgo(2), daysAgo(2)), exe('C:\\Program Files\\Zoom\\bin\\Zoom.exe', daysAgo(5), daysAgo(5)), exe('C:\\Program Files\\Old\\app.exe', daysAgo(40), daysAgo(40))]),
    microphone: cap([exe('C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe', daysAgo(1), daysAgo(1), 'Valid')]),
    location: cap([]),
  };
}

/** Программа из временной папки включала камеру; камера и микрофон включены прямо сейчас. */
function privacyBad() {
  return {
    webcam: cap([
      exe('C:\\Users\\user\\AppData\\Local\\Temp\\svc_update.exe', daysAgo(3), daysAgo(3), 'NotSigned'),
      exe('C:\\Program Files\\Zoom\\bin\\Zoom.exe', hoursAgo(1), null),
      exe('C:\\Program Files\\Crashed\\cam.exe', daysAgo(9), null), // оборванная запись - не «сейчас»
    ]),
    microphone: cap([exe('C:\\Users\\user\\Downloads\\recorder.exe', daysAgo(1), daysAgo(1)), pkg('MSTeams', hoursAgo(1), null)]),
    location: cap([exe('C:\\Users\\user\\AppData\\Roaming\\Tool\\tool.exe', daysAgo(2), daysAgo(2), 'NotSigned')]),
  };
}

function privacyQuiet() {
  return { webcam: cap([exe('C:\\Program Files\\Old\\app.exe', daysAgo(40), daysAgo(40))], 'Deny'), microphone: cap([]), location: cap([]) };
}

module.exports = {
  EN_PROFILE_HOME, EN_PROFILE_CAFE, EN_PROFILE_HOTEL_MANUAL, EN_INTERFACES_OPEN, EN_INTERFACES_DISCONNECTED, EN_NO_WIFI,
  RU_PROFILE_HOME, RU_PROFILE_DACHA_WEP, RU_PROFILE_OFFICE_TKIP, RU_PROFILE_VOKZAL_OPEN, RU_INTERFACES_CONNECTED, RU_INTERFACES_OPEN,
  wifiGoodEn, wifiBadEn, wifiGoodRu, wifiBadRu, softwareGood, softwareBad, readinessGood, readinessBad, privacyGood, privacyBad, privacyQuiet,
  daysAgo, hoursAgo,
};
