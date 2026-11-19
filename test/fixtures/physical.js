'use strict';
/** Сведения facts.physical (server/ps/sections/physical.ps1): «открытый» и «защищённый» компьютеры для тестов. */
const { good, bad, NOW } = require('./facts');

const at = (daysAgo, hh = '12:00') => {
  const d = new Date(NOW - daysAgo * 86_400_000).toISOString().slice(0, 10);
  return `${d}T${hh}:00.0000000+03:00`;
};
const SYS32 = 'C:\\WINDOWS\\System32\\';
const ORIGINAL = { 'sethc.exe': 'sethc.exe', 'utilman.exe': 'utilman2.exe', 'osk.exe': 'osk.exe', 'Magnify.exe': 'ScreenMagnifier.exe', 'Narrator.exe': 'SR.exe', 'DisplaySwitch.exe': 'DisplaySwitch.exe', 'AtBroker.exe': 'ATBroker.exe' };
const accessibility = () => Object.entries(ORIGINAL).map(([exe, originalName]) => ({ exe, path: SYS32 + exe, exists: true, originalName, description: '', modified: at(30), debugger: null }));

/** Защищённый компьютер: диск зашифрован с ПИН-кодом, автоблокировка, никто чужой не входил. */
function protectedPhysical() {
  return {
    admin: true, errors: {},
    accessibility: accessibility(),
    ats: [{ name: 'osk', startExe: SYS32 + 'osk.exe', atExe: 'osk.exe' }],
    usb: [
      { name: 'SanDisk Cruzer Blade USB Device', serial: '00010323090325223900', first: at(11, '21:15'), last: at(11, '21:15'), removed: at(11, '21:16'), present: false, id: 'USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\\00010323090325223900&0' },
    ],
    presence: {
      days: 14, security: true,
      events: [
        { at: at(0, '09:00'), kind: 'unlock', source: 'security', user: 'TEST-PC\\user', logonType: 7 },
        { at: at(0, '08:59'), kind: 'lock', source: 'security', user: 'TEST-PC\\user' },
        { at: at(1, '08:00'), kind: 'logon', source: 'security', user: 'TEST-PC\\user', logonType: 2 },
        { at: at(1, '07:59'), kind: 'boot', source: 'system' },
        { at: at(2, '23:00'), kind: 'shutdown', source: 'system' },
        { at: at(5, '10:00'), kind: 'unexpected', source: 'system' },
      ],
    },
    lock: { screenSaverActive: true, screenSaverExe: '', screenSaverSecure: false, screenSaverTimeout: null, inactivityTimeout: 600, dynamicLock: false, consoleLockAc: 1, consoleLockDc: 1, delayLock: 0, sleepAc: 1800, sleepDc: 600, battery: true },
    bitlocker: { protectors: ['TpmPin', 'RecoveryPassword'], preboot: 'pin', protection: 'On', policy: { useAdvancedStartup: 1, useTpm: null, useTpmPin: 1, useTpmKey: null, useTpmKeyPin: null } },
    winre: { enabled: true, source: 'reagentc' },
    dma: { protection: true, thunderbolt: true },
  };
}

/** Открытый компьютер: подменено залипание клавиш, диск не зашифрован, нет автоблокировки, чужие попытки входа. */
function exposedPhysical() {
  const p = protectedPhysical();
  p.accessibility[0].debugger = 'C:\\Windows\\System32\\cmd.exe';
  p.accessibility[1].originalName = 'Cmd.Exe';
  p.usb.unshift({ name: 'Generic Flash Disk USB Device', serial: 'AA11BB22', first: at(3, '02:10'), last: at(3, '02:10'), removed: at(3, '02:20'), present: false, id: 'USBSTOR\\Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07\\AA11BB22&0' });
  p.presence.events = [
    { at: at(3, '02:30'), kind: 'unlock', source: 'security', user: 'TEST-PC\\user', logonType: 7 },
    { at: at(3, '02:07'), kind: 'failed-local', source: 'security', user: 'TEST-PC\\user', logonType: 2 },
    { at: at(3, '02:06'), kind: 'failed-local', source: 'security', user: 'TEST-PC\\user', logonType: 2 },
    { at: at(3, '02:05'), kind: 'failed-local', source: 'security', user: 'TEST-PC\\user', logonType: 2 },
    { at: at(3, '01:00'), kind: 'lock', source: 'security', user: 'TEST-PC\\user' },
    { at: at(4, '09:00'), kind: 'boot', source: 'system' },
    { at: at(40, '09:00'), kind: 'failed-local', source: 'security', user: 'TEST-PC\\old' }, // старше 14 дней - не считается
  ];
  p.lock = { screenSaverActive: true, screenSaverExe: '', screenSaverSecure: false, screenSaverTimeout: null, inactivityTimeout: null, dynamicLock: false, consoleLockAc: 0, consoleLockDc: 1, delayLock: null, sleepAc: 0, sleepDc: 0, battery: true };
  p.bitlocker = { protectors: [], preboot: 'none', protection: 'Off', policy: {} };
  p.dma = { protection: false, thunderbolt: true };
  return p;
}

/** Полные сведения: хороший компьютер из facts.js + защищённый раздел physical. */
function protectedFacts() {
  return { ...good(), isAdmin: true, physical: protectedPhysical() };
}
/** Плохой компьютер из facts.js (диск не зашифрован, нет пароля BIOS, Secure Boot выключен) + открытый physical. */
function exposedFacts() {
  return { ...bad(), physical: exposedPhysical() };
}

module.exports = { protectedPhysical, exposedPhysical, protectedFacts, exposedFacts, NOW };
