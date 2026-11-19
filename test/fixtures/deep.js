'use strict';
/** Раздел hardening (server/ps/sections/hardening.ps1): «слабый» и «крепкий» компьютер для тестов. */
const { good, NOW } = require('./facts');

const SAFE_ASR_IDS = [
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', '56a863a9-875e-4185-98a7-b882c64b5ce5',
];
const LAST_BOOT = new Date(NOW - 3_600_000).toISOString();

function strongHardening() {
  return {
    admin: false, build: 26200, partOfDomain: false,
    lsa: { runAsPPL: 2, runAsPPLBoot: 2, lmCompat: null, noLmHash: 1, lsaCfgFlags: null, lsaCfgFlagsPolicy: null, pplEvent: { at: new Date(NOW - 3_000_000).toISOString(), level: 4 } },
    wdigest: { useLogonCredential: null },
    cachedLogons: '10',
    deviceGuard: { vbs: 2, running: [2], configured: [2], available: [1, 2, 3, 5], hvciEnabled: 1, vbsEnabled: 1 },
    mp: { available: true, cfa: 1, pua: 1, maps: 2, samples: 1, asr: SAFE_ASR_IDS.map((id) => ({ id, action: 1 })) },
    smartScreen: { explorer: null, policy: null, policyLevel: null, smartAppControl: 0 },
    driverBlocklist: 1,
    llmnr: 0, netbiosNodeType: null,
    netbios: [{ name: 'Intel(R) Ethernet', option: 2, index: 1 }],
    wpad: { autoDetect: false, serviceStart: 3 },
    smbSigning: { serverReg: null, clientReg: null, server: true, client: true },
    services: { WinRM: { status: 'Stopped', start: 'Manual' }, RemoteRegistry: { status: 'Stopped', start: 'Disabled' }, Spooler: { status: 'Running', start: 'Automatic' } },
    winrmListeners: 0,
    remoteAssistance: { allow: 0, policy: null },
    printers: [{ name: 'Microsoft Print to PDF', port: 'PORTPROMPT:' }, { name: 'HP LaserJet', port: 'WSD-1234' }],
    ps2: { engine: null },
    execPolicy: { machinePolicy: null, userPolicy: null, machine: 'RemoteSigned', user: null },
    autorun: { machineDriveTypes: 255, userDriveTypes: null, machineNoAutorun: 1, userNoAutorun: null, disableAutoplay: 1 },
    office: [{ app: 'Word', vbaWarnings: null, policyVbaWarnings: null, blockInternet: null }],
    lock: { inactivityTimeoutSecs: 600 },
  };
}

function weakHardening() {
  return {
    admin: true, build: 22631, partOfDomain: true,
    lsa: { runAsPPL: null, runAsPPLBoot: null, lmCompat: 1, noLmHash: 0, lsaCfgFlags: null, lsaCfgFlagsPolicy: null, pplEvent: null },
    wdigest: { useLogonCredential: 1 },
    cachedLogons: '25',
    deviceGuard: { vbs: 0, running: [], configured: [], available: [1, 3], hvciEnabled: 0, vbsEnabled: null },
    mp: { available: true, cfa: 0, pua: 0, maps: 0, samples: 2, asr: [{ id: SAFE_ASR_IDS[0].toUpperCase(), action: 2 }, { id: SAFE_ASR_IDS[1], action: 1 }] },
    smartScreen: { explorer: 'Off', policy: null, policyLevel: null, smartAppControl: 0 },
    driverBlocklist: 0,
    llmnr: null, netbiosNodeType: null,
    netbios: [{ name: 'Intel(R) Ethernet', option: 0, index: 1 }, { name: 'Wi-Fi', option: 1, index: 2 }, { name: 'VPN', option: 2, index: 3 }],
    wpad: { autoDetect: true, serviceStart: 3 },
    smbSigning: { serverReg: 0, clientReg: 0, server: false, client: false },
    services: { WinRM: { status: 'Running', start: 'Automatic' }, RemoteRegistry: { status: 'Running', start: 'Automatic' }, Spooler: { status: 'Running', start: 'Automatic' } },
    winrmListeners: 1,
    remoteAssistance: { allow: 1, policy: null },
    printers: [{ name: 'Microsoft Print to PDF', port: 'PORTPROMPT:' }, { name: 'OneNote (Desktop)', port: 'nul:' }],
    ps2: { engine: '2.0' },
    execPolicy: { machinePolicy: null, userPolicy: null, machine: 'Unrestricted', user: null },
    autorun: { machineDriveTypes: null, userDriveTypes: null, machineNoAutorun: null, userNoAutorun: null, disableAutoplay: 0 },
    office: [{ app: 'Word', vbaWarnings: 1, policyVbaWarnings: null, blockInternet: 0 }, { app: 'Excel', vbaWarnings: 2, policyVbaWarnings: null, blockInternet: null }],
    lock: { inactivityTimeoutSecs: null },
  };
}

/** Подмена специальных возможностей (раздел physical - его собирает другая проверка). */
const ACCESSIBILITY = [
  { exe: 'sethc.exe', path: 'C:\\Windows\\System32\\sethc.exe', exists: true, originalName: 'sethc.exe', debugger: 'C:\\Windows\\System32\\cmd.exe' },
  { exe: 'utilman.exe', path: 'C:\\Windows\\System32\\utilman.exe', exists: true, originalName: 'utilman.exe', debugger: '' },
  { exe: 'osk.exe', path: 'C:\\Windows\\System32\\osk.exe', exists: true, originalName: 'osk.exe', debugger: null },
];

function strong() {
  const f = good();
  f.meta.lastBoot = LAST_BOOT;
  f.meta.edition = 'Professional';
  f.hardening = strongHardening();
  return f;
}

function weak() {
  const f = good();
  f.meta.lastBoot = LAST_BOOT;
  f.meta.edition = 'Enterprise';
  f.hardening = weakHardening();
  f.physical = { accessibility: ACCESSIBILITY.map((a) => ({ ...a })) };
  return f;
}

module.exports = { strong, weak, NOW, SAFE_ASR_IDS };
