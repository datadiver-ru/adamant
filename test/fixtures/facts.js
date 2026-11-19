'use strict';
/** Сведения о компьютере в формате collect.ps1: «хороший» и «плохой» варианты для тестов. */
const NOW = Date.parse('2026-11-17T12:00:00Z');
const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();
const SID = 'S-1-5-21-1111111111-2222222222-3333333333';

function good() {
  return {
    format: 'adamant-facts', version: 1, errors: {}, isAdmin: false, collectedAt: new Date(NOW).toISOString(),
    meta: { computer: 'TEST-PC', user: 'TEST-PC\\user', userSid: `${SID}-1001`, osCaption: 'Microsoft Windows 11 Pro', osBuild: '26200' },
    ports: {
      tcp: [
        { proto: 'tcp', addr: '0.0.0.0', port: 135, pid: 1000, proc: 'svchost', services: ['RpcSs'] },
        { proto: 'tcp', addr: '0.0.0.0', port: 445, pid: 4, proc: 'System', services: [] },
        { proto: 'tcp', addr: '127.0.0.1', port: 5177, pid: 2000, proc: 'node', services: [] },
      ],
      udp: [],
    },
    firewall: {
      profiles: [{ name: 'Domain', enabled: 'True', inbound: 'NotConfigured' }, { name: 'Private', enabled: 'True', inbound: 'NotConfigured' }, { name: 'Public', enabled: 'True', inbound: 'NotConfigured' }],
      networks: [{ name: 'Home', category: 'Public', alias: 'Ethernet', ifIndex: 7 }],
    },
    defender: { status: { serviceEnabled: true, antivirusEnabled: true, realTime: true, tamper: true, signatureAge: 0, mode: 'Normal' }, products: [{ name: 'Windows Defender', state: 397568 }] },
    smb: { server1: false, server2: true, clientDriver: false, clientStart: null, shares: [] },
    rdp: { deny: 1, nla: 1, port: 3389, policyDeny: null, policyNla: null },
    uac: { enableLua: 1, consentAdmin: 5, secureDesktop: 1 },
    accounts: {
      users: [
        { name: 'Administrator', sid: `${SID}-500`, enabled: false, passwordRequired: true },
        { name: 'Guest', sid: `${SID}-501`, enabled: false, passwordRequired: false },
        { name: 'user', sid: `${SID}-1001`, enabled: true, passwordRequired: true },
      ],
      admins: [{ name: 'TEST-PC\\user', sid: `${SID}-1001`, kind: 'User', source: 'Local' }],
      autoLogon: '0', autoLogonPasswordStored: false,
    },
    autostart: { userSid: `${SID}-1001`, items: [{ loc: 'HKCU-Run', name: 'OneDrive', command: '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background', state: 'on' }] },
    updates: { lastHotfix: daysAgo(5), lastUpdate: daysAgo(2), service: 'Manual', noAutoUpdate: null, rebootRequired: false },
    encryption: { drives: [{ drive: 'C:', shellState: 1, system: true }] },
    boot: { firmware: 'uefi', secureBoot: 1, tpmDevices: [{ name: 'Trusted Platform Module 2.0', status: 'OK' }] },
    firmware: { manufacturer: 'Dell Inc.', model: 'OptiPlex', adminPasswordStatus: 1, powerOnPasswordStatus: 0, biosVendor: 'Dell Inc.', biosVersion: '1.2.3', biosDate: daysAgo(200), vendor: null },
  };
}

function bad() {
  const f = good();
  f.ports.tcp.push(
    { proto: 'tcp', addr: '0.0.0.0', port: 23, pid: 3000, proc: 'tlntsvr', services: ['TlntSvr'] },
    { proto: 'tcp', addr: '::', port: 6379, pid: 3100, proc: 'redis-server', services: [] },
    { proto: 'tcp', addr: '0.0.0.0', port: 3389, pid: 1200, proc: 'svchost', services: ['TermService'] },
    { proto: 'tcp', addr: '0.0.0.0', port: 8000, pid: 3200, proc: 'python', services: [] },
  );
  f.firewall.profiles = f.firewall.profiles.map((p) => ({ ...p, enabled: 'False' }));
  f.defender.status.realTime = false;
  f.defender.status.tamper = false;
  f.smb = { server1: true, server2: true, clientDriver: true, clientStart: 3, shares: [{ name: 'Public', path: 'C:\\Public' }] };
  f.rdp = { deny: 0, nla: 0, port: 3389 };
  f.uac = { enableLua: 0, consentAdmin: 0, secureDesktop: 0 };
  f.accounts.users[0].enabled = true;
  f.accounts.users[1].enabled = true;
  f.accounts.users.push({ name: 'nopass', sid: `${SID}-1002`, enabled: true, passwordRequired: false });
  f.accounts.autoLogon = '1';
  f.accounts.autoLogonPasswordStored = true;
  f.accounts.admins.push({ name: 'TEST-PC\\Administrator', sid: `${SID}-500` }, { name: 'TEST-PC\\nopass', sid: `${SID}-1002` });
  f.autostart.items.push({ loc: 'HKCU-Run', name: 'Updater', command: 'C:\\Users\\user\\AppData\\Local\\Temp\\upd.exe', state: 'on' });
  f.autostart.items.push({ loc: 'HKLM-Run', name: 'Loader', command: 'powershell.exe -w hidden -enc SQBFAFgA', state: 'on' });
  f.updates = { lastHotfix: daysAgo(120), lastUpdate: daysAgo(100), service: 'Disabled', noAutoUpdate: 1, rebootRequired: true };
  f.encryption = { drives: [{ drive: 'C:', shellState: 2, system: true }] };
  f.boot = { firmware: 'uefi', secureBoot: 0, tpmDevices: [] };
  f.firmware = { ...f.firmware, adminPasswordStatus: 0, biosDate: daysAgo(5 * 365) };
  return f;
}

module.exports = { good, bad, NOW, SID };
