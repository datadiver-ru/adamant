'use strict';
/**
 * Что это за порт - простыми словами, и можно ли его закрыть.
 * Порт «закрывается» правилом брандмауэра Windows: программа работает как раньше,
 * но подключиться к ней с других устройств нельзя. Правило ставит и убирает исправление port-block.
 *
 * Оценки:
 *   system   - часть Windows, трогать не нужно (кнопки «Закрыть» нет);
 *   normal   - нормально, закрывать незачем, но можно;
 *   optional - можно закрыть, если не пользуетесь;
 *   close    - лучше закрыть;
 *   unknown  - незнакомая программа: проверьте, знаете ли вы её;
 *   local    - доступен только с этого компьютера, делать ничего не нужно.
 */
const { tx, t } = require('./i18n');
const { arr } = require('./rules');

/** Порты из этого диапазона Windows раздаёт программам на время: номер меняется после перезапуска. */
const DYNAMIC_FROM = 49152;
/** Эти порты нельзя закрывать никогда: без них пропадёт сеть (адрес от роутера, время, служебная связь Windows). */
const NEVER = new Set(['udp:67', 'udp:68', 'udp:546', 'udp:547', 'tcp:135', 'udp:123']);
/** Системные процессы Windows: правило «по программе» для них поставить нельзя - закрылось бы всё сразу. */
const SYSTEM_PROCS = new Set(['system', 'svchost', 'lsass', 'wininit', 'services', 'spoolsv', 'idle', 'searchindexer', 'smss', 'csrss', 'winlogon', 'dllhost', 'msmpeng', 'registry']);
const MAX_ITEMS = 40;

const SHARED_ACCESS = {
  name: t('Общий доступ к интернету'),
  what: t('Windows раздаёт адреса и DNS виртуальным машинам, WSL или точке доступа на этом компьютере. Порт открыт только для этой внутренней сети.'),
  verdict: 'system',
};
const DYNAMIC_SYSTEM = {
  name: t('Служебный порт Windows'),
  what: t('Через такие порты службы Windows связываются между собой. Номер меняется после перезагрузки, а снаружи их закрывает брандмауэр.'),
  verdict: 'system',
};

/** Известные порты. Ключ - «tcp:445», «udp:1900» или «any:3389». */
const BY_PORT = {
  'any:21': { name: 'FTP', what: t('Передача файлов по старому протоколу FTP. Пароли и файлы идут по сети без шифрования.'), breaks: t('Перестанет работать FTP-сервер на этом компьютере.'), verdict: 'close' },
  'tcp:22': { name: t('SSH - удалённая командная строка'), what: t('Через SSH к компьютеру подключаются и управляют им из командной строки. Обычно его включают программисты и администраторы.'), breaks: t('К этому компьютеру нельзя будет подключиться по SSH.'), verdict: 'optional' },
  'tcp:23': { name: 'Telnet', what: t('Очень старый способ удалённо управлять компьютером. Пароли идут открытым текстом.'), breaks: t('Перестанет работать сервер Telnet - он почти никогда не нужен.'), verdict: 'close', home: true },
  'any:53': { name: t('DNS-сервер'), what: t('Программа на этом компьютере отвечает другим устройствам, по какому адресу находится сайт.'), breaks: t('Другие устройства не смогут пользоваться этим компьютером как DNS-сервером.'), verdict: 'optional' },
  'udp:67': { name: t('DHCP - раздача адресов'), what: t('Нужен, чтобы устройства получали адрес в сети. Закрывать нельзя.'), verdict: 'system' },
  'udp:68': { name: t('DHCP - получение адреса'), what: t('Через этот порт компьютер получает адрес от роутера. Без него пропадёт сеть.'), verdict: 'system' },
  'tcp:80': { name: t('Веб-сервер (HTTP)'), what: t('Программа на этом компьютере показывает сайт или страницу управления другим устройствам.'), breaks: t('Другие устройства не смогут открыть этот сайт или страницу.'), verdict: 'optional' },
  'udp:123': { name: t('Синхронизация времени'), what: t('Windows сверяет часы с сервером времени. Закрывать не нужно.'), verdict: 'system' },
  'tcp:135': { name: t('Служба RPC Windows'), what: t('Через этот порт программы Windows договариваются друг с другом. Без него Windows не работает, а снаружи его закрывает брандмауэр.'), verdict: 'system' },
  'udp:137': { name: t('NetBIOS - имена в сети'), what: t('Старый способ находить компьютеры по имени. Сейчас его заменяют DNS и mDNS.'), breaks: t('Очень старые устройства могут не найти этот компьютер по имени.'), verdict: 'optional', home: true },
  'udp:138': { name: t('NetBIOS - рассылки в сети'), what: t('Старый способ сообщать о себе другим компьютерам. Сейчас почти не нужен.'), breaks: t('Очень старые устройства могут не увидеть этот компьютер в сети.'), verdict: 'optional', home: true },
  'tcp:139': { name: t('NetBIOS - общие папки (старый способ)'), what: t('Старый вход к общим папкам. Новые устройства ходят через порт 445.'), breaks: t('Очень старые устройства (до Windows 2000) не откроют общие папки.'), verdict: 'optional', home: true },
  'tcp:443': { name: t('Веб-сервер (HTTPS)'), what: t('Программа на этом компьютере показывает защищённый сайт или страницу управления другим устройствам.'), breaks: t('Другие устройства не смогут открыть этот сайт или страницу.'), verdict: 'optional' },
  'tcp:445': { name: t('Общие папки и принтеры (SMB)'), what: t('Через него другие компьютеры открывают ваши общие папки и принтер. Это самый атакуемый порт Windows, но дома он часто нужен.'), breaks: t('Другие устройства не смогут открыть общие папки и принтер этого компьютера. Чужие папки вы открывать сможете.'), verdict: 'optional' },
  'udp:500': { name: t('VPN (IPsec)'), what: t('Нужен для VPN-подключений средствами Windows.'), breaks: t('Может перестать работать VPN, который принимает подключения на этом компьютере.'), verdict: 'normal' },
  'udp:4500': { name: t('VPN (IPsec)'), what: t('Нужен для VPN-подключений средствами Windows.'), breaks: t('Может перестать работать VPN, который принимает подключения на этом компьютере.'), verdict: 'normal' },
  'udp:546': { name: t('DHCPv6 - получение адреса'), what: t('Через этот порт компьютер получает адрес IPv6. Закрывать нельзя.'), verdict: 'system' },
  'any:554': { name: t('Видеопоток (RTSP)'), what: t('Программа на этом компьютере отдаёт видео по сети, как камера.'), breaks: t('Другие устройства не смогут смотреть этот видеопоток.'), verdict: 'optional' },
  'tcp:631': { name: t('Печать по сети (IPP)'), what: t('Этот компьютер принимает задания печати от других устройств.'), breaks: t('Другие устройства не смогут печатать через этот компьютер.'), verdict: 'optional' },
  'tcp:1433': { name: 'SQL Server', what: t('База данных принимает подключения из сети. Базы данных - любимая цель взломщиков.'), breaks: t('Программы на других компьютерах не смогут подключиться к этой базе. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'tcp:1883': { name: t('MQTT (умный дом)'), what: t('Сервер для устройств умного дома. Часто работает без пароля.'), breaks: t('Устройства умного дома не смогут связаться с этим компьютером.'), verdict: 'optional' },
  'udp:1900': { name: t('SSDP - поиск устройств в сети'), what: t('Windows ищет в сети телевизоры, приставки и медиаплееры.'), breaks: t('Windows может не находить телевизоры и медиаплееры, чтобы вывести на них видео.'), verdict: 'optional', home: true },
  'udp:2177': { name: t('qWave - качество звука и видео'), what: t('Windows проверяет качество домашней сети для звонков и видео.'), breaks: t('Почти ничего не изменится.'), verdict: 'normal', home: true },
  'tcp:2179': { name: t('Hyper-V: экран виртуальных машин'), what: t('Через этот порт открывается экран виртуальных машин Hyper-V с других компьютеров.'), breaks: t('С других компьютеров нельзя будет открыть экран виртуальных машин. На этом компьютере всё работает.'), verdict: 'optional', home: true },
  'tcp:2375': { name: t('Docker без пароля'), what: t('Управление Docker без шифрования и пароля. Кто подключится - получит полный доступ к компьютеру.'), breaks: t('Управлять Docker с других компьютеров будет нельзя. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'tcp:2869': { name: t('Узел UPnP'), what: t('Компьютер рассказывает о себе устройствам UPnP: телевизорам и медиаплеерам.'), breaks: t('Телевизоры могут не увидеть медиатеку этого компьютера.'), verdict: 'optional', home: true },
  'tcp:3306': { name: 'MySQL', what: t('База данных принимает подключения из сети. Базы данных - любимая цель взломщиков.'), breaks: t('Программы на других компьютерах не смогут подключиться к этой базе. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'any:3389': { name: t('Удалённый рабочий стол (RDP)'), what: t('Позволяет подключиться к этому компьютеру и управлять им по сети. Его постоянно пытаются взломать подбором пароля.'), breaks: t('Нельзя будет подключиться к этому компьютеру удалённо.'), verdict: 'optional' },
  'udp:3702': { name: t('Обнаружение сети (WS-Discovery)'), what: t('Компьютер ищет в сети принтеры и сканеры и сообщает о себе.'), breaks: t('Новые принтеры и сканеры в сети могут находиться не сами.'), verdict: 'optional', home: true },
  'tcp:5040': { name: t('Платформа подключённых устройств'), what: t('Связь с телефоном и другими вашими компьютерами: «Связь с телефоном», «Поделиться с устройствами поблизости».'), breaks: t('Может перестать работать «Поделиться с устройствами поблизости».'), verdict: 'normal' },
  'udp:5050': { name: t('Платформа подключённых устройств'), what: t('Связь с телефоном и другими вашими компьютерами: «Связь с телефоном», «Поделиться с устройствами поблизости».'), breaks: t('Может перестать работать «Поделиться с устройствами поблизости».'), verdict: 'normal' },
  'udp:5353': { name: t('mDNS - поиск устройств рядом'), what: t('Программы ищут в сети принтеры, колонки и телевизоры. Так делают браузеры, Spotify, iTunes и многие другие.'), breaks: t('Программы могут не найти колонки, телевизоры и принтеры в сети.'), verdict: 'normal' },
  'udp:5355': { name: t('LLMNR - поиск компьютеров по имени'), what: t('Старый способ найти компьютер по имени без DNS. Им пользуются, чтобы перехватить пароль в чужой сети.'), breaks: t('Почти ничего: имена находятся через DNS и mDNS.'), verdict: 'optional', home: true },
  'tcp:5357': { name: t('Обнаружение сети (WSD)'), what: t('Компьютер сообщает о себе, чтобы его видели другие в разделе «Сеть» проводника.'), breaks: t('Другие компьютеры не увидят этот в разделе «Сеть». Открыть его по имени можно будет как раньше.'), verdict: 'optional', home: true },
  'tcp:5358': { name: t('Обнаружение сети (WSD)'), what: t('Компьютер сообщает о себе, чтобы его видели другие в разделе «Сеть» проводника.'), breaks: t('Другие компьютеры не увидят этот в разделе «Сеть». Открыть его по имени можно будет как раньше.'), verdict: 'optional', home: true },
  'tcp:5432': { name: 'PostgreSQL', what: t('База данных принимает подключения из сети. Базы данных - любимая цель взломщиков.'), breaks: t('Программы на других компьютерах не смогут подключиться к этой базе. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'tcp:5555': { name: t('Android по сети (ADB)'), what: t('Управление телефоном или эмулятором Android по сети, для программистов.'), breaks: t('Подключиться к Android по сети через этот компьютер будет нельзя.'), verdict: 'optional', home: true },
  'tcp:5900': { name: t('VNC - управление экраном'), what: t('Через VNC видят ваш экран и управляют мышью. Часто его защищает только короткий пароль.'), breaks: t('Подключиться к экрану этого компьютера по VNC будет нельзя.'), verdict: 'close', home: true },
  'tcp:5901': { name: t('VNC - управление экраном'), what: t('Через VNC видят ваш экран и управляют мышью. Часто его защищает только короткий пароль.'), breaks: t('Подключиться к экрану этого компьютера по VNC будет нельзя.'), verdict: 'close', home: true },
  'tcp:5985': { name: t('Удалённое управление Windows (WinRM)'), what: t('Через WinRM администраторы выполняют команды на компьютере по сети.'), breaks: t('Управлять этим компьютером через PowerShell по сети будет нельзя.'), verdict: 'optional', home: true },
  'tcp:5986': { name: t('Удалённое управление Windows (WinRM)'), what: t('Через WinRM администраторы выполняют команды на компьютере по сети.'), breaks: t('Управлять этим компьютером через PowerShell по сети будет нельзя.'), verdict: 'optional', home: true },
  'tcp:6379': { name: 'Redis', what: t('База данных Redis по умолчанию работает без пароля: кто подключится, тот и хозяин.'), breaks: t('Программы на других компьютерах не смогут подключиться к Redis. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'tcp:7680': { name: t('Оптимизация доставки Windows'), what: t('Windows раздаёт скачанные обновления другим компьютерам вашей сети, чтобы каждый не качал их заново.'), breaks: t('Компьютеры в сети будут скачивать обновления каждый сам. Обновления работают как раньше.'), verdict: 'optional', home: true },
  'tcp:9200': { name: 'Elasticsearch', what: t('Поисковая база данных. По умолчанию отдаёт данные без пароля.'), breaks: t('Программы на других компьютерах не смогут подключиться к базе. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'tcp:10243': { name: t('Общий доступ к медиатеке Windows'), what: t('Windows Media Player отдаёт музыку и видео телевизорам в сети.'), breaks: t('Телевизоры не увидят медиатеку этого компьютера.'), verdict: 'optional', home: true },
  'any:11211': { name: 'Memcached', what: t('Кэш для сайтов без пароля. Его используют для атак на другие сайты.'), breaks: t('Программы на других компьютерах не смогут к нему подключиться.'), verdict: 'close', home: true },
  'tcp:27017': { name: 'MongoDB', what: t('База данных MongoDB в старых настройках работает без пароля.'), breaks: t('Программы на других компьютерах не смогут подключиться к этой базе. На этом компьютере всё работает.'), verdict: 'close', home: true },
  'any:27036': { name: t('Steam: игры по домашней сети'), what: t('Steam передаёт игры и запускает Remote Play на других компьютерах вашей сети.'), breaks: t('Не будет работать передача игр и Remote Play между компьютерами дома.'), verdict: 'optional' },
  'any:57621': { name: t('Spotify: устройства рядом'), what: t('Spotify находит колонки и телефоны в вашей сети, чтобы включать музыку на них.'), breaks: t('Spotify на этом компьютере может не увидеть колонки и телефоны.'), verdict: 'normal' },
};

/** Программы, если порт не из списка. Ключ - имя процесса без .exe, маленькими буквами. */
const BY_PROC = {
  steam: BY_PORT['any:27036'],
  spotify: BY_PORT['any:57621'],
  teamviewer: { name: t('TeamViewer - удалённое управление'), what: t('Программа удалённого управления: через неё видят экран и управляют компьютером. Если вы её не ставили - это опасно.'), breaks: t('К этому компьютеру нельзя будет подключиться через TeamViewer напрямую по сети.'), verdict: 'optional' },
  teamviewer_service: null,
  anydesk: { name: t('AnyDesk - удалённое управление'), what: t('Программа удалённого управления: через неё видят экран и управляют компьютером. Если вы её не ставили - это опасно.'), breaks: t('Подключения AnyDesk напрямую по сети перестанут работать.'), verdict: 'optional' },
  rustdesk: { name: t('RustDesk - удалённое управление'), what: t('Программа удалённого управления: через неё видят экран и управляют компьютером. Если вы её не ставили - это опасно.'), breaks: t('Подключения RustDesk напрямую по сети перестанут работать.'), verdict: 'optional' },
  nvcontainer: { name: t('NVIDIA: трансляция игр'), what: t('Программа NVIDIA передаёт игры на другие устройства в сети.'), breaks: t('Трансляция игр NVIDIA на другие устройства перестанет работать.'), verdict: 'optional', home: true },
  onedrive: { name: t('OneDrive'), what: t('Облачное хранилище Microsoft.'), breaks: t('Обмен файлами OneDrive напрямую по сети перестанет работать. Синхронизация через интернет останется.'), verdict: 'optional' },
  dropbox: { name: t('Dropbox: обмен файлами по домашней сети'), what: t('Dropbox передаёт файлы между вашими компьютерами напрямую по домашней сети - так быстрее.'), breaks: t('Файлы будут идти через интернет, чуть медленнее.'), verdict: 'optional', home: true },
  adb: { name: t('Android Debug Bridge (для программистов)'), what: t('Связь с телефоном или эмулятором Android для разработки программ.'), breaks: t('Подключиться к Android по сети через этот компьютер будет нельзя.'), verdict: 'optional', home: true },
  ollama: { name: t('Ollama: нейросеть на этом компьютере'), what: t('Ollama принимает запросы к нейросети. Открыть её для всей сети - значит дать любому пользоваться ею.'), breaks: t('Другие устройства не смогут обращаться к нейросети на этом компьютере.'), verdict: 'optional', home: true },
  postgres: BY_PORT['tcp:5432'],
  mysqld: BY_PORT['tcp:3306'],
  'redis-server': BY_PORT['tcp:6379'],
  mongod: BY_PORT['tcp:27017'],
  sqlservr: BY_PORT['tcp:1433'],
  vmms: BY_PORT['tcp:2179'],
};
BY_PROC.teamviewer_service = BY_PROC.teamviewer;
for (const b of ['chrome', 'msedge', 'firefox', 'brave', 'opera', 'browser', 'vivaldi']) {
  BY_PROC[b] = { name: t('Браузер ищет устройства рядом'), what: t('Браузер ищет в сети телевизоры и колонки, чтобы показать на них вкладку или видео.'), breaks: t('Браузер может не найти телевизор или колонку для трансляции.'), verdict: 'normal' };
}
for (const d of ['python', 'pythonw', 'node', 'java', 'javaw', 'ruby', 'php', 'dotnet', 'deno', 'bun']) {
  BY_PROC[d] = { name: t('Программа для разработки'), what: t('Обычно это сервер, который вы или программист запустили для проверки сайта или программы. Его часто забывают выключить.'), breaks: t('Другие устройства не смогут открыть этот сервер. На этом компьютере он работает как раньше.'), verdict: 'optional', home: true };
}

/** Службы Windows, если порт не из списка. Ключ - имя службы маленькими буквами. */
const BY_SERVICE = {
  sharedaccess: SHARED_ACCESS,
  termservice: BY_PORT['any:3389'],
  sshd: BY_PORT['tcp:22'],
  w3svc: BY_PORT['tcp:80'],
  winrm: BY_PORT['tcp:5985'],
  upnphost: BY_PORT['tcp:2869'],
  ssdpsrv: BY_PORT['udp:1900'],
  fdrespub: BY_PORT['tcp:5357'],
  wmpnetworksvc: BY_PORT['tcp:10243'],
  dosvc: BY_PORT['tcp:7680'],
  cdpsvc: BY_PORT['tcp:5040'],
  ikeext: BY_PORT['udp:500'],
  w32time: BY_PORT['udp:123'],
  spooler: { name: t('Диспетчер печати'), what: t('Служба печати Windows. Если принтер не общий, снаружи к ней не подключаются.'), breaks: t('Другие компьютеры не смогут печатать на ваш общий принтер.'), verdict: 'system' },
};

const procName = (p) => String((p && p.proc) || '').toLowerCase().replace(/\.exe$/, '');
const isLoopback = (a) => /^127\./.test(a) || a === '::1';
const underWindows = (p) => /^[a-z]:\\windows\\/i.test(String(p || ''));

/** Описание одного порта (без учёта того, закрыт ли он). */
function describe(row) {
  const proto = row.proto === 'udp' ? 'udp' : 'tcp';
  const services = arr(row.services).map((s) => String(s).toLowerCase());
  const proc = procName(row);
  if (services.includes('sharedaccess')) return SHARED_ACCESS;
  if (row.port >= DYNAMIC_FROM && (SYSTEM_PROCS.has(proc) || services.length)) return DYNAMIC_SYSTEM;
  const byPort = BY_PORT[`${proto}:${row.port}`] || BY_PORT[`any:${row.port}`];
  if (byPort) return byPort;
  for (const s of services) if (BY_SERVICE[s]) return BY_SERVICE[s];
  // python3.13, node22 - без номера версии.
  const byProc = BY_PROC[proc] || BY_PROC[proc.replace(/[\d._-]+$/, '')];
  if (byProc) return byProc;
  if (SYSTEM_PROCS.has(proc)) return { name: t('Служба Windows'), what: t('Порт открыла служба Windows. Обычно снаружи его закрывает брандмауэр.'), breaks: t('Может перестать работать служба Windows, которой нужен этот порт.'), verdict: 'normal' };
  return {
    name: t('Незнакомая программа'),
    what: row.proc ? tx('Порт открыла программа «{0}». Адамант её не знает. Если и вы её не знаете, закройте порт и проверьте программу антивирусом.', row.proc) : t('Адамант не смог узнать, какая программа открыла порт. Если он вам не нужен, закройте его.'),
    breaks: t('Программа не сможет принимать подключения с других устройств. На этом компьютере она работает как раньше.'),
    verdict: 'unknown',
  };
}

/** Активные сети, у которых выключен брандмауэр: правило в них не сработает. */
function firewallOff(facts) {
  const profiles = arr(facts.firewall && facts.firewall.profiles);
  const nets = arr(facts.firewall && facts.firewall.networks);
  const map = { Public: 'Public', Private: 'Private', DomainAuthenticated: 'Domain' };
  const active = new Set(nets.map((n) => map[n.category]).filter(Boolean));
  const off = profiles.filter((p) => String(p.enabled) === 'False');
  return (active.size ? off.filter((p) => active.has(p.name)) : off).map((p) => p.name);
}

/** Что уже закрыл Адамант: по журналу исправлений, только не откаченное. */
function blockedByJournal(journal) {
  const m = new Map();
  for (const e of arr(journal)) {
    if (e.id !== 'port-block' || e.undoneAt || !e.arg) continue;
    for (const it of arr(e.arg.items)) m.set(itemKey(it), e.record);
  }
  return m;
}
const itemKey = (it) => (it.kind === 'program' ? `program:${String(it.path).toLowerCase()}` : `${it.proto}:${it.port}`);

/**
 * Все порты из проверки - с описанием, оценкой и тем, как его закрыть.
 * Строка: proto, port, pid, proc, path, addrs, scope, info, close (что закрыть) или why (почему нельзя), blocked (запись журнала).
 */
function annotate(facts, journal) {
  const p = (facts && facts.ports) || {};
  const rows = new Map();
  for (const x of [...arr(p.tcp), ...arr(p.udp)]) {
    const proto = x.proto === 'udp' ? 'udp' : 'tcp';
    const k = `${proto}:${x.port}:${x.pid}`;
    if (!rows.has(k)) rows.set(k, { proto, port: Number(x.port), pid: x.pid, proc: x.proc || null, path: x.path || null, services: arr(x.services), addrs: [] });
    const r = rows.get(k);
    if (!r.addrs.includes(String(x.addr))) r.addrs.push(String(x.addr));
  }
  const blocked = blockedByJournal(journal);
  const out = [];
  for (const r of rows.values()) {
    const scope = r.addrs.some((a) => a === '0.0.0.0' || a === '::') ? 'net' : r.addrs.every(isLoopback) ? 'local' : 'addr';
    const info = describe(r);
    let close = null;
    let why = null;
    if (scope === 'local') why = t('К этому порту можно подключиться только с этого компьютера. Закрывать нечего.');
    else if (info.verdict === 'system' || NEVER.has(`${r.proto}:${r.port}`)) why = t('Это часть Windows. Закрывать его не нужно: можно сломать сеть или Windows.');
    else if (r.port < DYNAMIC_FROM) close = { kind: 'port', proto: r.proto, port: r.port };
    else if (r.path && !underWindows(r.path) && !SYSTEM_PROCS.has(procName(r))) close = { kind: 'program', path: r.path, name: r.proc || r.path };
    else why = t('Номер этого порта меняется при каждом запуске программы, а саму программу не удалось определить. Если она не нужна, удалите её.');
    const rec = close ? blocked.get(itemKey(close)) : null;
    out.push({
      proto: r.proto, port: r.port, pid: r.pid, proc: r.proc, path: r.path, services: r.services, addrs: r.addrs, scope,
      info: { name: info.name, what: info.what, breaks: info.breaks || null, verdict: scope === 'local' ? 'local' : info.verdict, home: !!info.home },
      close, why, blocked: rec || null,
    });
  }
  out.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
  return { items: out, firewallOff: firewallOff(facts || {}) };
}

/**
 * Проверенный список для исправления port-block. Берём только то, что есть в последней проверке
 * и что annotate() разрешил закрыть; путь программы - из проверки, а не из запроса.
 */
function validateBlock(facts, arg) {
  const want = arr(arg && arg.items);
  if (!want.length) throw new Error(t('Не выбран ни один порт'));
  if (want.length > MAX_ITEMS) throw new Error(tx('За один раз можно закрыть не больше {0} портов', MAX_ITEMS));
  const { items, firewallOff: off } = annotate(facts, []);
  if (off.length) throw new Error(t('Брандмауэр выключен, и правило не сработает. Сначала включите брандмауэр.'));
  const out = [];
  const seen = new Set();
  for (const w of want) {
    let hit = null;
    if (w && w.kind === 'program') {
      hit = items.find((i) => i.close && i.close.kind === 'program' && String(i.close.path).toLowerCase() === String(w.path || '').toLowerCase());
    } else if (w && (w.proto === 'tcp' || w.proto === 'udp') && Number.isInteger(w.port)) {
      hit = items.find((i) => i.close && i.close.kind === 'port' && i.close.proto === w.proto && i.close.port === w.port);
    }
    if (!hit) throw new Error(t('Этот порт закрыть нельзя или его уже нет - обновите проверку'));
    const item = hit.close.kind === 'program' ? { kind: 'program', path: hit.close.path, name: String(hit.close.name).slice(0, 120) } : { kind: 'port', proto: hit.close.proto, port: hit.close.port, name: String(hit.info.name).slice(0, 120) };
    const k = itemKey(item);
    if (seen.has(k)) continue;
    seen.add(k);
    item.breaks = hit.info.breaks;
    out.push(item);
  }
  // Аргумент уходит в fix.ps1 в командной строке - там есть предел длины.
  if (Buffer.byteLength(JSON.stringify(toScript({ items: out })), 'utf8') > 5500) throw new Error(t('Слишком много за один раз: закройте порты в несколько приёмов'));
  return { items: out };
}

/** Что уйдёт в fix.ps1: без пояснений для человека. */
const toScript = (a) => ({ items: a.items.map((i) => (i.kind === 'program' ? { kind: 'program', path: i.path } : { kind: 'port', proto: i.proto, port: i.port })) });

module.exports = { annotate, describe, validateBlock, toScript, BY_PORT, BY_PROC, BY_SERVICE, NEVER, DYNAMIC_FROM, MAX_ITEMS };
