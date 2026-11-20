'use strict';
/**
 * Подозрительные блоки PowerShell из журнала Windows (событие 4104, которое Windows сама пометила).
 * events.ps1 отдаёт свежие блоки как есть, а «сильный» признак - код скачивается из интернета
 * и сразу запускается - ищем здесь. В сценарии PowerShell такие образцы держать нельзя:
 * антивирус проверяет его текст при запуске и принимает за инструмент атаки.
 *
 * digestFacts(facts) заменяет facts.events.powershell на { suspicious, strong, samples } до сохранения
 * отчёта: сами тексты блоков в report.json не попадают (кроме пяти коротких примеров).
 */
const DL = String.raw`DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|\biwr\b`;
const EX = String.raw`\bIEX\b|Invoke-E[x]pression`;
const STRONG = new RegExp(`(?:${DL}).{0,300}(?:${EX})|(?:${EX}).{0,100}(?:DownloadString|FromBase64String)`, 'i');

const short = (s, n) => (String(s || '').length > n ? String(s).slice(0, n - 1) + '…' : String(s || ''));

function digest(psr) {
  // Старый ответ (помощник прошлой версии): strong уже посчитан в PowerShell.
  if (!psr || typeof psr !== 'object' || !Array.isArray(psr.blocks)) return psr;
  const strong = [];
  const weak = [];
  for (const b of psr.blocks) {
    if (!b || typeof b.text !== 'string') continue;
    const one = { at: b.at || null, path: b.path || '', text: short(b.text, 150) };
    if (STRONG.test(b.text)) strong.push(one);
    else weak.push(one);
  }
  return { suspicious: Number(psr.suspicious) || 0, strong: strong.length, samples: [...strong.slice(0, 5), ...weak.slice(0, 3)].slice(0, 5) };
}

function digestFacts(facts) {
  if (facts && facts.events && facts.events.powershell) facts.events.powershell = digest(facts.events.powershell);
  return facts;
}

module.exports = { digest, digestFacts, STRONG };
