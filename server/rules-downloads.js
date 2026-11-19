'use strict';
/**
 * Скачанные файлы (раздел 'downloads', server/ps/sections/downloads.ps1): свежие программы и сценарии из интернета
 * в папке «Загрузки». Смотрим только файлы с отметкой Windows «скачано из интернета» (zone 3 или 4).
 *  - «Важно»: сценарии и ярлыки из интернета (.js, .vbs, .hta, .bat, .lnk…), файлы, которые притворяются документом
 *    («счёт.pdf.exe», скрытый разворот имени), и программы с повреждённой подписью;
 *  - «Совет»: программы без цифровой подписи, образы дисков, документы Office с макросами.
 * У находки есть files[] - { path, name, why } - для кнопок «Проверить антивирусом», «Показать в папке», «В корзину».
 */
const { tx, t } = require('./i18n');
const { unknown, arr } = require('./rules');

const SCRIPT = new Set(['.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.scr', '.pif', '.com', '.bat', '.cmd', '.ps1', '.lnk', '.reg', '.cpl', '.chm', '.jar']);
const PROGRAM = new Set(['.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.dll']);
const IMAGE = new Set(['.iso', '.img', '.vhd', '.vhdx']);
const MACRO = new Set(['.docm', '.xlsm', '.pptm']);
const MAX_FILES = 12;

function fileReason(i) {
  if (i.rtlo) return { sev: 'high', why: t('имя перевёрнуто скрытым символом: файл притворяется документом') };
  if (i.double) return { sev: 'high', why: t('двойное расширение: программа притворяется документом') };
  if (i.sig === 'bad') return { sev: 'high', why: t('цифровая подпись повреждена: файл изменили после подписи') };
  if (SCRIPT.has(i.ext)) return { sev: 'high', why: t('сценарий или ярлык из интернета: запускает команды сразу, без установки') };
  if (PROGRAM.has(i.ext) && i.sig === 'unsigned') return { sev: 'advice', why: t('программа без цифровой подписи: неизвестно, кто её сделал') };
  if (IMAGE.has(i.ext)) return { sev: 'advice', why: t('образ диска: внутри могут быть программы') };
  if (MACRO.has(i.ext)) return { sev: 'advice', why: t('документ с макросами: макросы могут запускать программы') };
  return null;
}

function evaluate(f) {
  const out = [];
  const d = f.downloads;
  if (!d) {
    if (f.errors && f.errors.downloads) out.push(unknown('dl', 'downloads', t('Скачанные файлы'), f.errors.downloads));
    return out;
  }
  const hits = { high: [], advice: [] };
  for (const i of arr(d.items)) {
    if (!(Number(i.zone) >= 3)) continue;
    const r = fileReason(i);
    if (r) hits[r.sev].push({ ...i, why: r.why });
  }
  const files = (list) => list.slice(0, MAX_FILES).map((i) => ({ path: i.path, name: i.name, why: i.why }));
  const ev = (list) => list.map((i) => tx('{0} - {1}{2}', i.name, i.why, i.host ? tx(' (с сайта {0})', i.host) : ''));
  if (hits.high.length) {
    out.push({
      id: 'dl-danger', cat: 'downloads', sev: 'high',
      title: tx('Опасные файлы в «Загрузках»: {0}', hits.high.length),
      text: t('Так обычно приходят вирусы: файл выглядит как документ или запускает команды сразу. Не открывайте его, если не уверены, откуда он. Проверьте антивирусом или удалите в корзину.'),
      evidence: ev(hits.high), files: files(hits.high),
    });
  }
  if (hits.advice.length) {
    out.push({
      id: 'dl-unsigned', cat: 'downloads', sev: 'advice',
      title: tx('Программы без подписи в «Загрузках»: {0}', hits.advice.length),
      text: t('У надёжных программ обычно есть цифровая подпись производителя. Без неё нельзя проверить, кто сделал файл и не подменили ли его. Запускайте такое, только если скачали с официального сайта, а лучше сначала проверьте антивирусом.'),
      evidence: ev(hits.advice), files: files(hits.advice),
    });
  }
  if (!out.length) {
    out.push({ id: 'dl-ok', cat: 'downloads', sev: 'ok', title: t('В «Загрузках» нет подозрительных файлов'), text: t('За последние 30 дней из интернета скачаны только подписанные программы или ничего опасного.'), evidence: [] });
  }
  return out;
}

/** Путь, с которым можно что-то делать по кнопке: только файлы из находок последней проверки. */
function allowedPath(findings, p) {
  const want = String(p || '');
  if (!want) return null;
  for (const fd of arr(findings)) for (const x of arr(fd.files)) if (x.path === want) return x;
  return null;
}

module.exports = { evaluate, fileReason, allowedPath };
