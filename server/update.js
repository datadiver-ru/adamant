'use strict';
/**
 * «Проверить обновления»: только по кнопке и только один запрос - список выпусков на GitHub.
 * Отправляется обычный GET без сведений о человеке и компьютере (даже номер своей версии не уходит).
 * Программа ничего не скачивает и не ставит: если вышла новая версия, она открывает страницу загрузки в браузере.
 */
const https = require('node:https');
const { t } = require('./i18n');

const REPO = 'datadiver-ru/adamant';
const RELEASES = `https://api.github.com/repos/${REPO}/releases?per_page=20`;
const PAGE_PREFIX = `https://github.com/${REPO}/releases/`;
const MAX_BYTES = 1024 * 1024;

class UpdateError extends Error {}

/** GET JSON с GitHub: таймаут, предел размера, только https. */
function getJson(url, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.hostname !== 'api.github.com') return reject(new UpdateError('host'));
    const req = https.request(u, { method: 'GET', headers: { 'User-Agent': 'Adamant-update-check', Accept: 'application/vnd.github+json' }, timeout }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => { size += c.length; if (size > MAX_BYTES) req.destroy(new UpdateError('too big')); else chunks.push(c); });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new UpdateError(`HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new UpdateError('json')); }
      });
    });
    req.on('timeout', () => req.destroy(new UpdateError('timeout')));
    req.on('error', (e) => reject(e));
    req.end();
  });
}

/** «v1.2.3» → [1, 2, 3]; что-то другое - null. */
function parseVersion(s) {
  const m = /^v?(\d{1,4})\.(\d{1,4})\.(\d{1,5})$/.exec(String(s || '').trim());
  return m ? m.slice(1).map(Number) : null;
}
function compare(a, b) {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/** Самый новый выпуск по номеру версии (черновики и теги не по образцу не считаются). */
function newest(list) {
  let best = null;
  for (const r of Array.isArray(list) ? list : []) {
    if (!r || r.draft) continue;
    const v = parseVersion(r.tag_name);
    if (!v) continue;
    if (!best || compare(v, best.v) > 0) best = { v, r };
  }
  return best;
}

/** Есть ли версия новее этой. Ссылку на выпуск отдаём, только если она ведёт в свой репозиторий. */
async function check({ version, fetch = getJson } = {}) {
  const mine = parseVersion(version);
  let list;
  try {
    list = await fetch(RELEASES);
  } catch {
    throw new UpdateError(t('Не удалось связаться с GitHub. Проверьте подключение к интернету и попробуйте ещё раз.'));
  }
  const best = newest(list);
  if (!best) throw new UpdateError(t('GitHub не вернул ни одного выпуска. Попробуйте позже.'));
  const page = typeof best.r.html_url === 'string' && best.r.html_url.startsWith(PAGE_PREFIX) ? best.r.html_url : null;
  return {
    current: version,
    latest: best.v.join('.'),
    newer: mine ? compare(best.v, mine) > 0 : true,
    beta: !!best.r.prerelease,
    publishedAt: typeof best.r.published_at === 'string' ? best.r.published_at : null,
    page,
  };
}

module.exports = { check, getJson, parseVersion, compare, newest, UpdateError, RELEASES };
