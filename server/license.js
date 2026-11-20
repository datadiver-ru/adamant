'use strict';
/**
 * Бесплатная и полная версии. Ключ полной версии проверяется на этом компьютере, без интернета:
 * он подписан закрытым ключом автора (Ed25519), программа сверяет подпись со встроенным открытым ключом.
 * Подделать или «продлить» ключ без закрытого ключа нельзя. Закрытый ключ хранится только у автора
 * (вне проекта и дистрибутива), ключи выдаёт tools/license.js.
 *
 * Формат: ADAMANT1.<base64url(JSON)>.<base64url(подпись)>
 * JSON: { id, licensee, issuedAt, expires|null, edition: 'full' }
 *
 * Бесплатная версия не прячет угрозы: проверка, находки, исправления, Страж, сеть, чек-лист и отчёт
 * работают полностью. В полной версии - дополнительные разделы (FEATURES). Если сопряжено устройство для атак,
 * бесплатная версия всё равно о нём скажет.
 */
const crypto = require('node:crypto');
const { t } = require('./i18n');

const VENDOR_PUBLIC_KEY = 'MCowBQYDK2VwAyEAR0zTblNtnyFpJ2NKej+AOWuiZtdwPOvf4MvD+Az8fWE=';
const PREFIX = 'ADAMANT1';

/** Разделы полной версии. */
const FEATURES = ['bluetooth', 'entry', 'drills', 'away', 'realtime', 'panic', 'telegram', 'ports'];

function publicKey(b64 = VENDOR_PUBLIC_KEY) {
  return crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

const today = (ms = Date.now()) => new Date(ms).toISOString().slice(0, 10);

/** Разбор и проверка ключа; бросает ошибку с понятным текстом. */
function parse(text, { pub = publicKey(), now = Date.now() } = {}) {
  const m = /^ADAMANT1\.([A-Za-z0-9_-]{10,2000})\.([A-Za-z0-9_-]{60,200})$/.exec(String(text || '').replace(/\s+/g, ''));
  if (!m) throw new Error(t('Это не ключ Адаманта: скопируйте его целиком, начиная с ADAMANT1.'));
  const payload = Buffer.from(m[1], 'base64url');
  let ok = false;
  try { ok = crypto.verify(null, payload, pub, Buffer.from(m[2], 'base64url')); } catch { ok = false; }
  if (!ok) throw new Error(t('Подпись ключа не сходится: ключ изменён или выдан не автором Адаманта.'));
  let lic;
  try { lic = JSON.parse(payload.toString('utf8')); } catch { lic = null; }
  if (!lic || typeof lic !== 'object' || lic.edition !== 'full') throw new Error(t('Ключ повреждён'));
  const expires = typeof lic.expires === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(lic.expires) ? lic.expires : null;
  return {
    id: String(lic.id || '').slice(0, 64), licensee: String(lic.licensee || '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 80),
    issuedAt: String(lic.issuedAt || '').slice(0, 10), edition: 'full', expires, expired: !!(expires && expires < today(now)),
  };
}

/** Подписать ключ (инструмент автора). */
function issue(lic, privateKeyPem) {
  const body = { id: crypto.randomUUID(), issuedAt: today(), edition: 'full', expires: null, ...lic };
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  const sig = crypto.sign(null, payload, crypto.createPrivateKey(privateKeyPem));
  return `${PREFIX}.${payload.toString('base64url')}.${sig.toString('base64url')}`;
}

/** Что сейчас доступно. Просроченный ключ ведёт себя как бесплатная версия. */
function status(lic) {
  const full = !!(lic && !lic.expired);
  const features = Object.fromEntries(FEATURES.map((f) => [f, full]));
  if (!lic) return { edition: 'free', licensee: null, expires: null, expired: false, features };
  return { edition: full ? 'full' : 'free', licensee: lic.licensee, expires: lic.expires, expired: lic.expired, id: lic.id, features };
}

module.exports = { parse, issue, status, publicKey, FEATURES, VENDOR_PUBLIC_KEY, PREFIX };
