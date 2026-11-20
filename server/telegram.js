'use strict';
/**
 * Уведомления в Telegram (полная версия). ВЫКЛЮЧЕНЫ, пока человек сам не включит их в настройках.
 *
 * Как это устроено: человек создаёт своего бота у @BotFather, вставляет его ключ (token) и пишет боту любое
 * сообщение - «Адамант» находит этот чат (getUpdates) и дальше отправляет туда только короткие тревоги:
 * «Пока вас не было», приманки, Страж в реальном времени, «Тревога». Отчёты, файлы, имена файлов и списки
 * программ не отправляются. Запросы идут только на api.telegram.org и только когда включено.
 *
 * Файл telegram.json в папке данных (доступ только владельцу): { enabled, token, chatId, chatName, events, sent }.
 */
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { t, render } = require('./i18n');

const FILE = 'telegram.json';
const TOKEN_RE = /^\d{5,12}:[A-Za-z0-9_-]{30,}$/;
const EVENTS = ['away', 'canary', 'guard', 'panic'];
const DEFAULTS = { enabled: false, token: '', chatId: null, chatName: '', events: { away: true, canary: true, guard: true, panic: true }, sent: [], lastError: null, lastSentAt: null };
const GAP_MS = 1500; // Telegram не любит частые сообщения одному чату
const MAX_TEXT = 1500;

class TgError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** POST JSON на api.telegram.org (или base для проверок). */
function postJson(base, token, method, body, timeout = 15_000) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${base}/bot${token}/${method}`);
    const data = Buffer.from(JSON.stringify(body || {}));
    const lib = url.protocol === 'http:' ? require('node:http') : https;
    const req = lib.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }, timeout }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => { size += c.length; if (size > 512 * 1024) req.destroy(new Error('too big')); else chunks.push(c); });
      res.on('end', () => {
        let j = null;
        try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* не JSON */ }
        if (j && j.ok) return resolve(j.result);
        const code = res.statusCode === 401 || res.statusCode === 404 ? 'TOKEN' : res.statusCode === 403 ? 'BLOCKED' : res.statusCode === 400 ? 'CHAT' : 'TG';
        reject(new TgError(code, (j && j.description) || `HTTP ${res.statusCode}`));
      });
    });
    req.on('timeout', () => req.destroy(new TgError('NET', 'timeout')));
    req.on('error', (e) => reject(e instanceof TgError ? e : new TgError('NET', e.message)));
    req.end(data);
  });
}

const REASON = {
  TOKEN: t('Telegram не принял ключ бота. Проверьте, что скопировали его целиком.'),
  BLOCKED: t('Бот не может написать вам: откройте чат с ботом и нажмите «Запустить» (Start).'),
  CHAT: t('Чат не найден. Напишите боту любое сообщение и нажмите «Найти чат» ещё раз.'),
  NET: t('Нет связи с Telegram. Проверьте интернет.'),
  TG: t('Telegram ответил ошибкой. Попробуйте позже.'),
};

function createTelegram({ dataDir, store = null, base = 'https://api.telegram.org', post = postJson, now = () => Date.now(), lang = () => 'ru' } = {}) {
  const file = path.join(dataDir, FILE);
  let queue = Promise.resolve();
  let lastSend = 0;

  function read() {
    let j = {};
    // С store токен лежит зашифрованным (server/vault.js); без него (тесты) - обычным файлом.
    try { j = store ? store.read(FILE, {}) || {} : JSON.parse(fs.readFileSync(file, 'utf8')); } catch { j = {}; }
    return { ...DEFAULTS, ...j, events: { ...DEFAULTS.events, ...(j.events || {}) }, sent: Array.isArray(j.sent) ? j.sent : [] };
  }
  function write(c) {
    if (store) store.write(FILE, c);
    else fs.writeFileSync(file, JSON.stringify(c, null, 1), { mode: 0o600 });
    return c;
  }

  function status() {
    const c = read();
    return {
      enabled: !!c.enabled, hasToken: !!c.token, tokenHint: c.token ? '…' + c.token.slice(-4) : '',
      chat: !!c.chatId, chatName: c.chatName || '', events: c.events, lastError: c.lastError, lastSentAt: c.lastSentAt,
    };
  }

  function save(patch = {}) {
    const c = read();
    if (typeof patch.token === 'string') {
      const tok = patch.token.trim();
      if (tok && !TOKEN_RE.test(tok)) throw new TgError('FORMAT', t('Это не похоже на ключ бота. Ключ выглядит так: 123456789:AAE… (цифры, двоеточие и длинный код).'));
      if (tok !== c.token) { c.token = tok; c.chatId = null; c.chatName = ''; c.enabled = false; }
    }
    if (patch.events && typeof patch.events === 'object') for (const k of EVENTS) if (typeof patch.events[k] === 'boolean') c.events[k] = patch.events[k];
    if (typeof patch.enabled === 'boolean') {
      if (patch.enabled && (!c.token || !c.chatId)) throw new TgError('SETUP', t('Сначала вставьте ключ бота и найдите чат.'));
      c.enabled = patch.enabled;
      // Включили - старые события «Пока вас не было» не присылаем.
      if (patch.enabled) c.primeAway = true;
    }
    if (patch.forget === true) Object.assign(c, { token: '', chatId: null, chatName: '', enabled: false, sent: [], lastError: null });
    c.lastError = patch.token !== undefined ? null : c.lastError;
    write(c);
    return status();
  }

  /** Найти чат: последний личный чат, где человек написал боту. */
  async function findChat() {
    const c = read();
    if (!c.token) throw new TgError('SETUP', t('Сначала вставьте ключ бота.'));
    const updates = await post(base, c.token, 'getUpdates', { limit: 50, allowed_updates: ['message'] });
    const msgs = (Array.isArray(updates) ? updates : []).map((u) => u && u.message).filter((m) => m && m.chat && m.chat.type === 'private');
    if (!msgs.length) return { found: false, ...status() };
    const m = msgs[msgs.length - 1];
    const c2 = read();
    c2.chatId = m.chat.id;
    c2.chatName = String(m.chat.first_name || m.chat.username || '').slice(0, 64);
    write(c2);
    return { found: true, ...status() };
  }

  function send(text, { force = false } = {}) {
    const job = queue.then(async () => {
      const c = read();
      if (!c.token || !c.chatId || (!c.enabled && !force)) return { sent: false };
      const wait = lastSend + GAP_MS - now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      try {
        await post(base, c.token, 'sendMessage', { chat_id: c.chatId, text: String(text).slice(0, MAX_TEXT), disable_web_page_preview: true });
        lastSend = now();
        const c2 = read();
        c2.lastSentAt = new Date(now()).toISOString();
        c2.lastError = null;
        write(c2);
        return { sent: true };
      } catch (e) {
        const c2 = read();
        c2.lastError = { code: e.code || 'TG', at: new Date(now()).toISOString() };
        write(c2);
        throw e;
      }
    });
    queue = job.catch(() => {});
    return job;
  }

  const head = () => (lang() === 'en' ? 'Adamant' : 'Адамант');

  function test() {
    return send(`${head()}: ${render(lang(), t('проверка связи. Сюда будут приходить тревоги с вашего компьютера.'))}`, { force: true });
  }

  /** Тревога из app.raiseAlert: { kind, ... } и готовый текст. */
  function notifyAlert(kind, text) {
    const c = read();
    if (!c.enabled || !c.events[kind]) return Promise.resolve({ sent: false });
    return send(`⚠ ${head()}: ${text}`).catch(() => ({ sent: false }));
  }

  /** «Пока вас не было»: тревожные отрезки (отчёт away.report). Каждый отрезок с новыми причинами - один раз. */
  function notifyAway(rep) {
    const c = read();
    if (!rep || !Array.isArray(rep.spans)) return [];
    const keys = rep.spans.filter((s) => s && s.level && s.level !== 'calm' && !s.confirmed).map((s) => ({ s, key: `${s.id}|${s.level}|${(s.reasons || []).slice().sort().join(',')}` }));
    if (c.primeAway || !c.enabled || !c.events.away) {
      // Не присылаем то, что было до включения: помечаем как отправленное.
      if (c.primeAway || c.enabled) {
        c.sent = [...new Set([...keys.map((x) => x.key), ...c.sent])].slice(0, 200);
        delete c.primeAway;
        write(c);
      }
      return [];
    }
    const fresh = keys.filter((x) => !c.sent.includes(x.key));
    if (!fresh.length) return [];
    c.sent = [...fresh.map((x) => x.key), ...c.sent].slice(0, 200);
    write(c);
    return fresh.map((x) => send(`⚠ ${head()}: ${render(lang(), x.s.headline)}`).catch(() => ({ sent: false })));
  }

  return { status, save, findChat, send, test, notifyAlert, notifyAway, REASON };
}

module.exports = { createTelegram, postJson, TOKEN_RE, TgError, REASON, EVENTS };
