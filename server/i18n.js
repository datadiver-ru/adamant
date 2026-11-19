'use strict';
/**
 * Тексты. Исходный язык - русский. Сообщение - либо строка, либо { k: 'шаблон {0}', a: [аргументы] }.
 * Сервер собирает находки на русском; интерфейс и отчёт переводят их по словарю public/i18n-en.js
 * (тот же файл читает браузер: window.ADAMANT_EN). Ключ словаря - исходная русская строка.
 */
const fs = require('node:fs');
const path = require('node:path');

/** Сообщение с подстановками. Аргументы тоже могут быть сообщениями. */
function tx(k, ...a) {
  return a.length ? { k, a } : k;
}
/** Простая строка для перевода (метка, чтобы её нашла проверка полноты словаря). */
const t = (s) => s;

let EN = null;
function dict() {
  if (EN) return EN;
  try {
    const src = fs.readFileSync(path.join(__dirname, '..', 'public', 'i18n-en.js'), 'utf8');
    const start = src.indexOf('{', src.indexOf('window.ADAMANT_EN'));
    const end = src.lastIndexOf('}');
    EN = new Map(Object.entries(JSON.parse(src.slice(start, end + 1))));
  } catch {
    EN = new Map();
  }
  return EN;
}

function fill(s, args) {
  return s.replace(/\{(\d+)\}/g, (m, i) => (args[i] === undefined ? m : String(args[i])));
}

/** Сообщение → текст на нужном языке. */
function render(lang, m) {
  if (m == null) return '';
  if (typeof m === 'number') return String(m);
  if (typeof m === 'string') return lang === 'en' && dict().has(m) ? dict().get(m) : m;
  if (typeof m === 'object' && typeof m.k === 'string') {
    const base = render(lang, m.k);
    // Аргументы-строки тоже переводятся, если это строка словаря («общедоступная сеть»); имена процессов и пути словарь не знает.
    return fill(base, (m.a || []).map((x) => (x && (typeof x === 'object' || typeof x === 'string') ? render(lang, x) : x)));
  }
  return String(m);
}

module.exports = { tx, t, render, dict };
