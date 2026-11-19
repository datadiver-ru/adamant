'use strict';
/**
 * Индекс защищённости 0-100 и «чистота камня».
 *
 * Камень в окне светлеет, когда защита крепнет: чем меньше дыр, тем чище и ярче алмаз.
 * Ступени названы как у ювелиров (чистота алмаза), но простыми словами.
 * «Грани» - сколько проверок в порядке из всех, что удалось провести: каждое исправление добавляет камню грань.
 *
 * Правило счёта простое и предсказуемое (человек должен понимать, за что снимаются баллы):
 *   критично −20, важно −6 (вместе не больше −30), совет −1 (не больше −12), «не видно» −0,5 (не больше −4).
 *   Потолки нужны, чтобы десяток мелких советов не «чернил» камень: важно, что дыр нет, а не сколько мелочей можно ещё подкрутить.
 *   Пока есть хоть одна критичная находка, индекс не выше 49: камень не может быть «чистым» с открытой дырой.
 */
const { t } = require('./i18n');

const WEIGHT = { critical: 20, high: 6, advice: 1, unknown: 0.5 };
const CAP = { high: 30, advice: 12, unknown: 4 };

const GRADES = [
  { id: 'flawless', min: 92, title: t('Чистой воды'), text: t('Защита на высоте. Камень без единого изъяна - так держать.') },
  { id: 'clear', min: 78, title: t('Прозрачный'), text: t('Крепкая защита. Осталось несколько мелочей, чтобы камень засиял.') },
  { id: 'inclusions', min: 60, title: t('С включениями'), text: t('Основа есть, но в защите видны трещинки. Исправьте важное - камень посветлеет.') },
  { id: 'cloudy', min: 35, title: t('Мутный'), text: t('В защите заметные дыры. Начните с критичного и важного.') },
  { id: 'dark', min: 0, title: t('Тёмный'), text: t('Компьютер почти беззащитен. Исправьте критичное в первую очередь - это займёт несколько минут.') },
];

/** findings → { value, grade: { id, title, text }, facets: { done, total }, penalty: { critical, high, advice, unknown } } */
function score(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const count = { critical: 0, high: 0, advice: 0, unknown: 0, ok: 0 };
  for (const f of list) if (Object.hasOwn(count, f.sev)) count[f.sev]++;
  const penalty = {
    critical: count.critical * WEIGHT.critical,
    high: Math.min(CAP.high, count.high * WEIGHT.high),
    advice: Math.min(CAP.advice, count.advice * WEIGHT.advice),
    unknown: Math.min(CAP.unknown, count.unknown * WEIGHT.unknown),
  };
  let value = Math.round(100 - penalty.critical - penalty.high - penalty.advice - penalty.unknown);
  if (count.critical) value = Math.min(value, 49);
  value = Math.max(0, Math.min(100, value));
  const g = GRADES.find((x) => value >= x.min);
  const total = count.ok + count.critical + count.high + count.advice;
  return { value, grade: { id: g.id, title: g.title, text: g.text }, facets: { done: count.ok, total }, penalty };
}

/** История индекса: одна точка в день (последняя за день), не больше 365. */
function pushHistory(history, { at, value, critical, high }) {
  const list = Array.isArray(history) ? history.slice() : [];
  const day = String(at).slice(0, 10);
  const last = list[list.length - 1];
  const point = { at, value, critical, high };
  if (last && String(last.at).slice(0, 10) === day) list[list.length - 1] = point;
  else list.push(point);
  return list.slice(-365);
}

module.exports = { score, pushHistory, GRADES, WEIGHT, CAP };
