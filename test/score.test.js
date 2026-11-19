'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { score, pushHistory } = require('../server/score');
const { render } = require('../server/i18n');

const f = (sev, n = 1) => Array.from({ length: n }, (_, i) => ({ id: `${sev}-${i}`, sev }));

test('индекс: всё в порядке - «чистой воды», грани считаются по проверкам в порядке', () => {
  const s = score([...f('ok', 20)]);
  assert.equal(s.value, 100);
  assert.equal(s.grade.id, 'flawless');
  assert.deepEqual(s.facets, { done: 20, total: 20 });
});

test('индекс: критичная находка не даёт подняться выше 49', () => {
  const s = score([...f('critical'), ...f('ok', 30)]);
  assert.ok(s.value <= 49);
  assert.equal(s.grade.id, 'cloudy');
  assert.equal(score([...f('critical', 4)]).grade.id, 'dark');
});

test('индекс: «не видно» и мелочи влияют слабо и ограничены сверху', () => {
  assert.equal(score([...f('unknown', 100), ...f('ok', 5)]).value, 96);
  assert.equal(score([...f('high', 2), ...f('advice', 3)]).value, 85);
  // Потолки: много мелочей не делают камень тёмным.
  assert.equal(score([...f('high', 20), ...f('advice', 40), ...f('unknown', 20)]).value, 54);
  assert.equal(render('ru', score([]).grade.title), 'Чистой воды');
});

test('история индекса: одна точка в день, не больше 365', () => {
  let h = pushHistory([], { at: '2026-11-01T10:00:00Z', value: 40, critical: 1, high: 3 });
  h = pushHistory(h, { at: '2026-11-01T18:00:00Z', value: 60, critical: 0, high: 3 });
  h = pushHistory(h, { at: '2026-11-02T09:00:00Z', value: 70, critical: 0, high: 2 });
  assert.deepEqual(h.map((p) => p.value), [60, 70]);
  let big = [];
  for (let i = 0; i < 400; i++) big = pushHistory(big, { at: new Date(Date.UTC(2025, 0, 1) + i * 86_400_000).toISOString(), value: i % 100 });
  assert.equal(big.length, 365);
});
