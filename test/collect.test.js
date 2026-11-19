'use strict';
/**
 * Настоящая проверка этого компьютера: collect.ps1 и network.ps1 без прав администратора.
 * Сценарии только читают настройки. На других ОС тест пропускается.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const ps = require('../server/ps');
const { evaluate } = require('../server/rules');
const netscan = require('../server/netscan');

const win = process.platform === 'win32';

test('collect.ps1: сведения собираются, правила по ним работают', { skip: !win && 'только Windows', timeout: 180_000 }, async () => {
  const f = await ps.runJson('collect.ps1');
  assert.equal(f.format, 'adamant-facts');
  for (const sec of ['meta', 'ports', 'firewall', 'uac', 'accounts', 'autostart', 'updates', 'encryption', 'boot', 'firmware']) {
    assert.ok(f[sec], `нет раздела ${sec}: ${f.errors && f.errors[sec]}`);
  }
  assert.match(f.meta.userSid, /^S-1-5-/);
  assert.ok(Array.isArray(f.ports.tcp));
  assert.equal(typeof f.accounts.autoLogonPasswordStored, 'boolean', 'пароль автовхода не передаётся - только признак');
  assert.equal(f.accounts.DefaultPassword, undefined);
  const list = evaluate(f);
  assert.ok(list.length >= 10);
  for (const x of list) assert.ok(['critical', 'high', 'advice', 'unknown', 'ok'].includes(x.sev), x.id);
});

test('network.ps1: адаптеры и соседи', { skip: !win && 'только Windows', timeout: 120_000 }, async () => {
  const adapters = await ps.runJson('network.ps1', ['-Mode', 'adapters']);
  const list = Array.isArray(adapters) ? adapters : [adapters];
  assert.ok(list.every((a) => typeof a.address === 'string'));
  const subs = netscan.subnets(list);
  assert.ok(subs.every((s) => netscan.isPrivate(s.address) && s.count <= 256));
  const nb = await ps.runJson('network.ps1', ['-Mode', 'neighbors']);
  assert.ok(Array.isArray(nb) || typeof nb === 'object');
});
