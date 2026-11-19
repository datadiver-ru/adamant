'use strict';
/** Сведения facts.login (server/ps/sections/login.ps1): «крепкий» и «слабый» вход в Windows для тестов. */
const { good, bad, NOW } = require('./facts');
const { protectedPhysical, exposedPhysical } = require('./physical');

function strongLogin() {
  return {
    admin: false, errors: {}, partOfDomain: false,
    lockout: { threshold: 10, windowSec: 600, durationSec: 600 },
    cad: { policy: 0, winlogon: 1, source: 'policy', required: true },
    hello: { pin: true, pinSource: 'logon-creds', biometricDevices: [], biometrics: null },
    edition: { id: 'Professional', composition: 'Enterprise' },
    bitlocker: {
      controlKey: true, autoDE: true, preventDeviceEncryption: null, tools: { wizard: true, manageBde: true },
      policy: { useAdvancedStartup: 1, enableBdeWithNoTpm: null, useTpm: 2, useTpmPin: 2, useTpmKey: 2, useTpmKeyPin: 2, minimumPin: null, useEnhancedPin: null },
    },
  };
}

function weakLogin() {
  return {
    admin: false, errors: {}, partOfDomain: false,
    lockout: { threshold: 0, windowSec: 1800, durationSec: 1800 },
    cad: { policy: null, winlogon: 1, source: 'winlogon', required: false },
    hello: { pin: false, pinSource: 'absent', biometricDevices: ['Goodix fingerprint'], biometrics: null },
    edition: { id: 'Professional', composition: 'Enterprise' },
    bitlocker: {
      controlKey: true, autoDE: false, preventDeviceEncryption: null, tools: { wizard: true, manageBde: true },
      policy: { useAdvancedStartup: null, enableBdeWithNoTpm: null, useTpm: null, useTpmPin: null, useTpmKey: null, useTpmKeyPin: null, minimumPin: null, useEnhancedPin: null },
    },
  };
}

/** Хороший компьютер: диск зашифрован с ПИН-кодом (полная проверка), вход защищён, динамическая блокировка включена. */
function strongFacts() {
  const p = protectedPhysical();
  p.lock.dynamicLock = true;
  return { ...good(), isAdmin: true, physical: p, login: strongLogin() };
}
/** Слабый вход: попыток сколько угодно, без Ctrl+Alt+Del и ПИН-кода Hello; диск не зашифрован, TPM не найден. */
function weakFacts() {
  return { ...bad(), physical: exposedPhysical(), login: weakLogin() };
}

module.exports = { strongLogin, weakLogin, strongFacts, weakFacts, NOW };
