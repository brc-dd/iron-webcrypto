export const crypto = (() => {
  if (typeof globalThis?.crypto?.subtle === 'object') return globalThis.crypto;
  if (typeof globalThis?.crypto?.webcrypto?.subtle === 'object') return globalThis.crypto.webcrypto;
  return new ((typeof __webpack_require__ === 'function' ? __non_webpack_require__ : require)(
    '@peculiar/webcrypto',
  ).Crypto)();
})();
