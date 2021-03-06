# iron-webcrypto (WIP)

This module is a replacement for [`@hapi/iron`](https://hapi.dev/module/iron/),
written using the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
that makes it compatible with browser and edge environments.

---

## Installation

To use this module, run:

```sh
npm add iron-webcrypto
npm remove @hapi/iron
```

and change:

```js
const Iron = require('@hapi/iron');
// or
import Iron from '@hapi/iron';
```

to:

```js
const Iron = require('iron-webcrypto');
// or
import * as Iron from 'iron-webcrypto';
```

Then modify function calls to pass a Web Crypto implementation as the first
param. For example:

```js
Iron.seal(obj, password, Iron.defaults);
```

becomes:

```js
Iron.seal(_crypto, obj, password, Iron.defaults);
```

where `_crypto` is your Web Crypto implementation. Generally this will available
in your context (for example, `globalThis.crypto` in browsers/edge runtimes,
`globalThis.crypto.webcrypto` in newer Node.js versions). However, you may also
need to polyfill this (for older Node.js versions). We recommend using
[`@peculiar/webcrypto`](https://www.npmjs.com/package/@peculiar/webcrypto) for
that.
