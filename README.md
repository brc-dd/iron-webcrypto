# iron-webcrypto

This module is a drop-in replacement for
[`@hapi/iron`](https://hapi.dev/module/iron/), written using the
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
