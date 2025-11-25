# iron-webcrypto

[![npm](https://img.shields.io/npm/v/iron-webcrypto?style=flat-square)](https://www.npmjs.com/package/iron-webcrypto) [![jsr](https://img.shields.io/badge/jsr-@brc--dd/iron@v1.2.1-blue.svg?style=flat-square)](https://jsr.io/@brc-dd/iron) [![downloads](https://img.shields.io/npm/dm/iron-webcrypto?style=flat-square)](https://www.npmjs.com/package/iron-webcrypto)

WebCrypto-based implementation of `@hapi/iron`. It seals JSON-like data using symmetric encryption, signs it for integrity, and returns a compact, URL-safe string that can later be unsealed with the same password.

Works anywhere `crypto.subtle` is available: modern Node, Deno, Bun, Cloudflare Workers, etc.

- Stateless, tamper-evident blobs for session-like data
- Zero `node:crypto` or `node:buffer` usage; relies on standard WebCrypto
- Compatible API with `@hapi/iron`
- ESM-only; typed TypeScript surface

## Installation

Choose the variant that fits your toolchain:

```sh
npm add iron-webcrypto
pnpm add iron-webcrypto
yarn add iron-webcrypto
deno add npm:iron-webcrypto
bun add iron-webcrypto
```

<details>
<summary>JSR package</summary>

```sh
npx jsr add @brc-dd/iron
pnpm add jsr:@brc-dd/iron
yarn add jsr:@brc-dd/iron
deno add jsr:@brc-dd/iron
bun x jsr add @brc-dd/iron
```

Import it like this:

```ts
import * as Iron from '@brc-dd/iron'
```

</details>

## Quick start

```ts
import * as Iron from 'iron-webcrypto'

const password = 'a_long_random_secret_please_change_me'
const payload = { userId: 123, scope: ['user'] }

const sealed = await Iron.seal(payload, password, Iron.defaults)
// => 'Fe26.2**...'

// later or elsewhere
const unsealed = await Iron.unseal(sealed, password, Iron.defaults)
// => { userId: 123, scope: ['user'] }
```

- Check out [unjs/h3](https://github.com/unjs/h3), [vvo/iron-session](https://github.com/vvo/iron-session), and [others](https://github.com/search?q=/from+%5B%22'%5D((npm:%7Cjsr:)?(iron-webcrypto%7C@brc-dd%5C/iron)%7Chttps:%5C/%5C/(deno%5C.land%5C/x%5C/iron%7Cesm%5C.sh%5C/(iron-webcrypto%7Cjsr%5C/@brc-dd%5C/iron)))/+(language:TypeScript+OR+language:JavaScript)+NOT+is:fork+&type=code) to see this module in use!
- Use `.env` or a secrets manager in production to store your secret key(s) securely.
- While this module utilizes WebCrypto and technically functions in a browser environment, it is not recommended for client-side code due to the security risks inherent in exposing encryption secrets to the client.

## API

Full docs: [jsDocs reference](https://www.jsdocs.io/package/iron-webcrypto)\
Concepts and background: [@hapi/iron docs](https://hapi.dev/module/iron/)

- `defaults`: Commonly used `SealOptions` (AES-256-CBC + SHA-256, 256-bit salts, no TTL).
- `seal(object, password, options)`: Serializes, encrypts, and signs data into the iron token string.
- `unseal(sealed, password, options)`: Verifies, decrypts, and parses a sealed string.
- `encrypt(password, options, data)` / `decrypt(password, options, data)`: Low-level helpers for symmetric encryption.
- `hmacWithPassword(password, options, data)`: Produces a URL-safe Base64 HMAC digest.
- `generateKey(password, options)`: Derives a `CryptoKey` and IV (for encryption) or salt (for HMAC).

### Options

`SealOptions` has two parts, `encryption` and `integrity`, each with:

- `algorithm`: Encryption is `'aes-256-cbc'` (default) or `'aes-128-ctr'`; integrity is `'sha256'`.
- `saltBits`: Length of the randomly generated salt (default `256`).
- `iterations`: PBKDF2 iterations for string passwords (default `1`).
- `minPasswordlength`: Minimum string length (default `32`).

Additional seal options:

- `ttl`: Expiration in milliseconds (`0` means no expiry).
- `timestampSkewSec`: Allowed clock skew when validating expiry (default `60`).
- `localtimeOffsetMsec`: Adjust local clock when sealing/unsealing (default `0`).
- `encode` / `decode`: Custom serializers (defaults to lossless JSON encode/parse).

### Password shapes

- Simple: string or `Uint8Array`.
- With id: `{ id, secret }` or `{ id, encryption, integrity }`.
- Hash map: `{ [id]: password | secret | specific }` (used by `unseal` to look up `passwordId` embedded in the token).

### Errors

Most functions throw when inputs are missing, too short, or malformed (e.g., unknown algorithms, invalid Base64, expired token, or unserializable data). Catch and handle these to swallow errors or surface meaningful responses to callers.

## Migration

### From `@hapi/iron`

The API is mostly compatible with `@hapi/iron`. Install the module and update your imports:

```diff
- import * as Iron from '@hapi/iron'
+ import * as Iron from 'iron-webcrypto'
```

Note that implementation differences may result in variations in error messages due to the use of standard Web APIs instead of Node.js-specific modules.

### From `iron-webcrypto` v1 to v2

- v2 uses the global `crypto` implementation by default, eliminating the need to pass WebCrypto as the first parameter. If you need a custom WebCrypto implementation, polyfill it as follows:

  ```ts
  import { webcrypto } from 'node:crypto'

  if (typeof globalThis.crypto === 'undefined') {
    // @ts-ignore
    globalThis.crypto = webcrypto
  }
  ```

  Polyfill support:

  - Not needed in Node.js v19+, Deno v1.11+, Bun v1+
  - Node.js < v19 requires manual polyfill as above or `--experimental-global-webcrypto` flag
  - Node.js < v15 requires `@peculiar/webcrypto` or similar polyfill
  - Node.js < v10 has no polyfill available

  Then you can call the functions without passing `crypto` explicitly.

  ```diff
  - const sealed = await Iron.seal(crypto, payload, password, Iron.defaults)
  + const sealed = await Iron.seal(payload, password, Iron.defaults)

  - const unsealed = await Iron.unseal(crypto, sealed, password, Iron.defaults)
  + const unsealed = await Iron.unseal(sealed, password, Iron.defaults)
  ```

- The package is now ESM-only. Node v20+ is recommended; older Node versions require dynamic `import()` if using CommonJS without a bundler / interop layer. Refer to [this gist](https://gist.github.com/sindresorhus/a39789f98801d908bbc7ff3ecc99d99c) for migration help.

- The default encoder has been updated from `JSON.stringify` to a lossless JSON stringifier that validates data can be completely round-tripped without modification. While `undefined` values inside objects are still intentionally ignored (matching the original behavior), the new encoder will throw an error if it encounters any data that cannot be reliably serialized and deserialized, such as:

  - Circular references
  - Non-plain objects (with prototypes other than `Object.prototype` or `null`)
  - Symbol keys or non-enumerable properties and methods
  - `undefined` (empty) values in arrays (which become `null` with the standard `JSON.stringify`)
  - Non-finite numbers (including `NaN`, `Infinity`, `-Infinity`)
  - And any other data type not representable in JSON (e.g., `BigInt`, `Map`, `Set`, `Date`, `RegExp`, etc.)

  This change ensures data integrity but may require updates to your code if you were previously relying on silent truncation of unserializable data. If you need to maintain the previous behavior, you have two options:

  - Use the original JSON methods in options:

    ```ts
    const sealed = await Iron.seal(payload, password, { ...Iron.defaults, encode: JSON.stringify })
    ```

  - Pre-process data before sealing:

    ```ts
    const sealed = await Iron.seal(JSON.parse(JSON.stringify(payload)), password, Iron.defaults)
    ```

## Security Considerations

**You are responsible for securing your keys and integrating this library safely.** Quoting [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API):

> The Web Crypto API provides a number of low-level cryptographic primitives. It's very easy to misuse them, and the pitfalls involved can be very subtle.
>
> Even assuming you use the basic cryptographic functions correctly, secure key management and overall security system design are extremely hard to get right, and are generally the domain of specialist security experts.
>
> Errors in security system design and implementation can make the security of the system completely ineffective.

### Algorithm Strengths

The cryptographic primitives used in the Iron algorithm have weakened over time. While AES-256-CBC and HMAC-SHA256 remain secure for most use cases, periodically review your security requirements, especially for sensitive data.

PBKDF2 with a single iteration is suboptimal for password hashing but was deemed acceptable for key derivation in this context. Mitigate this risk by using strong, high-entropy passwords. `openssl rand -base64 24` is a handy way to generate one locally.

Modern applications should consider stronger algorithms like AES-GCM that provide Authenticated Encryption with Associated Data (AEAD). Future releases may explore using it with appropriate key management strategies like HKDF-derived per-payload keys or envelope encryption schemes.

### Password Rotation

Assigning the password used an `id` allows for password rotation to improve the security of your deployment. Passwords should be rotated over time to reduce the risk of compromised security. When providing a password id, the id is included with the iron protocol string and it must match the id used to unseal.

It is recommended to combine password id with the `ttl` option to generate iron protocol strings of limited time validity which also allow for rotating passwords without the need to keep all previous passwords around (only the number of passwords used within the ttl window).

### Threat Model

This library is designed to provide confidentiality and integrity for data stored in untrusted environments, such as client-side storage or third-party services. However, it does not protect against all possible threats. Consider the following when using this library:

- **Key Management**: Ensure that encryption keys are stored securely and are not exposed to unauthorized parties. Compromise of the key compromises all data sealed with it.
- **Replay Attacks**: While the library supports TTL for tokens, it does not inherently prevent replay attacks. Implement additional measures if necessary.
- **Side-Channel Attacks**: Be aware of potential side-channel attacks that could leak information about the sealed data or keys through timing or other observable behaviors.
- **Data Sensitivity**: Evaluate the sensitivity of the data being sealed and ensure that the chosen algorithms and key sizes are appropriate for the level of security required.

## Credits

```txt
@hapi/iron
    Copyright (c) 2012-2022, Project contributors
    Copyright (c) 2012-2020, Sideway Inc
    All rights reserved.
    https://cdn.jsdelivr.net/npm/@hapi/iron@7.0.1/LICENSE.md
```

## Development

- Format: `deno task format`
- Lint: `deno task lint`
- Test: `deno task test`
- Type check: `deno task type`

## Sponsors

<p align="center">
  <a href="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg">
    <img alt="brc-dd's sponsors" src="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg" />
  </a>
</p>
