/* eslint-disable @typescript-eslint/prefer-ts-expect-error, @typescript-eslint/ban-ts-comment */

import Crypto from 'crypto';
import { Buffer } from 'buffer/';

import { expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import 'mocha';

import * as Iron from '.';

use(chaiAsPromised);

// eslint-disable-next-line @typescript-eslint/naming-convention, no-underscore-dangle, @typescript-eslint/no-unsafe-assignment
const _crypto: Crypto =
  // eslint-disable-next-line no-nested-ternary, @typescript-eslint/no-unsafe-member-access
  typeof globalThis.crypto?.subtle === 'object'
    ? globalThis.crypto
    : // @ts-ignore
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    typeof globalThis.crypto?.webcrypto?.subtle === 'object'
    ? // @ts-ignore
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      globalThis.crypto.webcrypto
    : // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, global-require, @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      new (require('@peculiar/webcrypto').Crypto)();

describe('Iron', () => {
  const obj = { a: 1, b: 2, c: [3, 4, 5], d: { e: 'f' } };
  const password = 'some_not_random_password_that_is_also_long_enough';

  it('turns object into a ticket than parses the ticket successfully', async () => {
    const sealed = await Iron.seal(_crypto, obj, password, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, { default: password }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('unseal and sealed object with expiration', async () => {
    const options = Iron.clone(Iron.defaults);
    options.ttl = 200;
    const sealed = await Iron.seal(_crypto, obj, password, options);
    const unsealed = await Iron.unseal(_crypto, sealed, { default: password }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('unseal and sealed object with expiration and time offset', async () => {
    const options = Iron.clone(Iron.defaults);
    options.ttl = 200;
    options.localtimeOffsetMsec = -100000;
    const sealed = await Iron.seal(_crypto, obj, password, options);

    const options2 = Iron.clone(Iron.defaults);
    options2.localtimeOffsetMsec = -100000;
    const unsealed = await Iron.unseal(_crypto, sealed, { default: password }, options2);
    expect(unsealed).to.deep.equal(obj);
  });

  it('turns object into a ticket than parses the ticket successfully (password buffer)', async () => {
    const key = Iron.randomBits(_crypto, 256);
    const sealed = await Iron.seal(_crypto, obj, key, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, key, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('turns object into a ticket than parses the ticket successfully (password buffer in object)', async () => {
    const key = Iron.randomBits(_crypto, 256);
    const sealed = await Iron.seal(_crypto, obj, key, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, { default: key }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('fails to turns object into a ticket (password buffer too short)', async () => {
    const key = Iron.randomBits(_crypto, 128);
    await expect(Iron.seal(_crypto, obj, key, Iron.defaults)).to.be.rejectedWith(
      'Key buffer (password) too small',
    );
  });

  it('fails to turn object into a ticket (failed to stringify object)', async () => {
    const cyclic: Array<unknown> = [];
    cyclic[0] = cyclic;
    const key = Iron.randomBits(_crypto, 128);
    await expect(Iron.seal(_crypto, cyclic, key, Iron.defaults)).to.be.rejectedWith(
      'Converting circular structure to JSON',
    );
  });

  it('turns object into a ticket than parses the ticket successfully (password object)', async () => {
    const sealed = await Iron.seal(_crypto, obj, { id: '1', secret: password }, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, { '1': password }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('handles separate password buffers (password object)', async () => {
    const key = {
      id: '1',
      encryption: Iron.randomBits(_crypto, 256),
      integrity: Iron.randomBits(_crypto, 256),
    };
    const sealed = await Iron.seal(_crypto, obj, key, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, { '1': key }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('handles a common password buffer (password object)', async () => {
    const key = { id: '1', secret: Iron.randomBits(_crypto, 256) };
    const sealed = await Iron.seal(_crypto, obj, key, Iron.defaults);
    const unsealed = await Iron.unseal(_crypto, sealed, { '1': key }, Iron.defaults);
    expect(unsealed).to.deep.equal(obj);
  });

  it('fails to parse a sealed object when password not found', async () => {
    const sealed = await Iron.seal(_crypto, obj, { id: '1', secret: password }, Iron.defaults);
    await expect(Iron.unseal(_crypto, sealed, { '2': password }, Iron.defaults)).to.be.rejectedWith(
      'Cannot find password: 1',
    );
  });

  describe('generateKey()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-ignore
      await expect(Iron.generateKey(_crypto, null, null)).to.be.rejectedWith('Empty password');
    });

    it('returns an error when password is too short', async () => {
      await expect(
        Iron.generateKey(_crypto, 'password', Iron.defaults.encryption),
      ).to.be.rejectedWith('Password string too short (min 32 characters required)');
    });

    it('returns an error when options are missing', async () => {
      // @ts-ignore
      await expect(Iron.generateKey(_crypto, password, null)).to.be.rejectedWith('Bad options');
      // @ts-ignore
      await expect(Iron.generateKey(_crypto, password, 'abc')).to.be.rejectedWith('Bad options');
    });

    it('returns an error when an unknown algorithm is specified', async () => {
      await expect(
        // @ts-ignore
        Iron.generateKey(_crypto, password, { algorithm: 'unknown' }),
      ).to.be.rejectedWith('Unknown algorithm: unknown');
    });

    it('returns an error when no salt and no salt bits are provided', async () => {
      const options = { algorithm: 'sha256' as const, iterations: 2, minPasswordlength: 32 };
      await expect(Iron.generateKey(_crypto, password, options)).to.be.rejectedWith(
        'Missing salt and saltBits options',
      );
    });

    it('returns an error when invalid salt bits are provided', async () => {
      const options = {
        saltBits: 999999999999999,
        algorithm: 'sha256' as const,
        iterations: 2,
        minPasswordlength: 32,
      };
      await expect(Iron.generateKey(_crypto, password, options)).to.be.rejectedWith(
        'Attempt to allocate Buffer larger than maximum size',
      );
    });
  });

  describe('encrypt()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-ignore
      await expect(Iron.encrypt(_crypto, null, null, 'data')).to.be.rejectedWith('Empty password');
    });
  });

  describe('decrypt', () => {
    it('returns an error when password is missing', async () => {
      // @ts-ignore
      await expect(Iron.decrypt(_crypto, null, null, 'data')).to.be.rejectedWith('Empty password');
    });
  });

  describe('hmacWithPassword()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-ignore
      await expect(Iron.hmacWithPassword(_crypto, null, null, 'data')).to.be.rejectedWith(
        'Empty password',
      );
    });

    it('produces the same mac when used with buffer password', async () => {
      const data = 'Not so random';
      const key = Iron.randomBits(_crypto, 256);
      const hmac = Crypto.createHmac(Iron.defaults.integrity.algorithm, key).update(data);
      const digest = Iron.base64urlEncode(Buffer.from(hmac.digest()));

      const mac = await Iron.hmacWithPassword(_crypto, key, Iron.defaults.integrity, data);
      expect(mac.digest).to.equal(digest);
    });
  });

  describe('seal()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-ignore
      await expect(Iron.seal(_crypto, 'data', null, Iron.defaults)).to.be.rejectedWith(
        'Empty password',
      );
    });

    it('returns an error when integrity options are missing', async () => {
      const options = Iron.clone(Iron.defaults);
      // @ts-ignore
      options.integrity = {};

      await expect(Iron.seal(_crypto, 'data', password, options)).to.be.rejectedWith(
        'Unknown algorithm: undefined',
      );
    });

    it('returns an error when password.id is invalid', async () => {
      await expect(
        Iron.seal(_crypto, 'data', { id: 'asd$', secret: 'asd' }, Iron.defaults),
      ).to.be.rejectedWith('Invalid password id');
    });
  });

  describe('unseal()', () => {
    it('unseals a ticket', async () => {
      const ticket =
        'Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI';
      const unsealed = await Iron.unseal(_crypto, ticket, password, Iron.defaults);
      expect(unsealed).to.deep.equal(obj);
    });

    it('returns an error when number of sealed components is wrong', async () => {
      const ticket =
        'x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Incorrect number of sealed components',
      );
    });

    it('returns an error when password is missing', async () => {
      const ticket =
        'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
      // @ts-ignore
      await expect(Iron.unseal(_crypto, ticket, null, Iron.defaults)).to.be.rejectedWith(
        'Empty password',
      );
    });

    it('returns an error when mac prefix is wrong', async () => {
      const ticket =
        'Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Wrong mac prefix',
      );
    });

    it('returns an error when integrity check fails', async () => {
      const ticket =
        'Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ';
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Bad hmac value',
      );
    });

    it('returns an error when decryption fails', async () => {
      const macBaseString =
        'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??*';
      const options: GenerateKeyOptions = Iron.clone(Iron.defaults).integrity;
      options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
      const mac = await Iron.hmacWithPassword(_crypto, password, options, macBaseString);
      const ticket = `${macBaseString}*${mac.salt}*${mac.digest}`;
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'bad decrypt',
      );
    });

    it('returns an error when iv base64 decoding fails', async () => {
      const macBaseString =
        'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M*';
      const options: GenerateKeyOptions = Iron.clone(Iron.defaults).integrity;
      options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
      const mac = await Iron.hmacWithPassword(_crypto, password, options, macBaseString);
      const ticket = `${macBaseString}*${mac.salt}*${mac.digest}`;
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'bad decrypt',
      );
    });

    it('returns an error when decrypted object is invalid', async () => {
      const badJson = '{asdasd';
      const { encrypted, key } = await Iron.encrypt(
        _crypto,
        password,
        Iron.defaults.encryption,
        badJson,
      );
      const encryptedB64 = Iron.base64urlEncode(encrypted);
      const iv = Iron.base64urlEncode(key.iv);
      const macBaseString = `${Iron.macPrefix}**${key.salt}*${iv}*${encryptedB64}*`;
      const mac = await Iron.hmacWithPassword(
        _crypto,
        password,
        Iron.defaults.integrity,
        macBaseString,
      );
      const ticket = `${macBaseString}*${mac.salt}*${mac.digest}`;
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Unexpected token a',
      );
    });

    it('returns an error when expired', async () => {
      const macBaseString =
        'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060';
      const options: GenerateKeyOptions = Iron.clone(Iron.defaults).integrity;
      options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
      const mac = await Iron.hmacWithPassword(_crypto, password, options, macBaseString);
      const ticket = `${macBaseString}*${mac.salt}*${mac.digest}`;
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Expired seal',
      );
    });

    it('returns an error when expiration NaN', async () => {
      const macBaseString =
        'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a';
      const options: GenerateKeyOptions = Iron.clone(Iron.defaults).integrity;
      options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
      const mac = await Iron.hmacWithPassword(_crypto, password, options, macBaseString);
      const ticket = `${macBaseString}*${mac.salt}*${mac.digest}`;
      await expect(Iron.unseal(_crypto, ticket, password, Iron.defaults)).to.be.rejectedWith(
        'Invalid expiration',
      );
    });
  });
});

/* eslint-enable */
