// eslint-disable-next-line @typescript-eslint/naming-convention
type _Buffer = import('buffer/').Buffer;

/**
 * seal() method options.
 */
type SealOptionsSub = {
  /**
   * The length of the salt (random buffer used to ensure that two identical objects will generate a different encrypted result). Defaults to 256.
   */
  saltBits: number;

  /**
   * The algorithm used. Defaults to 'aes-256-cbc' for encryption and 'sha256' for integrity.
   */
  algorithm: 'aes-128-ctr' | 'aes-256-cbc' | 'sha256';

  /**
   * The number of iterations used to derive a key from the password. Defaults to 1.
   */
  iterations: number;

  /**
   * Minimum password size. Defaults to 32.
   */
  minPasswordlength: number;
};

/**
 * Options for customizing the key derivation algorithm used to generate encryption and integrity verification keys as well as the algorithms and salt sizes used.
 */
type SealOptions = {
  /**
   * Encryption step options.
   */
  encryption: SealOptionsSub;

  /**
   * Integrity step options.
   */
  integrity: SealOptionsSub;

  /**
   * Sealed object lifetime in milliseconds where 0 means forever. Defaults to 0.
   */
  ttl: number;

  /**
   * Number of seconds of permitted clock skew for incoming expirations. Defaults to 60 seconds.
   */
  timestampSkewSec: number;

  /**
   * Local clock time offset, expressed in number of milliseconds (positive or negative). Defaults to 0.
   */
  localtimeOffsetMsec: number;
};

/**
 * Password secret string or buffer.
 */
type Password = _Buffer | string;

/**
 * generateKey() method options.
 */
type GenerateKeyOptions = Pick<SealOptionsSub, 'algorithm' | 'iterations' | 'minPasswordlength'> & {
  saltBits?: number | undefined;
  salt?: string | undefined;
  iv?: _Buffer | undefined;
  hmac?: boolean | undefined;
};

/**
 * Generated internal key object.
 */
type Key = { key: CryptoKey; salt: string; iv: _Buffer };

/**
 * Generated HMAC internal results.
 */
type HMacResult = { digest: string; salt: string };

declare namespace password {
  /**
   * Secret object with optional id.
   */
  type Secret = { id?: string | undefined; secret: Password };

  /**
   * Secret object with optional id and specified password for each encryption and integrity.
   */
  type Specific = { id?: string | undefined; encryption: Password; integrity: Password };

  /**
   * Key-value pairs hash of password id to value.
   */
  type Hash = Record<string, Password | Secret | Specific>;
}

type RawPassword = Password | password.Secret | password.Specific;
