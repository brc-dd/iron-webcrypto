export interface _Crypto {
  readonly subtle: _SubtleCrypto
  getRandomValues: (array: Uint8Array) => Uint8Array
}

interface _SubtleCrypto {
  decrypt: (
    algorithm: AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams,
    key: CryptoKey,
    data: Uint8Array
  ) => Promise<ArrayBuffer>
  deriveBits: (
    algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
    baseKey: CryptoKey,
    length: number
  ) => Promise<ArrayBuffer>
  encrypt: (
    algorithm: AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams,
    key: CryptoKey,
    data: Uint8Array
  ) => Promise<ArrayBuffer>
  importKey: (
    format: Exclude<KeyFormat, 'jwk'>,
    keyData: ArrayBuffer | Uint8Array,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ) => Promise<CryptoKey>
  sign: (
    algorithm: AlgorithmIdentifier | EcdsaParams | RsaPssParams,
    key: CryptoKey,
    data: Uint8Array
  ) => Promise<ArrayBuffer>
}
