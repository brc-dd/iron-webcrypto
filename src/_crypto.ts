export interface _Crypto {
  readonly subtle: _SubtleCrypto
  getRandomValues: (array: BufferSource) => BufferSource
}

interface _SubtleCrypto {
  decrypt: (
    algorithm: AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ) => Promise<ArrayBuffer>
  deriveBits: (
    algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
    baseKey: CryptoKey,
    length: number
  ) => Promise<ArrayBuffer>
  encrypt: (
    algorithm: AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ) => Promise<ArrayBuffer>
  importKey: (
    format: Exclude<KeyFormat, 'jwk'>,
    keyData: BufferSource,
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
    data: BufferSource
  ) => Promise<ArrayBuffer>
}
