declare module '@aws-sdk/util-base64/dist-es/fromBase64.browser' {
  export const fromBase64: (input: string) => Uint8Array
}

declare module '@aws-sdk/util-base64/dist-es/toBase64.browser' {
  export const toBase64: (input: Uint8Array) => string
}
