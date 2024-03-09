// @ts-nocheck

declare module 'bun:assert' {
  import assert = require('assert')
  export = assert
}

declare module 'bun:crypto' {
  export * from 'crypto'
}
