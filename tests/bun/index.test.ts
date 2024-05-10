import { deepStrictEqual as deepEqual, rejects } from 'bun:assert'
import { createHmac } from 'bun:crypto'
import { describe, it } from 'bun:test'
import { tests } from '../index.js'

tests({ crypto: globalThis.crypto, createHmac, describe, it, deepEqual, rejects })
