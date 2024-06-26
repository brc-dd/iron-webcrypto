import { deepStrictEqual as deepEqual, rejects } from 'node:assert'
import { createHmac, webcrypto } from 'node:crypto'
import { describe, it } from 'node:test'
import { tests } from '../index.js'

// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-misused-promises
tests({ crypto: globalThis.crypto ?? webcrypto, createHmac, describe, it, deepEqual, rejects })
