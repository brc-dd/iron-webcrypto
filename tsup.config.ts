import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  target: 'node10',
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  treeshake: true,
  publicDir: true
})
