import type { Options } from 'tsup'

const config: Options = {
  entry: ['src/index.ts'],
  target: 'node10',
  format: ['esm', 'cjs'],
  dts: { resolve: true },
  clean: true,
  treeshake: true,
  publicDir: true,
  esbuildOptions(options) {
    options.platform = 'browser'
  }
}

export default config
