/* eslint-disable eslint-comments/disable-enable-pair, eslint-comments/no-unlimited-disable */
/* eslint-disable */
import { defineBuildConfig } from 'unbuild'
import fs from 'node:fs'

const files = ['./dist/index.node.d.ts', './dist/index.node.mjs', './dist/index.node.cjs']

export default defineBuildConfig({
  hooks: {
    'rollup:done': (ctx) => {
      files.forEach((file) => {
        ctx.warnings.delete(`Could not find entrypoint for ${file}`)
        let data = fs.readFileSync(file.replace('.node.', '.'), { encoding: 'utf8' })
        data = data.replace(/buffer\/index\.js/g, 'buffer')
        fs.writeFileSync(file, data)
      })
    },
  },
})
