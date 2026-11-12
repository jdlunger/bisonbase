// An esbuild plugin that runs imported CSS through Tailwind, which generates the classes the
// app uses. Used by react-todo/server.ts (and the browser tests' copy of its build).

import { readFile } from 'node:fs/promises'
import tailwindcss from '@tailwindcss/postcss'
import type { Plugin } from 'esbuild'
import postcss from 'postcss'

export const tailwind: Plugin = {
  name: 'tailwind',
  setup(build) {
    build.onLoad({ filter: /\.css$/ }, async ({ path }) => {
      const css = await postcss([tailwindcss()]).process(await readFile(path, 'utf8'), { from: path })
      return { contents: css.css, loader: 'css' }
    })
  },
}
