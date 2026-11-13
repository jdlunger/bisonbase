// Starts bisonbase in this process, then serves the workspace app on http://localhost:3001 with
// esbuild's dev server, which bundles app.tsx (JSX, TypeScript and CSS, through Tailwind) on each
// request.
// Needs `npm install` in examples/ts first. Run: node examples/ts/react-workspace/server.ts

import { fileURLToPath } from 'node:url'
import { context } from 'esbuild'
import { tailwind } from '../tailwind.ts'
import { start } from '../../../node/index.js' // in your own project: from '@bisonbase/server'

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url))

const bisonbase = await start({ port: 8080, dataDir: here('../../.data'), log: 'off' })
console.log(`bisonbase: ${bisonbase.url}`)
if (bisonbase.setupUrl) console.log(`First run: create your account at ${bisonbase.setupUrl}`)

const esbuild = await context({
  entryPoints: [here('app.tsx')],
  outdir: here('.'), // where the bundle is served from
  write: false, // keep it in memory
  bundle: true,
  format: 'esm',
  sourcemap: true,
  plugins: [tailwind],
  define: { BISONBASE_URL: JSON.stringify(bisonbase.url) },
  // Only because this example uses the library straight from its source in ../../../client;
  // an app that installs bisonbase from npm needs none of this.
  alias: {
    bisonbase: here('../../../client/src/index.ts'),
    'bisonbase/react': here('../../../client/src/react.tsx'),
    react: here('../node_modules/react'), // one copy of React for the app and the library
  },
})
await esbuild.serve({ servedir: here('.'), host: '127.0.0.1', port: 3001 })
console.log('Workspace app: http://localhost:3001')
