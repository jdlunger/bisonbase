// `npm run dev` serves the UI with hot reload on http://localhost:5173 and proxies the server's
// endpoints to a running bisonbase (BISONBASE_URL, default http://localhost:8080). Passkeys only
// work on the server's own origin, so log in there first: cookies on localhost are shared across
// ports, so the session carries over to the dev server.
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const target = process.env.BISONBASE_URL ?? 'http://localhost:8080'
const proxy = { target, changeOrigin: false }

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: {
      '/ui/': proxy,
      '/auth/': proxy,
      '/api/': proxy,
      '/raw/': proxy,
      '/logout': proxy,
      '/oauth/token': proxy,
      '/oauth/revoke': proxy,
      '/.well-known/': proxy,
      '^/admin/users/[^/]+/raw/': proxy,
      // The consent form posts here; the page itself is the app's.
      '/oauth/authorize': { ...proxy, bypass: (req) => (req.method === 'GET' ? '/index.html' : undefined) },
    },
  },
})
