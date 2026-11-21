import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  root: "web",
  plugins: [react(), tailwindcss()],
  build: {
    // gate.html: a private node's sign-in page. The node reads the manifest to serve only its files to
    // those it doesn't let in (see GATE_FILES in src/main.rs).
    manifest: true,
    rollupOptions: { input: ["index.html", "gate.html"].map((f) => fileURLToPath(new URL(`web/${f}`, import.meta.url))) },
  },
  // API: the Rust server this SPA talks to (see `npm run dev:peer` for a second one).
  // ws: for docs' live rooms (/api/docs/<hash>/live).
  server: { proxy: { "/api": { target: process.env.API ?? "http://localhost:8080", ws: true } } },
});
