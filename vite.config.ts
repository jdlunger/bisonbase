import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  root: "web",
  plugins: [react(), tailwindcss()],
  // API: the Rust server this SPA talks to (see `npm run dev:peer` for a second one).
  // ws: for docs' live rooms (/api/docs/<hash>/live).
  server: { proxy: { "/api": { target: process.env.API ?? "http://localhost:8080", ws: true } } },
});
