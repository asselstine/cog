import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: { "/api": "http://127.0.0.1:4788", "/login": "http://127.0.0.1:4788", "/logout": "http://127.0.0.1:4788", "/ui/integrations": "http://127.0.0.1:4788", "/ui/tokens": "http://127.0.0.1:4788", "/ui/clients": "http://127.0.0.1:4788" }
  }
});
