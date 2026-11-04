/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// VITE_BASE — путь SPA (в платформе «/grc/»), по умолчанию «/».
export default defineConfig({
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  // Без data:-ссылок: CSP разрешает шрифты и картинки только с 'self'.
  build: { assetsInlineLimit: 0 },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.GRC_API_URL ?? "http://127.0.0.1:18002",
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
