/// <reference types="node" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react({ jsxRuntime: "classic" })],

  resolve: {
    alias: { "@": resolve(__dirname, "src") },
  },

  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1000,

    rollupOptions: {
      input: {
        popup: resolve(__dirname, "src/popup/index.html"),
        background: resolve(__dirname, "src/background/index.ts"),
        content: resolve(__dirname, "src/content/index.ts"),
      },
      output: [
        // ES modules for popup and background (allow code splitting)
        {
          dir: "dist",
          format: "es",
          entryFileNames: "[name].js",
          chunkFileNames: "assets/[name].js",
          assetFileNames: "assets/[name].[ext]",
        },
      ],
    },
  },

  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
  },
});


