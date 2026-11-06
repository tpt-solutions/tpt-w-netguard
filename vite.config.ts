// SPDX-License-Identifier: MIT OR Apache-2.0
import { defineConfig } from "vite";

// Port 1420 matches Tauri's dev convention so the shell can point at it later.
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { outDir: "dist", target: "es2022" },
});
