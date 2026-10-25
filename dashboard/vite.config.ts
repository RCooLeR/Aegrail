import { defineConfig } from "vite";
import babel from "@rolldown/plugin-babel";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";

export default defineConfig({
  base: "/dashboard/",
  plugins: [
    react(),
    babel({
      presets: [reactCompilerPreset()]
    })
  ],
  build: {
    target: "baseline-widely-available"
  },
  server: {
    port: 5173,
    strictPort: false,
    forwardConsole: {
      unhandledErrors: true,
      logLevels: ["warn", "error"]
    },
    proxy: {
      "/api": "http://127.0.0.1:8787",
      "/healthz": "http://127.0.0.1:8787"
    }
  }
});
