import { defineConfig } from "vite";

export default defineConfig({
  build: { target: "es2022", sourcemap: false },
  server: { port: 5173 },
  test: { environment: "node", include: ["test/**/*.test.ts"] },
});
