import { defineConfig } from "vite";

export default defineConfig({
  build: { target: "es2022", sourcemap: false },
  server: { port: 5173 },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    /* These are integration tests over real cryptography: a single one
       registers several accounts, each generating a hundred classical and a
       hundred ML-KEM prekeys. Four seconds locally is comfortably inside the
       five-second default, and five and a bit on a shared CI runner is not,
       which is a needlessly flaky way to find out nothing is wrong. */
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
