import { defineConfig } from "vitest/config";

// Deliberately NOT an extension of vite.config.ts. That config exists to build
// the bundle committed into ../kitewrt/static, `emptyOutDir` and all, and CI
// fails on a byte of drift there — a test run has no business loading it, let
// alone the React and Tailwind plugins it carries.
//
// Node environment, no DOM: what is under test is health.ts, which is pure by
// design (see its header). Anything that needs a browser to be tested is a
// component, and belongs on the other side of that boundary.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
