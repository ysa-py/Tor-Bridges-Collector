import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:sockets": path.resolve(__dirname, "src/__mocks__/cloudflare-sockets.ts"),
    },
  },
  test: {
    // No additional config needed
  },
});
