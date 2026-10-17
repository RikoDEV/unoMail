import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// During development the API is served by the Rust backend (UNOMAIL_HTTP_PORT, default 8080).
const backend = process.env.UNOMAIL_BACKEND ?? 'http://127.0.0.1:8080';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': backend,
      '/jmap': backend,
      '/.well-known': backend,
      '/dav': backend,
    },
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 1200 },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts'], setupFiles: ['src/test-setup.ts'] },
});
