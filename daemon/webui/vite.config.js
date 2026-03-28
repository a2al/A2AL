import { defineConfig } from 'vite';

const target = 'http://127.0.0.1:2121';

export default defineConfig({
  root: '.',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
      },
    },
  },
  server: {
    proxy: {
      '/agents': target,
      '/discover': target,
      '/status': target,
      '/config': target,
      '/resolve': target,
      '/connect': target,
      '/identity': target,
      '/health': target,
      '/debug': target,
      '/mcp': target,
    },
  },
});
