import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  base: process.env.TAURI_PLATFORM ? './' : '/',
  server: {
    host: process.env.VITE_DEV_LISTEN_ALL === '1' ? "::" : "127.0.0.1",
    port: Number(process.env.VITE_PORT) || 8080,
    strictPort: true,
    cors: false,
  },
  esbuild: mode === 'production' ? { drop: ['console', 'debugger'] } : undefined,
  plugins: [
    react(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    target: 'es2020',
    sourcemap: false,
    minify: 'esbuild',
    // Ensure content hashes in filenames for cache busting
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    }
  }
}));
