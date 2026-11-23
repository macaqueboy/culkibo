import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import zlib from 'node:zlib'

/** Pre-comprime assets de web/dist (.br y .gz) en tiempo de build sin dependencias externas. */
function precompressDist() {
  return {
    name: 'culkibo-precompress',
    apply: 'build' as const,
    closeBundle() {
      const distDir = fileURLToPath(new URL('./dist', import.meta.url))
      if (!fs.existsSync(distDir)) return
      const walk = (dir: string) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name)
          if (entry.isDirectory()) {
            walk(full)
          } else if (/\.(?:js|css|html|svg|json|txt)$/i.test(entry.name)) {
            const raw = fs.readFileSync(full)
            if (raw.length < 512) continue
            const br = zlib.brotliCompressSync(raw, {
              params: {
                [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
                [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: raw.length
              }
            })
            const gz = zlib.gzipSync(raw, { level: 9 })
            if (br.length < raw.length) fs.writeFileSync(`${full}.br`, br)
            if (gz.length < raw.length) fs.writeFileSync(`${full}.gz`, gz)
          }
        }
      }
      walk(distDir)
    }
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), precompressDist()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:3030',
        changeOrigin: true
      },
      '/metrics': {
        target: 'http://127.0.0.1:3030',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://127.0.0.1:3030',
        ws: true
      }
    }
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/[/\\]node_modules[/\\]react(?:-dom)?[/\\]/.test(id)) {
            return 'vendor';
          }
          if (/[/\\]node_modules[/\\]lucide-react[/\\]/.test(id)) {
            return 'ui';
          }
        }
      }
    }
  }
})
