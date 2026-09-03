import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { spawn } from 'child_process';
import http from 'http';
import path from 'path';

let fastApiProc: any = null;

function fastApiSupervisorPlugin(): Plugin {
  function checkAndStartFastApi() {
    const req = http.get('http://127.0.0.1:8001/health', () => {
      // FastAPI is already active and healthy on port 8001
    });
    req.on('error', () => {
      console.log('[FastAPI] Launching FastAPI backend on http://127.0.0.1:8001 ...');
      fastApiProc = spawn(
        'python3',
        ['-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8001'],
        {
          cwd: path.resolve(process.cwd(), 'backend'),
          env: {
            ...process.env,
            PYTHONPATH: path.resolve(process.cwd(), 'backend'),
          },
          stdio: 'inherit',
        }
      );
      fastApiProc.on('error', (err: any) => {
        console.error('[FastAPI] Error starting FastAPI:', err);
      });
    });
  }

  return {
    name: 'hawkeye-fastapi-supervisor',
    configureServer() {
      checkAndStartFastApi();
    },
    configurePreviewServer() {
      checkAndStartFastApi();
    },
  };
}

process.on('exit', () => {
  if (fastApiProc) {
    try {
      fastApiProc.kill();
    } catch {}
  }
});

const fastApiProxyConfig = {
  target: 'http://127.0.0.1:8001',
  changeOrigin: true,
};

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    fastApiSupervisorPlugin(),
  ],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    proxy: {
      '/health': fastApiProxyConfig,
      '/alerts': fastApiProxyConfig,
      '/incidents': fastApiProxyConfig,
      '/incident': fastApiProxyConfig,
      '/simulate': fastApiProxyConfig,
      '/simulator': fastApiProxyConfig,
      '/analyze': fastApiProxyConfig,
      '/api': {
        ...fastApiProxyConfig,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    proxy: {
      '/health': fastApiProxyConfig,
      '/alerts': fastApiProxyConfig,
      '/incidents': fastApiProxyConfig,
      '/incident': fastApiProxyConfig,
      '/simulate': fastApiProxyConfig,
      '/simulator': fastApiProxyConfig,
      '/analyze': fastApiProxyConfig,
      '/api': {
        ...fastApiProxyConfig,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
});
