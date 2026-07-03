import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget =
    env.GREENGATEWAY_BACKEND_URL || 'http://127.0.0.1:8080';

  return {
    base: '/admin/',
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      proxy: {
        '/v1/admin': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
