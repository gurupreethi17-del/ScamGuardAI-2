import path from 'path';
import express from 'express';
import { app } from './src/server/index.ts';

const PORT = 3000;
const isProd = process.env.NODE_ENV === 'production';

async function startServer() {
  if (!isProd) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true, host: '0.0.0.0', port: PORT },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        return next();
      }
      res.sendFile(path.join(distPath, 'index.html'), (err) => {
        if (err) {
          res.status(200).send('ScamGuard AI backend is running. Frontend build in progress.');
        }
      });
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ScamGuard AI full-stack server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
