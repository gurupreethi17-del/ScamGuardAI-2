import { app } from '../src/server/index.ts';

export default function handler(req: any, res: any) {
  // If Vercel rewrite transformed the request URL to /api, restore the original URI
  const forwardedUri = req.headers['x-forwarded-uri'] as string | undefined;
  if (forwardedUri && (req.url === '/api' || req.url === '/api/')) {
    req.url = forwardedUri;
  }
  return app(req, res);
}
