import cors, { type CorsOptions } from 'cors';
import express from 'express';
import helmet from 'helmet';
import { allowedOrigins, isProduction } from './config';
import { errorHandler } from './middleware/errorHandler';
import { requestIdMiddleware } from './middleware/requestId';
import { requestLoggingMiddleware } from './middleware/requestLogging';
import scanRoutes from './routes/scan.routes';
import reportsRoutes from './routes/reports.routes';
import downloadsRoutes from './routes/downloads.routes';
import healthRoutes from './routes/health.routes';
import aiRoutes from './routes/ai.routes';
import securityRoutes from './routes/security.routes';
import adminRoutes from './routes/admin.routes';
import { statsController } from './controllers/health.controller';
import { createRateLimiter } from './middleware/rateLimiter';
import { AppError } from './errors';

const isAllowedDevelopmentOrigin = (origin: string): boolean => {
  if (!origin) {
    return false;
  }
  return origin.startsWith('chrome-extension://')
    || origin.startsWith('http://localhost:')
    || origin.startsWith('http://127.0.0.1:')
    || origin.startsWith('https://localhost:')
    || origin.startsWith('https://127.0.0.1:');
};

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      callback(null, true);
      return;
    }
    if (!isProduction && isAllowedDevelopmentOrigin(origin)) {
      callback(null, true);
      return;
    }
    if (allowedOrigins.some((allowed) => origin.startsWith(allowed))) {
      callback(null, true);
      return;
    }
    callback(new AppError(403, 'cors_forbidden', 'origin forbidden'));
  },
  credentials: true
};

export const createApp = () => {
  const app = express();
  app.set('trust proxy', 1);
  app.use(requestIdMiddleware);
  app.use(requestLoggingMiddleware);
  app.use(helmet({ hsts: isProduction, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  app.options(/.*/, cors(corsOptions));
  app.use(cors(corsOptions));
  app.use(express.json({
    limit: '10mb',
    verify: (req, _res, buffer) => {
      (req as express.Request).rawBody = buffer.toString('utf8');
    }
  }));
  app.use(express.urlencoded({
    extended: true,
    limit: '10mb',
    verify: (req, _res, buffer) => {
      (req as express.Request).rawBody = buffer.toString('utf8');
    }
  }));
  app.use((err: { type?: string } | null, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err?.type === 'entity.too.large') {
      res.status(413).json({ error: 'payload_too_large', maxBytes: 10485760 });
      return;
    }
    next(err);
  });

  app.use('/api/v1/scan', scanRoutes);
  app.use('/api/v1/reports', reportsRoutes);
  app.use('/api/v1/downloads', downloadsRoutes);
  app.use('/api/v1/health', healthRoutes);
  app.use('/api/v1/ai', aiRoutes);
  app.use('/api/v1/security', securityRoutes);
  app.use('/api/v1/admin', adminRoutes);
  app.get('/api/v1/stats', createRateLimiter({ endpoint: 'stats_root_ip', limit: 100, windowMs: 60_000 }), statsController);

  app.use((req, _res, next) => {
    next(new AppError(404, 'not_found', `route not found: ${req.path}`, { path: req.path }));
  });
  app.use(errorHandler);
  return app;
};
