import type { NextFunction, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { incrementMetric, observeLatency } from '../services/metrics.service';

export const requestLoggingMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const started = Date.now();
  res.on('finish', () => {
    const latencyMs = Date.now() - started;
    incrementMetric('request', { method: req.method, path: req.path, status: String(res.statusCode) });
    if (req.path.includes('/scan/url')) {
      observeLatency('scan', latencyMs);
    }
    logger.info({
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      latencyMs
    }, 'request completed');
  });
  next();
};
