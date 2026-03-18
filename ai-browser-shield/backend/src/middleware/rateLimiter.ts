import type { NextFunction, Request, Response } from 'express';
import { isDatabaseAvailable, prisma } from '../db/client';
import { RateLimitError } from '../errors';
import { hashIp } from '../utils/ip';

type Scope = 'ip' | 'apiKey';

interface RateLimitOptions {
  endpoint: string;
  limit: number;
  windowMs: number;
  scope?: Scope;
}

const counters = new Map<string, { count: number; expiresAt: number }>();

const getKey = (req: Request, endpoint: string, scope: Scope): string => {
  if (scope === 'apiKey') {
    return `${endpoint}:api:${req.header('x-api-key') ?? 'missing'}`;
  }
  return `${endpoint}:ip:${hashIp(req.ip || '0.0.0.0')}`;
};

const recordRateLimit = async (req: Request, endpoint: string, count: number, blocked: boolean): Promise<void> => {
  if (!isDatabaseAvailable()) {
    return;
  }
  const ipHash = hashIp(req.ip || '0.0.0.0');
  await prisma.rateLimitLog.create({
    data: {
      ipHash,
      endpoint,
      requestCount: count,
      windowStart: new Date(),
      blocked
    }
  }).catch(() => undefined);
};

export const createRateLimiter = (options: RateLimitOptions) =>
  async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    const scope = options.scope ?? 'ip';
    const key = getKey(req, options.endpoint, scope);
    const now = Date.now();
    const current = counters.get(key);
    if (!current || current.expiresAt <= now) {
      counters.set(key, { count: 1, expiresAt: now + options.windowMs });
      void recordRateLimit(req, options.endpoint, 1, false);
      next();
      return;
    }

    current.count += 1;
    const remaining = Math.max(0, options.limit - current.count);
    if (current.count > options.limit) {
      const retryAfterMs = current.expiresAt - now;
      void recordRateLimit(req, options.endpoint, current.count, true);
      next(new RateLimitError('rate limit exceeded', {
        retryAfterMs,
        limit: options.limit,
        remaining
      }));
      return;
    }

    void recordRateLimit(req, options.endpoint, current.count, false);
    next();
  };
