import { z } from 'zod';
import type { Request, Response } from 'express';
import { env } from '../config';
import { cacheKeys, cacheService } from '../services/cache.service';
import { pingGemini } from '../services/ai.service';
import { getEmailMlHealth } from '../services/emailMl.service';
import { prisma } from '../db/client';
import { getAppStats } from '../services/stats.service';
import { renderPrometheusMetrics } from '../services/metrics.service';
import { logger } from '../utils/logger';

const healthSchema = z.object({
  status: z.enum(['ok', 'degraded']),
  db: z.boolean(),
  redis: z.boolean(),
  ai: z.boolean(),
  emailMl: z.boolean(),
  uptime: z.number(),
  version: z.string(),
  env: z.string(),
  services: z.object({
    database: z.boolean(),
    redis: z.boolean(),
    gemini: z.boolean(),
    emailMl: z.boolean()
  })
});

export const healthController = async (req: Request, res: Response): Promise<void> => {
  const cached = await cacheService.get<z.infer<typeof healthSchema>>(cacheKeys.health);
  if (cached) {
    res.json(cached);
    return;
  }

  let db = false;
  let redis = false;
  let ai = false;
  let emailMl = false;
  try {
    await prisma.$queryRaw`SELECT 1`;
    db = true;
  } catch {
    db = false;
  }
  try {
    redis = await cacheService.ping();
  } catch {
    redis = false;
  }
  try {
    ai = await pingGemini();
  } catch {
    ai = false;
  }
  try {
    const health = await getEmailMlHealth();
    emailMl = health.modelLoaded;
  } catch {
    emailMl = false;
  }

  const result = {
    status: db && redis && ai && emailMl ? 'ok' as const : 'degraded' as const,
    db,
    redis,
    ai,
    emailMl,
    uptime: process.uptime(),
    version: process.env.npm_package_version ?? '2.0.0',
    env: env.NODE_ENV,
    services: {
      database: db,
      redis,
      gemini: ai,
      emailMl
    }
  };
  const parsed = healthSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid health response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  await cacheService.set(cacheKeys.health, parsed.data, 30);
  res.status(200).json(parsed.data);
};

export const statsController = async (_req: Request, res: Response): Promise<void> => {
  res.json(await getAppStats());
};

export const readinessController = async (_req: Request, res: Response): Promise<void> => {
  let db = false;
  let redis = false;
  try {
    await prisma.$queryRaw`SELECT 1`;
    db = true;
  } catch {
    db = false;
  }
  try {
    redis = await cacheService.ping();
  } catch {
    redis = false;
  }

  if (!db) {
    res.status(503).json({ status: 'not_ready', db, redis });
    return;
  }

  res.json({ status: redis ? 'ready' : 'degraded', db, redis });
};

export const metricsController = async (_req: Request, res: Response): Promise<void> => {
  res.setHeader('content-type', 'text/plain; version=0.0.4');
  res.send(renderPrometheusMetrics());
};
