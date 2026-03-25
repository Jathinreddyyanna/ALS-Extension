import { createServer } from 'node:http';
import { env } from './config';
import { createApp } from './app';
import { connectDatabase, disconnectDatabase, isDatabaseAvailable, prisma } from './db/client';
import { cacheService } from './services/cache.service';
import { getGeminiDebugResult } from './services/ai.service';
import { loadModelMetadata, getModelPerformanceSummary, validateModelMetadata } from './services/modelMetadata';
import { logger } from './utils/logger';
import { startDomainRecalculatorJob } from './jobs/domainRecalculator';
import { startCleanupJobs } from './jobs/cleanup';
import { startStatsUpdaterJob } from './jobs/statsUpdater';

const app = createApp();
const server = createServer(app);
const jobs = process.env.NODE_ENV === 'test'
  ? []
  : [startDomainRecalculatorJob(), startStatsUpdaterJob(), ...startCleanupJobs()];
const NODE_MAJOR = Number.parseInt(process.versions.node.split('.')[0] || '0', 10);

const formatStartupError = (error: unknown) => {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
      cause: 'cause' in error ? error.cause : undefined
    };
  }

  return error;
};

const runStartupChecks = async () => {
  logger.info('running startup checks');

  try {
    loadModelMetadata();
    const validation = validateModelMetadata();
    if (!validation.valid) {
      logger.warn({ issues: validation.issues }, 'model metadata validation reported issues');
    }
    logger.info({ summary: getModelPerformanceSummary() }, 'model metadata loaded');
  } catch (error) {
    logger.warn({ err: formatStartupError(error) }, 'model metadata unavailable at startup');
  }

  try {
    if (process.env.NO_DB !== 'true' && isDatabaseAvailable()) {
      await prisma.$queryRaw`SELECT 1`;
      logger.info('database connected');
    } else if (process.env.NO_DB === 'true') {
      logger.warn('database disabled via NO_DB=true');
    } else {
      logger.warn('database unavailable, continuing in degraded mode');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown database error';
    logger.error({ err: message }, 'database startup verification failed');
  }

  try {
    logger.info('skipping Gemini startup check to prevent burning rate limit tokens');
    void getGeminiDebugResult;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown Gemini error';
    logger.warn({ err: message, configuredModel: env.GEMINI_MODEL }, 'Gemini startup check failed');
  }
};

const shutdown = async () => {
  for (const job of jobs) {
    job.stop();
  }
  server.close(() => {
    void disconnectDatabase().finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(0), 30_000).unref();
};

const start = async () => {
  if (NODE_MAJOR >= 24) {
    logger.warn({ nodeVersion: process.versions.node }, 'Node 24+ detected; Prisma 5.x is only validated on Node 20/22 LTS');
  }

  const db = await connectDatabase();
  if (!db && process.env.NO_DB !== 'true') {
    logger.warn('database unavailable at startup, continuing in degraded mode');
  }

  await cacheService.connect();

  server.listen(env.PORT, async () => {
    logger.info({ port: env.PORT }, `ai browser shield backend listening on ${env.PORT}`);
    await runStartupChecks();
  });

  server.on('error', (error: NodeJS.ErrnoException) => {
    if (error.code === 'EADDRINUSE') {
      logger.error({ port: env.PORT }, 'port already in use. choose a different PORT.');
      process.exit(1);
    }
  });
};

process.on('SIGTERM', () => {
  void shutdown();
});

process.on('SIGINT', () => {
  void shutdown();
});

void start();
