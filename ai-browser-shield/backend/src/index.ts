import { createServer } from 'node:http';
import { env } from './config';
import { createApp } from './app';
import { prisma } from './db/client';
import { getGeminiDebugResult } from './services/ai.service';
import { cacheService } from './services/cache.service';
import { connectDatabase, disconnectDatabase } from './db/client';
import { logger } from './utils/logger';
import { startDomainRecalculatorJob } from './jobs/domainRecalculator';
import { startCleanupJobs } from './jobs/cleanup';
import { startStatsUpdaterJob } from './jobs/statsUpdater';

const app = createApp();
const server = createServer(app);
const jobs = process.env.NODE_ENV === 'test' ? [] : [startDomainRecalculatorJob(), startStatsUpdaterJob(), ...startCleanupJobs()];

const runStartupChecks = async () => {
  logger.info('Running startup checks...');

  try {
    await prisma.$queryRaw`SELECT 1`;
    logger.info('Database connected');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown database error';
    logger.error({ err: message }, 'Database FAILED - events will not persist');
  }

  try {
    logger.info('Skipping Gemini startup check to prevent burning rate limit tokens');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown Gemini error';
    logger.warn({ err: message, configuredModel: env.GEMINI_MODEL }, 'Gemini startup check failed - fallback chain will activate');
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
  const db = await connectDatabase();
  if (!db) {
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
