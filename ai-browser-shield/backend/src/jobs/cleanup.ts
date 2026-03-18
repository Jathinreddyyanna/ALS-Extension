import cron from 'node-cron';
import { prisma } from '../db/client';
import { getCurrentSalt, resetDailySaltCache } from '../utils/ip';
import { logger } from '../utils/logger';

export const startCleanupJobs = () => {
  const hourly = cron.schedule('0 * * * *', async () => {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    await prisma.rateLimitLog.deleteMany({ where: { windowStart: { lt: cutoff } } }).catch(() => undefined);
  });

  const daily = cron.schedule('0 0 * * *', async () => {
    resetDailySaltCache();
    const salt = getCurrentSalt();
    logger.info({ date: new Date().toISOString().slice(0, 10), saltPreview: salt.slice(0, 8) }, `Daily IP salt rotated for ${new Date().toISOString().slice(0, 10)}`);
    await prisma.detectionEvent.deleteMany({ where: { createdAt: { lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) } } }).catch(() => undefined);
    await prisma.fileScan.deleteMany({ where: { createdAt: { lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } } }).catch(() => undefined);
  });

  return [hourly, daily];
};
