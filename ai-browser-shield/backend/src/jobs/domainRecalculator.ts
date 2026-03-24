import cron from 'node-cron';
import { isDatabaseAvailable, prisma } from '../db/client';
import { recalculateDomainScore } from '../services/domain.service';
import { logger } from '../utils/logger';

export const startDomainRecalculatorJob = () => cron.schedule('*/5 * * * *', async () => {
  if (!isDatabaseAvailable()) {
    return;
  }
  const domains = await prisma.detectionEvent.findMany({
    distinct: ['domain'],
    orderBy: { createdAt: 'desc' },
    select: { domain: true }
  }).catch(() => []);
  for (const item of domains) {
    try {
      await recalculateDomainScore(item.domain);
      await new Promise((resolve) => setTimeout(resolve, 50));
    } catch (err) {
      logger.warn({ err, domain: item.domain }, 'failed writing recalculated domain score');
    }
  }
});
