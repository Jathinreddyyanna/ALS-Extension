import cron from 'node-cron';
import { isDatabaseAvailable, prisma } from '../db/client';
import { recalculateDomainScore } from '../services/domain.service';

export const startDomainRecalculatorJob = () => cron.schedule('*/5 * * * *', async () => {
  if (!isDatabaseAvailable()) {
    return;
  }
  const domains = await prisma.detectionEvent.findMany({
    distinct: ['domain'],
    orderBy: { createdAt: 'desc' },
    select: { domain: true }
  }).catch(() => []);
  await Promise.all(domains.map((item) => recalculateDomainScore(item.domain)));
});
