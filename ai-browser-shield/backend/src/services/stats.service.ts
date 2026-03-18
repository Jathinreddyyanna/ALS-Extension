import { prisma } from '../db/client';
import { cacheKeys, cacheService } from './cache.service';

export const updateAppStats = async () => {
  const [totalScans, totalThreats, totalReports, totalFileScans] = await Promise.all([
    prisma.detectionEvent.count().catch(() => 0),
    prisma.detectionEvent.count({ where: { riskScore: { gte: 50 } } }).catch(() => 0),
    prisma.threatReport.count().catch(() => 0),
    prisma.fileScan.count().catch(() => 0)
  ]);
  const stats = await prisma.appStats.upsert({
    where: { id: 1 },
    update: { totalScans, totalThreats, totalReports, totalFileScans, lastUpdated: new Date() },
    create: { id: 1, totalScans, totalThreats, totalReports, totalFileScans, lastUpdated: new Date() }
  }).catch(() => ({
    id: 1,
    totalScans,
    totalThreats,
    totalReports,
    totalFileScans,
    lastUpdated: new Date()
  }));
  await cacheService.set(cacheKeys.stats, stats, 60);
  return stats;
};

export const getAppStats = async () => {
  const cached = await cacheService.get<Awaited<ReturnType<typeof prisma.appStats.findUnique>>>(cacheKeys.stats);
  if (cached) {
    return cached;
  }
  const stats = await prisma.appStats.findUnique({ where: { id: 1 } }).catch(() => null);
  if (stats) {
    await cacheService.set(cacheKeys.stats, stats, 60);
    return stats;
  }
  return updateAppStats();
};
