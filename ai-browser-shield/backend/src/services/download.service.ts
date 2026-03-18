import { prisma } from '../db/client';

export const approveDownload = async (chromeDownloadId: string, sessionId?: string) => {
  await prisma.downloadRecord.updateMany({
    where: { chromeDownloadId, ...(sessionId ? { sessionId } : {}) },
    data: {
      status: 'approved',
      approvedAt: new Date()
    }
  });
  return { approved: true };
};

export const cancelDownload = async (chromeDownloadId: string, sessionId?: string) => {
  await prisma.downloadRecord.updateMany({
    where: { chromeDownloadId, ...(sessionId ? { sessionId } : {}) },
    data: {
      status: 'cancelled'
    }
  });
  return { cancelled: true };
};
