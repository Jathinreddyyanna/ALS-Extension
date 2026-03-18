import { z } from 'zod';
import type { Request, Response } from 'express';
import { createThreatReport, getRecentConfirmedReports } from '../services/report.service';
import { logger } from '../utils/logger';

const reportResponseSchema = z.object({
  id: z.string(),
  status: z.enum(['pending', 'already_reported']),
  message: z.string()
});

export const createReportController = async (req: Request, res: Response): Promise<void> => {
  const result = await createThreatReport({
    ...req.body,
    ip: req.ip,
    userAgent: req.get('user-agent') ?? undefined
  });
  const parsed = reportResponseSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid report response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  res.status(result.status === 'pending' ? 201 : 200).json(parsed.data);
};

export const recentReportsController = async (_req: Request, res: Response): Promise<void> => {
  const result = await getRecentConfirmedReports();
  res.json(result);
};
