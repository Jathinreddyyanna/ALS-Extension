import { z } from 'zod';
import type { Request, Response } from 'express';
import { confirmDomainVerdict, getFlaggedDomains } from '../services/domain.service';
import { logger } from '../utils/logger';

const adminConfirmResponseSchema = z.object({
  domain: z.string(),
  verdict: z.enum(['confirmed', 'rejected']),
  riskScore: z.number(),
  affectedReports: z.number()
});

const flaggedDomainsSchema = z.array(z.any());

export const confirmDomainController = async (req: Request, res: Response): Promise<void> => {
  const result = await confirmDomainVerdict({
    domain: req.params.domain ?? '',
    verdict: req.body.verdict,
    notes: req.body.notes,
    overrideRiskScore: req.body.overrideRiskScore
  });
  const parsed = adminConfirmResponseSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid admin confirm response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  res.json(parsed.data);
};

export const flaggedDomainsController = async (req: Request, res: Response): Promise<void> => {
  const result = await getFlaggedDomains();
  const parsed = flaggedDomainsSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid flagged domains response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  res.json(parsed.data);
};
