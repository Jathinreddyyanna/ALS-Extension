import { z } from 'zod';
import type { Request, Response } from 'express';
import type { Prisma } from '@prisma/client';
import { prisma } from '../db/client';
import { getDomainInsight, getDomainScoreRecord } from '../services/domain.service';
import { scanFile } from '../services/file.service';
import { localPersistence } from '../services/localPersistence.service';
import { performUrlScan } from '../services/scan.service';
import { NotFoundError } from '../errors';
import { logger } from '../utils/logger';
import { FileScanResponseSchema, UrlScanResponseSchema } from '../types/scan.types';

const domainInsightSchema = z.object({
  score: z.any(),
  detectionEvents: z.array(z.any()),
  reports: z.array(z.any()),
  trend: z.any()
});

const threatEventUpsertSchema = z.object({
  id: z.string().optional(),
  eventType: z.enum(['url_threat', 'redirect_chain', 'popup_abuse', 'download_intercept', 'file_scan', 'ad_block', 'crypto_mining', 'data_exfil']),
  domain: z.string().min(1),
  url: z.string().min(1),
  riskScore: z.number().int().min(0).max(100),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  aiExplanation: z.string().optional(),
  verdict: z.string().optional(),
  timestamp: z.number().optional(),
  metadata: z.record(z.unknown()).optional(),
  sessionId: z.string().optional()
}).strip();

export const scanUrlController = async (req: Request, res: Response): Promise<void> => {
  const started = Date.now();
  const result = await performUrlScan({
    ...req.body,
    ip: req.ip,
    userAgent: req.get('user-agent') ?? undefined,
    requestId: req.requestId,
    userGeminiKey: req.userGeminiKey
  });
  const parsed = UrlScanResponseSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid url scan response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  logger.info({
    requestId: req.requestId,
    latencyMs: Date.now() - started,
    decisionBasis: parsed.data.decisionBasis,
    threatSource: parsed.data.threatSource,
    riskLevel: parsed.data.riskLevel
  }, 'url scan completed');
  res.json(parsed.data);
};

export const scanFileController = async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Record<string, string | undefined>;
  const result = await scanFile({
    filename: req.file?.originalname ?? String(body.filename ?? ''),
    mimeType: req.file?.mimetype ?? String(body.mimeType ?? ''),
    sizeBytes: req.file?.size ?? Number(body.sizeBytes ?? 0),
    sourceUrl: String(body.sourceUrl ?? ''),
    base64Content: typeof body.base64Content === 'string' ? body.base64Content : undefined,
    chromeDownloadId: typeof body.chrome_download_id === 'string' ? body.chrome_download_id : undefined,
    sessionId: typeof body.sessionId === 'string' ? body.sessionId : undefined,
    buffer: req.file?.buffer,
    sha256Hash: req.file?.buffer ? undefined : undefined,
    userGeminiKey: req.userGeminiKey
  });
  const parsed = FileScanResponseSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid file scan response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  res.json(parsed.data);
};

export const getDomainController = async (req: Request, res: Response): Promise<void> => {
  const domain = req.params.domain ?? '';
  const result = await getDomainInsight(domain);
  if (!result) {
    throw new NotFoundError('domain not found');
  }
  const parsed = domainInsightSchema.safeParse(result);
  if (!parsed.success) {
    logger.error({ requestId: req.requestId, issues: parsed.error.issues }, 'invalid domain insight response schema');
    res.status(500).json({ error: 'internal_schema_error' });
    return;
  }
  res.json(parsed.data);
};

export const getLegacyDomainScoreController = async (req: Request, res: Response): Promise<void> => {
  const domain = req.params.domain ?? '';
  const score = await getDomainScoreRecord(domain);
  if (!score) {
    throw new NotFoundError('domain not found');
  }

  res.json({
    domain: score.domain,
    risk_score: score.riskScore,
    report_count: score.reportCount,
    categories: score.categories,
    last_updated: score.lastUpdated.toISOString(),
    ai_summary: null,
    ai_threat_level: null,
    ai_recommendation: null
  });
};

export const getThreatEventsController = async (req: Request, res: Response): Promise<void> => {
  const domain = String(req.query.domain ?? '').trim();
  const limitRaw = Number(req.query.limit ?? 100);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, Math.floor(limitRaw))) : 100;

  let events;
  try {
    events = await prisma.detectionEvent.findMany({
      where: domain ? { domain } : undefined,
      orderBy: { createdAt: 'desc' },
      take: limit
    });
  } catch {
    events = await localPersistence.listDetectionEvents({ domain: domain || undefined, limit });
  }

  res.json(events.map((event) => ({
    id: event.id,
    eventType: event.eventType,
    domain: event.domain,
    url: event.url,
    riskScore: event.riskScore,
    riskLevel: event.riskLevel,
    aiExplanation: event.aiExplanation ?? undefined,
    verdict: event.verdict ?? undefined,
    timestamp: event.createdAt.getTime()
  })));
};

export const createThreatEventController = async (req: Request, res: Response): Promise<void> => {
  const parsed = threatEventUpsertSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ error: 'validation_error', errors: parsed.error.issues });
    return;
  }

  const body = parsed.data;
  const createdAt = typeof body.timestamp === 'number' && Number.isFinite(body.timestamp)
    ? new Date(body.timestamp)
    : undefined;

  let created: { id: string };
  try {
    created = await prisma.detectionEvent.create({
      data: {
        eventType: body.eventType,
        domain: body.domain,
        url: body.url,
        riskScore: body.riskScore,
        riskLevel: body.riskLevel,
        aiExplanation: body.aiExplanation,
        verdict: body.verdict,
        userAgent: req.get('user-agent') ?? undefined,
        sessionId: body.sessionId,
        signals: (body.metadata ?? {}) as Prisma.InputJsonValue,
        ...(createdAt ? { createdAt } : {})
      }
    });
  } catch {
    created = await localPersistence.createDetectionEvent({
      eventType: body.eventType,
      domain: body.domain,
      url: body.url,
      riskScore: body.riskScore,
      riskLevel: body.riskLevel,
      aiExplanation: body.aiExplanation,
      verdict: body.verdict,
      userAgent: req.get('user-agent') ?? undefined,
      sessionId: body.sessionId,
      signals: body.metadata ?? {},
      createdAt,
      ipHash: undefined,
      domainScoreId: undefined,
      fileScanId: undefined
    });
  }

  res.status(201).json({ ok: true, id: created.id });
};
