import type { Request, Response } from 'express';
import { cacheKeys, cacheService } from '../services/cache.service';
import { getGeminiDebugResult } from '../services/ai.service';
import { explainUrlWithAi } from '../services/scan.service';

export const explainAiController = async (req: Request, res: Response): Promise<void> => {
  const result = await explainUrlWithAi({
    ...req.body,
    ip: req.ip,
    userAgent: req.get('user-agent') ?? undefined,
    userGeminiKey: req.userGeminiKey
  });
  res.json(result);
};

export const debugAiController = async (_req: Request, res: Response): Promise<void> => {
  const cached = await cacheService.get<Awaited<ReturnType<typeof getGeminiDebugResult>>>(cacheKeys.aiDebug);
  if (cached) {
    res.json(cached);
    return;
  }
  const result = await getGeminiDebugResult();
  await cacheService.set(cacheKeys.aiDebug, result, 60);
  res.json(result);
};
