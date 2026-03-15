import { Router, Request, Response } from 'express';
import { prisma } from '../db/client';
import { aiConfig } from '../config';
import { explainThreatWithGemini } from '../ai/geminiClient';

const router = Router();

router.get('/status', async (_req: Request, res: Response) => {
  const checks: Record<string, any> = {};

  // Check env and config
  checks.env = {
    hasDatabaseUrl: !!process.env.DATABASE_URL,
    hasDirectUrl: !!process.env.DIRECT_URL,
    hasGeminiApiKey: !!process.env.GEMINI_API_KEY,
  };

  // Check DB connectivity
  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.database = { ok: true };
  } catch (err: any) {
    checks.database = { ok: false, error: String(err?.message || err) };
  }

  // Check Gemini config & basic call (with heuristic-only fallback if not configured)
  try {
    const testInput = {
      url: 'https://example.com',
      heuristicRisk: 10,
      domainReputation: { riskScore: 10, reportCount: 0 },
      signals: { testSignal: 1 },
      popupRedirect: { riskLevel: 'LOW' },
    };
    const aiResult = await explainThreatWithGemini(testInput);
    checks.gemini = {
      ok: true,
      riskLevel: aiResult.riskLevel,
      recommendedAction: aiResult.recommendedAction,
      confidence: aiResult.confidence,
      keyIndicators: aiResult.keyIndicators,
      usedRealGemini: !!aiConfig.gemini.apiKey,
    };
  } catch (err: any) {
    checks.gemini = { ok: false, error: String(err?.message || err) };
  }

  return res.json({
    status: checks.database.ok === false || checks.gemini.ok === false ? 'degraded' : 'ok',
    checks,
  });
});

export default router;