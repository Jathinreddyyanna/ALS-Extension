import { Router } from 'express';
import { debugAiController, explainAiController } from '../controllers/ai.controller';
import { env } from '../config';
import { adminKeyAuth, apiKeyAuth } from '../middleware/apiKeyAuth';
import { createRateLimiter } from '../middleware/rateLimiter';
import { validateBody } from '../middleware/validateBody';
import { aiExplainSchema } from '../schemas';

const router = Router();

router.post('/explain', apiKeyAuth, createRateLimiter({ endpoint: 'ai_explain_ip', limit: 30, windowMs: 60_000 }), validateBody(aiExplainSchema), explainAiController);
router.get('/debug', adminKeyAuth, createRateLimiter({ endpoint: 'ai_debug_ip', limit: 100, windowMs: 60_000 }), debugAiController);
router.get('/status', apiKeyAuth, createRateLimiter({ endpoint: 'ai_status_ip', limit: 120, windowMs: 60_000 }), (_req, res) => {
  res.json({
    aiAvailable: global.__aiDegraded__ !== true,
    model: env.GEMINI_MODEL,
    timestamp: new Date().toISOString()
  });
});

export default router;
