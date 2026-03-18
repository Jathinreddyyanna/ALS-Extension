import { Router } from 'express';
import { healthController, statsController } from '../controllers/health.controller';
import { createRateLimiter } from '../middleware/rateLimiter';

const router = Router();

router.get('/', createRateLimiter({ endpoint: 'health_ip', limit: 100, windowMs: 60_000 }), healthController);
router.get('/stats', createRateLimiter({ endpoint: 'stats_ip', limit: 100, windowMs: 60_000 }), statsController);

export default router;
