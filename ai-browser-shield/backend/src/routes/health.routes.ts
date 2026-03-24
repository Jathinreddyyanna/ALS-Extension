import { Router } from 'express';
import { healthController, metricsController, readinessController, statsController } from '../controllers/health.controller';
import { createRateLimiter } from '../middleware/rateLimiter';

const router = Router();

router.get('/', createRateLimiter({ endpoint: 'health_ip', limit: 100, windowMs: 60_000 }), healthController);
router.get('/readiness', createRateLimiter({ endpoint: 'health_readiness_ip', limit: 100, windowMs: 60_000 }), readinessController);
router.get('/metrics', createRateLimiter({ endpoint: 'health_metrics_ip', limit: 60, windowMs: 60_000 }), metricsController);
router.get('/stats', createRateLimiter({ endpoint: 'stats_ip', limit: 100, windowMs: 60_000 }), statsController);

export default router;
