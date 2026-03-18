import { Router } from 'express';
import { createReportController, recentReportsController } from '../controllers/reports.controller';
import { apiKeyAuth } from '../middleware/apiKeyAuth';
import { createRateLimiter } from '../middleware/rateLimiter';
import { validateBody } from '../middleware/validateBody';
import { reportSchema } from '../schemas';

const router = Router();

router.post('/', apiKeyAuth, createRateLimiter({ endpoint: 'reports_ip', limit: 5, windowMs: 60 * 60 * 1000 }), validateBody(reportSchema), createReportController);
router.get('/recent', createRateLimiter({ endpoint: 'reports_recent_ip', limit: 100, windowMs: 60_000 }), recentReportsController);

export default router;
