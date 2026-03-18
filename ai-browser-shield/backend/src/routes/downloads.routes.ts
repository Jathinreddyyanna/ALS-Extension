import { Router } from 'express';
import { approveDownloadController, cancelDownloadController } from '../controllers/downloads.controller';
import { apiKeyAuth } from '../middleware/apiKeyAuth';
import { createRateLimiter } from '../middleware/rateLimiter';
import { validateBody } from '../middleware/validateBody';
import { downloadActionSchema } from '../schemas';

const router = Router();

router.post('/approve', apiKeyAuth, createRateLimiter({ endpoint: 'downloads_ip', limit: 100, windowMs: 60_000 }), validateBody(downloadActionSchema), approveDownloadController);
router.post('/cancel', apiKeyAuth, createRateLimiter({ endpoint: 'downloads_cancel_ip', limit: 100, windowMs: 60_000 }), validateBody(downloadActionSchema), cancelDownloadController);

export default router;
