import { Router, type NextFunction, type Request, type Response } from 'express';
import multer from 'multer';
import { createThreatEventController, getDomainController, getLegacyDomainScoreController, getThreatEventsController, scanFileController, scanUrlController } from '../controllers/scan.controller';
import { apiKeyAuth } from '../middleware/apiKeyAuth';
import { createRateLimiter } from '../middleware/rateLimiter';
import { optionalRequestSignature } from '../middleware/requestSignature';
import { validateBody } from '../middleware/validateBody';
import { AppError } from '../errors';
import { scanFileJsonSchema, scanUrlSchema } from '../schemas';

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

const multipartFileMiddleware = (req: Request, res: Response, next: NextFunction) => {
  if (!req.is('multipart/form-data')) {
    next();
    return;
  }
  upload.single('file')(req, res, (error: unknown) => {
    if (error && typeof error === 'object' && error !== null && 'code' in error && (error as { code?: string }).code === 'LIMIT_FILE_SIZE') {
      next(new AppError(413, 'payload_too_large', 'payload too large', { maxBytes: 50 * 1024 * 1024 }));
      return;
    }
    next(error);
  });
};

router.post('/url', apiKeyAuth, optionalRequestSignature, createRateLimiter({ endpoint: 'scan_url_ip', limit: 60, windowMs: 60_000 }), createRateLimiter({ endpoint: 'scan_url_key', limit: 300, windowMs: 60_000, scope: 'apiKey' }), validateBody(scanUrlSchema), scanUrlController);
router.post('/file', apiKeyAuth, optionalRequestSignature, createRateLimiter({ endpoint: 'scan_file_ip', limit: 10, windowMs: 60_000 }), multipartFileMiddleware, (req: Request, res: Response, next: NextFunction) => {
  if (!req.is('multipart/form-data')) {
    validateBody(scanFileJsonSchema)(req, res, next);
    return;
  }
  next();
}, scanFileController);
router.get('/events', apiKeyAuth, createRateLimiter({ endpoint: 'scan_events_ip', limit: 120, windowMs: 60_000 }), getThreatEventsController);
router.post('/events', apiKeyAuth, createRateLimiter({ endpoint: 'scan_events_write_ip', limit: 120, windowMs: 60_000 }), createThreatEventController);
router.get('/domain/:domain', createRateLimiter({ endpoint: 'scan_domain_ip', limit: 100, windowMs: 60_000 }), getDomainController);
router.get('/domain/:domain/score', createRateLimiter({ endpoint: 'scan_domain_score_ip', limit: 100, windowMs: 60_000 }), getLegacyDomainScoreController);

export default router;
