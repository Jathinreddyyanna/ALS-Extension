import { Router } from 'express';
import { emailSecurityController } from '../controllers/security.controller';
import { apiKeyAuth } from '../middleware/apiKeyAuth';
import { createRateLimiter } from '../middleware/rateLimiter';
import { validateBody } from '../middleware/validateBody';
import { emailSecuritySchema } from '../schemas';

const router = Router();

router.post('/email', apiKeyAuth, createRateLimiter({ endpoint: 'security_email_ip', limit: 100, windowMs: 60_000 }), validateBody(emailSecuritySchema), emailSecurityController);

export default router;
