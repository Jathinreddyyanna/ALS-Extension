import { Router } from 'express';
import { confirmDomainController, flaggedDomainsController } from '../controllers/admin.controller';
import { adminKeyAuth } from '../middleware/apiKeyAuth';
import { validateBody } from '../middleware/validateBody';
import { adminConfirmSchema } from '../schemas';

const router = Router();

router.post('/domains/:domain/confirm', adminKeyAuth, validateBody(adminConfirmSchema), confirmDomainController);
router.get('/domains/flagged', adminKeyAuth, flaggedDomainsController);

export default router;
