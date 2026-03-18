import type { Request, Response } from 'express';
import { scoreExtractedEmailUrls } from '../services/scan.service';

export const emailSecurityController = async (req: Request, res: Response): Promise<void> => {
  res.json(await scoreExtractedEmailUrls(req.body));
};
