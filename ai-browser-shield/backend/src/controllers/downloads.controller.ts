import type { Request, Response } from 'express';
import { approveDownload, cancelDownload } from '../services/download.service';

export const approveDownloadController = async (req: Request, res: Response): Promise<void> => {
  res.json(await approveDownload(req.body.chrome_download_id, req.body.sessionId));
};

export const cancelDownloadController = async (req: Request, res: Response): Promise<void> => {
  res.json(await cancelDownload(req.body.chrome_download_id, req.body.sessionId));
};
