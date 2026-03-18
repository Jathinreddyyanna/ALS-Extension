import type { NextFunction, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

declare module 'express-serve-static-core' {
  interface Request {
    requestId: string;
    userGeminiKey?: string;
  }
}

export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const incoming = req.header('x-request-id');
  const requestId = incoming && incoming.length > 0 ? incoming : uuidv4();
  req.requestId = requestId;
  res.setHeader('x-request-id', requestId);
  next();
};
