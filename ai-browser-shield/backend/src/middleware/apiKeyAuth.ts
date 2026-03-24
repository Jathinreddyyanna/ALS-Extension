import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { env } from '../config';
import { AppError } from '../errors';

const isValidApiKey = (provided: string | undefined, expected: string): boolean => {
  if (!provided || !expected) return false;
  const providedBuffer = Buffer.from(provided.trim());
  const expectedBuffer = Buffer.from(expected);
  if (providedBuffer.length !== expectedBuffer.length) return false;
  return timingSafeEqual(providedBuffer, expectedBuffer);
};

export const apiKeyAuth = (req: Request, _res: Response, next: NextFunction): void => {
  const apiKey = req.header('x-api-key');
  if (!isValidApiKey(apiKey, env.API_KEY)) {
    next(new AppError(401, 'unauthorized', 'invalid api key'));
    return;
  }
  const userGeminiKey = req.header('x-gemini-key');
  if (typeof userGeminiKey === 'string' && userGeminiKey.startsWith('AIza')) {
    req.userGeminiKey = userGeminiKey.trim();
  }
  next();
};

export const adminKeyAuth = (req: Request, _res: Response, next: NextFunction): void => {
  if (!env.ADMIN_KEY) {
    next(new AppError(503, 'admin_disabled', 'admin features disabled'));
    return;
  }
  if (!isValidApiKey(req.header('x-admin-key'), env.ADMIN_KEY)) {
    next(new AppError(401, 'unauthorized', 'invalid admin key'));
    return;
  }
  next();
};
