import { createHmac, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { env } from '../config';
import { AppError } from '../errors';

const FIVE_MINUTES_MS = 5 * 60 * 1000;

function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export const optionalRequestSignature = (req: Request, _res: Response, next: NextFunction): void => {
  if (!env.REQUEST_SIGNATURE_SECRET) {
    next();
    return;
  }

  const signature = req.header('x-request-signature');
  const timestampHeader = req.header('x-request-timestamp');

  if (!signature || !timestampHeader) {
    next(new AppError(401, 'unauthorized', 'missing request signature'));
    return;
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > FIVE_MINUTES_MS) {
    next(new AppError(401, 'unauthorized', 'stale request signature'));
    return;
  }

  const payload = `${req.method}\n${req.originalUrl}\n${timestamp}\n${req.rawBody ?? ''}`;
  const expected = createHmac('sha256', env.REQUEST_SIGNATURE_SECRET)
    .update(payload)
    .digest('hex');

  if (!safeEquals(signature, expected)) {
    next(new AppError(401, 'unauthorized', 'invalid request signature'));
    return;
  }

  next();
};
