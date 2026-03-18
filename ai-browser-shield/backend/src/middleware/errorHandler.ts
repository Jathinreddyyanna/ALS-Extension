import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { AiError, AppError } from '../errors';
import { isProduction } from '../config';
import { logger } from '../utils/logger';

export const errorHandler = (error: unknown, req: Request, res: Response, _next: NextFunction): void => {
  if (error instanceof ZodError) {
    res.status(422).json({ error: 'validation_error', errors: error.issues });
    return;
  }

  if (error instanceof SyntaxError && 'body' in error) {
    res.status(400).json({ error: 'invalid_json', message: 'invalid JSON' });
    return;
  }

  if (error instanceof AiError) {
    logger.warn({ requestId: req.requestId, code: error.code, details: error.details }, error.message);
    res.status(200).json({
      error: error.code,
      message: error.message,
      aiDegraded: true
    });
    return;
  }

  if (error instanceof AppError) {
    const context = { requestId: req.requestId, code: error.code, details: error.details };
    if (error.statusCode >= 500) {
      logger.error(context, error.message);
    } else if (error.statusCode === 429) {
      logger.warn(context, error.message);
    } else {
      logger.debug(context, error.message);
    }
    res.status(error.statusCode).json({
      error: error.code,
      message: error.message,
      ...(error.details && typeof error.details === 'object' ? error.details as object : error.details ? { details: error.details } : {}),
      ...(!isProduction && error.stack ? { stack: error.stack } : {})
    });
    return;
  }

  logger.error({ err: error, requestId: req.requestId }, 'unhandled error');
  res.status(500).json({
    error: 'internal_error',
    message: 'internal server error',
    ...(!isProduction && error instanceof Error ? { stack: error.stack } : {})
  });
};
