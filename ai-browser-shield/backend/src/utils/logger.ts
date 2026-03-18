import pino from 'pino';
import { env } from '../config';

export const logger = pino({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  base: undefined,
  redact: {
    paths: ['req.headers.authorization', 'req.headers.x-api-key', 'req.headers.x-admin-key'],
    censor: '[REDACTED]'
  }
});
