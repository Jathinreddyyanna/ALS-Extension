import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { AiError, AppError, DatabaseError, NotFoundError, RateLimitError, ValidationError } from '../src/errors';
import { errorHandler } from '../src/middleware/errorHandler';

const buildApp = (error: Error) => {
  const app = express();
  app.get('/test', () => {
    throw error;
  });
  app.use(errorHandler);
  return app;
};

describe('errorHandler', () => {
  it('maps AppError to its status', async () => {
    const response = await request(buildApp(new AppError(400, 'bad_request', 'bad'))).get('/test');
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('bad_request');
  });

  it('maps ValidationError to 422', async () => {
    const response = await request(buildApp(new ValidationError('invalid', [{ path: ['url'] }]))).get('/test');
    expect(response.status).toBe(422);
  });

  it('maps NotFoundError to 404', async () => {
    const response = await request(buildApp(new NotFoundError('missing'))).get('/test');
    expect(response.status).toBe(404);
  });

  it('maps RateLimitError to 429', async () => {
    const response = await request(buildApp(new RateLimitError('slow down', { retryAfterMs: 1000 }))).get('/test');
    expect(response.status).toBe(429);
    expect(response.body.retryAfterMs).toBe(1000);
  });

  it('maps AiError to 200 degraded', async () => {
    const response = await request(buildApp(new AiError('ai degraded'))).get('/test');
    expect(response.status).toBe(200);
    expect(response.body.aiDegraded).toBe(true);
  });

  it('maps DatabaseError to 503', async () => {
    const response = await request(buildApp(new DatabaseError('db down'))).get('/test');
    expect(response.status).toBe(503);
  });
});
