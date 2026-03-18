import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { prisma } from '../src/db/client';
import { createApp } from '../src/app';

describe('POST /reports', () => {
  beforeEach(() => {
    vi.mocked(prisma.threatReport.findFirst).mockResolvedValue(null);
    vi.mocked(prisma.threatReport.create).mockResolvedValue({ id: 'report-1' } as never);
    vi.mocked(prisma.threatReport.findMany).mockResolvedValue([] as never);
  });

  it('returns already_reported on duplicate report within 24h', async () => {
    vi.mocked(prisma.threatReport.findFirst).mockResolvedValueOnce({ id: 'existing-report' } as never);
    const response = await request(createApp())
      .post('/api/v1/reports')
      .set('x-api-key', 'test-api-key')
      .send({ url: 'https://example.com/phish', category: 'phishing', description: 'looks suspicious' });
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('already_reported');
  });

  it('returns 429 on 6th report in an hour', async () => {
    const app = createApp();
    for (let index = 0; index < 5; index += 1) {
      await request(app)
        .post('/api/v1/reports')
        .set('x-api-key', 'test-api-key')
        .set('x-forwarded-for', '9.9.9.9')
        .send({ url: `https://example.com/phish-${index}`, category: 'phishing', description: 'looks suspicious' });
    }
    const response = await request(app)
      .post('/api/v1/reports')
      .set('x-api-key', 'test-api-key')
      .set('x-forwarded-for', '9.9.9.9')
      .send({ url: 'https://example.com/phish-final', category: 'phishing', description: 'looks suspicious' });
    expect(response.status).toBe(429);
  });

  it('returns 201 on valid report', async () => {
    const response = await request(createApp())
      .post('/api/v1/reports')
      .set('x-api-key', 'test-api-key')
      .send({ url: 'https://example.com/phish', category: 'phishing', description: 'looks suspicious' });
    expect(response.status).toBe(201);
    expect(response.body.status).toBe('pending');
  });

  it('returns 422 on invalid url', async () => {
    const response = await request(createApp())
      .post('/api/v1/reports')
      .set('x-api-key', 'test-api-key')
      .send({ url: '', category: 'phishing', description: 'looks suspicious' });
    expect(response.status).toBe(422);
  });
});
